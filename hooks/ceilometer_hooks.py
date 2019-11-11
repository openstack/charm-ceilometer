#!/usr/bin/env python3
#
# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import subprocess
import sys
import os

_path = os.path.dirname(os.path.realpath(__file__))
_root = os.path.abspath(os.path.join(_path, '..'))


def _add_path(path):
    if path not in sys.path:
        sys.path.insert(1, path)


_add_path(_root)


from charmhelpers.fetch import (
    apt_install,
    apt_update,
    filter_installed_packages,
)
from charmhelpers.core.hookenv import (
    DEBUG,
    Hooks,
    UnregisteredHookError,
    WARNING,
    close_port,
    config,
    is_leader,
    leader_get,
    leader_set,
    log,
    open_port,
    related_units,
    relation_get,
    relation_ids,
    relation_set,
    status_set,
)
from charmhelpers.core.host import (
    service_restart,
    lsb_release,
    mkdir,
    init_is_systemd,
)
import charmhelpers.contrib.openstack.cert_utils as cert_utils
from charmhelpers.contrib.openstack.context import ADDRESS_TYPES
from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    openstack_upgrade_available,
    pausable_restart_on_change as restart_on_change,
    is_unit_paused_set,
    get_os_codename_install_source,
    CompareOpenStackReleases,
    series_upgrade_prepare,
    series_upgrade_complete,
)
from charmhelpers.contrib.openstack.ha.utils import (
    generate_ha_relation_data,
)
from ceilometer_utils import (
    ApacheSSLContext,
)
from ceilometer_utils import (
    disable_package_apache_site,
    get_packages,
    CEILOMETER_DB,
    CEILOMETER_SERVICE,
    CEILOMETER_ROLE,
    CEILOMETER_API_SYSTEMD_CONF,
    register_configs,
    restart_map,
    run_in_apache,
    services,
    get_ceilometer_context,
    get_shared_secret,
    do_openstack_upgrade,
    set_shared_secret,
    assess_status,
    reload_systemd,
    pause_unit_helper,
    resume_unit_helper,
    remove_old_packages,
)
from ceilometer_contexts import CEILOMETER_PORT
from charmhelpers.contrib.openstack.ip import (
    canonical_url,
    PUBLIC, INTERNAL, ADMIN
)
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.network.ip import (
    get_relation_ip,
)
from charmhelpers.contrib.hahelpers.cluster import (
    is_clustered,
    is_elected_leader
)
from charmhelpers.contrib.peerstorage import (
    peer_retrieve,
    peer_store,
)
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.hardening.harden import harden

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook('install.real')
@harden()
def install():
    execd_preinstall()
    origin = config('openstack-origin')
    if (lsb_release()['DISTRIB_CODENAME'] == 'precise' and origin == 'distro'):
        origin = 'cloud:precise-grizzly'
    configure_installation_source(origin)
    packages = filter_installed_packages(get_packages())
    if packages:
        status_set('maintenance', 'Installing packages')
        apt_update(fatal=True)
        apt_install(packages, fatal=True)
    if init_is_systemd():
        # NOTE(jamespage): ensure systemd override folder exists prior to
        #                  attempting to write override.conf
        mkdir(os.path.dirname(CEILOMETER_API_SYSTEMD_CONF))
    if run_in_apache():
        disable_package_apache_site()


@hooks.hook("amqp-listener-relation-joined")
@hooks.hook("amqp-relation-joined")
def amqp_joined():
    relation_set(username=config('rabbit-user'),
                 vhost=config('rabbit-vhost'))


@hooks.hook("shared-db-relation-joined")
def db_joined():
    relation_set(ceilometer_database=CEILOMETER_DB)


@hooks.hook("metric-service-relation-joined")
def metric_service_joined():
    # NOTE(jamespage): gnocchiclient is required to support
    #                  the gnocchi event dispatcher
    release = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    pkgs = ['python-gnocchiclient']
    if release >= 'rocky':
        pkgs = ['python3-gnocchiclient']
    apt_install(filter_installed_packages(pkgs), fatal=True)


@hooks.hook("amqp-relation-changed",
            "amqp-relation-departed",
            "amqp-listener-relation-changed",
            "amqp-listener-relation-departed",
            "shared-db-relation-changed",
            "shared-db-relation-departed",
            "identity-service-relation-changed",
            "identity-service-relation-departed",
            "identity-credentials-relation-changed",
            "identity-credentials-relation-departed",
            "metric-service-relation-changed",
            "metric-service-relation-departed",
            "event-service-relation-changed",
            "event-service-relation-departed",)
@restart_on_change(restart_map())
def any_changed():
    CONFIGS.write_all()
    for r_id in relation_ids('certificates'):
        for unit in related_units(r_id):
            certs_changed(r_id, unit)
    configure_https()
    for rid in relation_ids('identity-service'):
        keystone_joined(relid=rid)
    ceilometer_joined()


def configure_https():
    """Enables SSL API Apache config if appropriate."""
    # need to write all to ensure changes to the entire request pipeline
    # propagate (c-api, haprxy, apache)
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename >= 'queens':
        ssl = ApacheSSLContext()
        ssl.configure_ca()
        return
    CONFIGS.write_all()
    if 'https' in CONFIGS.complete_contexts():
        cmd = ['a2ensite', 'openstack_https_frontend']
        subprocess.check_call(cmd)
    else:
        cmd = ['a2dissite', 'openstack_https_frontend']
        subprocess.check_call(cmd)

    # TODO: improve this by checking if local CN certs are available
    # first then checking reload status (see LP #1433114).
    if not is_unit_paused_set():
        if (cmp_codename <= 'newton' and
                CEILOMETER_API_SYSTEMD_CONF in restart_map()):
            reload_systemd()
        try:
            subprocess.check_call(['service', 'apache2', 'reload'])
        except subprocess.CalledProcessError:
            subprocess.call(['service', 'apache2', 'restart'])


@hooks.hook('config-changed')
@restart_on_change(restart_map())
@harden()
def config_changed():
    # if we are paused, delay doing any config changed hooks.
    # It is forced on the resume.
    if is_unit_paused_set():
        log("Unit is pause or upgrading. Skipping config_changed", "WARN")
        return

    if not config('action-managed-upgrade'):
        if openstack_upgrade_available('ceilometer-common'):
            status_set('maintenance', 'Upgrading to new OpenStack release')
            do_openstack_upgrade(CONFIGS)
    update_nrpe_config()
    CONFIGS.write_all()
    # NOTE(jamespage): Drop when charm switches to apache2+mod_wsgi
    #                  reload ensures port override is set correctly
    reload_systemd()
    ceilometer_joined()

    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename < 'queens':
        open_port(CEILOMETER_PORT)
    else:
        close_port(CEILOMETER_PORT)

    # Refire certificates relations for VIP changes
    for r_id in relation_ids('certificates'):
        certs_joined(r_id)

    configure_https()

    # NOTE(jamespage): Iterate identity-{service,credentials} relations
    #                  to pickup any required databag changes on these
    #                  relations.
    for rid in relation_ids('identity-service'):
        keystone_joined(relid=rid)
    for rid in relation_ids('identity-credentials'):
        keystone_credentials_joined(relid=rid)

    # Define the new ocf resource and use the key delete_resources to delete
    # legacy resource for >= Liberty since the ceilometer-agent-central moved
    # to ceilometer-polling in liberty (see LP: #1606787).
    for rid in relation_ids('ha'):
        ha_joined(rid)


@hooks.hook('upgrade-charm')
@harden()
def upgrade_charm():
    install()
    packages_removed = remove_old_packages()
    if packages_removed and not is_unit_paused_set():
        log("Package purge detected, restarting services", "INFO")
        for s in services():
            service_restart(s)
    update_nrpe_config()
    any_changed()
    for rid in relation_ids('cluster'):
        cluster_joined(relation_id=rid)
    # NOTE: (thedac) Currently there is no method to independently check if
    # ceilometer-upgrade has been run short of manual DB queries.
    # On upgrade-charm the leader node must assume it has already been run
    # and assert so with leader-set. If this is not done, then the upgrade from
    # the previous version of the charm will leave ceilometer in a blocked
    # state.
    if is_leader() and relation_ids("metric-service"):
        if not leader_get("ceilometer_upgrade_run"):
            log("Assuming ceilometer-upgrade has been run. If this is not the "
                "case, please run the ceilometer-upgrade action on the leader "
                "node.", level=WARNING)
            leader_set(ceilometer_upgrade_run=True)


@hooks.hook('cluster-relation-joined')
@restart_on_change(restart_map(), stopstart=True)
def cluster_joined(relation_id=None):
    # If this node is the elected leader then share our secret with other nodes
    if is_elected_leader('grp_ceilometer_vips'):
        peer_store('shared_secret', get_shared_secret())

    CONFIGS.write_all()

    settings = {}

    for addr_type in ADDRESS_TYPES:
        address = get_relation_ip(
            addr_type,
            cidr_network=config('os-{}-network'.format(addr_type)))
        if address:
            settings['{}-address'.format(addr_type)] = address

    settings['private-address'] = get_relation_ip('cluster')

    relation_set(relation_id=relation_id, relation_settings=settings)


@hooks.hook('cluster-relation-changed',
            'cluster-relation-departed')
@restart_on_change(restart_map(), stopstart=True)
def cluster_changed():
    shared_secret = peer_retrieve('shared_secret')
    if shared_secret is None or shared_secret.strip() == '':
        log('waiting for shared secret to be provided by leader')
    elif not shared_secret == get_shared_secret():
        set_shared_secret(shared_secret)

    CONFIGS.write_all()


@hooks.hook('ha-relation-joined')
def ha_joined(relation_id=None):
    ceil_ha_settings = {
        'resources': {
            'res_ceilometer_agent_central': 'lsb:ceilometer-agent-central'},
        'resource_params': {
            'res_ceilometer_agent_central': 'op monitor interval="30s"'},
        'delete_resources': ['res_ceilometer_polling'],
    }

    haproxy_enabled = True
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename >= 'ocata':
        haproxy_enabled = False
        ceil_ha_settings['delete_resources'].append('res_ceilometer_haproxy')

    settings = generate_ha_relation_data(
        'ceilometer',
        haproxy_enabled=haproxy_enabled,
        extra_settings=ceil_ha_settings)
    relation_set(relation_id=relation_id, **settings)


@hooks.hook('ha-relation-changed')
def ha_changed():
    clustered = relation_get('clustered')
    if not clustered or clustered in [None, 'None', '']:
        log('ha_changed: hacluster subordinate not fully clustered.')
    else:
        log('Cluster configured, notifying other services and updating '
            'keystone endpoint configuration')
        for rid in relation_ids('identity-service'):
            keystone_joined(relid=rid)


@hooks.hook("identity-credentials-relation-joined")
def keystone_credentials_joined(relid=None):
    relation_set(relation_id=relid,
                 username=CEILOMETER_SERVICE,
                 requested_roles=CEILOMETER_ROLE)


@hooks.hook("identity-service-relation-joined")
def keystone_joined(relid=None):
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename >= 'queens':
        log("For OpenStack version Queens and onwards Ceilometer Charm "
            "requires the 'identity-credentials' relation to Keystone, not "
            "the 'identity-service' relation.", level=WARNING)
        log('Skipping endpoint registration for >= Queens', level=DEBUG)
        return

    if config('vip') and not is_clustered():
        log('Defering registration until clustered', level=DEBUG)
        return

    public_url = "{}:{}".format(
        canonical_url(CONFIGS, PUBLIC),
        CEILOMETER_PORT
    )
    admin_url = "{}:{}".format(
        canonical_url(CONFIGS, ADMIN),
        CEILOMETER_PORT
    )
    internal_url = "{}:{}".format(
        canonical_url(CONFIGS, INTERNAL),
        CEILOMETER_PORT
    )
    region = config("region")
    relation_set(relation_id=relid,
                 service=CEILOMETER_SERVICE,
                 public_url=public_url,
                 admin_url=admin_url,
                 internal_url=internal_url,
                 requested_roles=CEILOMETER_ROLE,
                 region=region)


@hooks.hook('identity-notifications-relation-changed')
def identity_notifications_changed():
    """Receive notifications from keystone."""
    notifications = relation_get()
    if not notifications:
        return

    # Some ceilometer services will create a client and request
    # the service catalog from keystone on startup. So if
    # endpoints change we need to restart these services.
    key = '%s-endpoint-changed' % (CEILOMETER_SERVICE)
    if key in notifications:
        service_restart('ceilometer-alarm-evaluator')
        service_restart('ceilometer-alarm-notifier')


@hooks.hook("ceilometer-service-relation-joined")
def ceilometer_joined():
    # Pass local context data onto related agent services
    context = get_ceilometer_context()
    # This value gets tranformed to a path by the context we need to
    # pass the data to agents.
    if 'rabbit_ssl_ca' in context:
        with open(context['rabbit_ssl_ca'], 'rb') as fh:
            context['rabbit_ssl_ca'] = base64.b64encode(fh.read())
    for relid in relation_ids('ceilometer-service'):
        relation_set(relid, context)


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    apt_install('python-dbus')
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.copy_nrpe_checks()
    nrpe.add_init_service_checks(nrpe_setup, services(), current_unit)
    nrpe.add_haproxy_checks(nrpe_setup, current_unit)
    nrpe_setup.write()


@hooks.hook('update-status')
@harden()
def update_status():
    log('Updating status.')


@hooks.hook('pre-series-upgrade')
def pre_series_upgrade():
    log("Running prepare series upgrade hook", "INFO")
    series_upgrade_prepare(
        pause_unit_helper, CONFIGS)


@hooks.hook('post-series-upgrade')
def post_series_upgrade():
    log("Running complete series upgrade hook", "INFO")
    if init_is_systemd():
        # NOTE(ajkavangh): ensure systemd override folder exists prior to
        #                  attempting to write override.conf
        #                  See bug: #1838634
        mkdir(os.path.dirname(CEILOMETER_API_SYSTEMD_CONF))
    series_upgrade_complete(
        resume_unit_helper, CONFIGS)


@hooks.hook('certificates-relation-joined')
def certs_joined(relation_id=None):
    relation_set(
        relation_id=relation_id,
        relation_settings=cert_utils.get_certificate_request())


@hooks.hook('certificates-relation-changed')
def certs_changed(relation_id=None, unit=None):
    @restart_on_change(restart_map())
    def _certs_changed():
        cert_utils.process_certificates('ceilometer', relation_id, unit)
        configure_https()
    _certs_changed()


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    assess_status(CONFIGS)
