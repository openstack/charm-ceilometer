#!/usr/bin/python
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
import shutil
import subprocess
import sys
import os

from charmhelpers.fetch import (
    apt_install, filter_installed_packages,
    apt_update
)
from charmhelpers.core.hookenv import (
    open_port,
    close_port,
    relation_get,
    relation_set,
    relation_ids,
    config,
    Hooks, UnregisteredHookError,
    log,
    status_set,
    WARNING,
    DEBUG,
)
from charmhelpers.core.host import (
    service_restart,
    lsb_release,
    mkdir,
    init_is_systemd,
)
from charmhelpers.contrib.openstack.context import ADDRESS_TYPES
from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    openstack_upgrade_available,
    pausable_restart_on_change as restart_on_change,
    is_unit_paused_set,
    get_os_codename_install_source,
    CompareOpenStackReleases,
)
from charmhelpers.contrib.openstack.ha.utils import (
    update_dns_ha_resource_params,
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
    ceilometer_upgrade,
)
from ceilometer_contexts import CEILOMETER_PORT
from charmhelpers.contrib.openstack.ip import (
    canonical_url,
    PUBLIC, INTERNAL, ADMIN
)
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.network.ip import (
    get_iface_for_address,
    get_netmask_for_address,
    get_relation_ip,
    is_ipv6,
)
from charmhelpers.contrib.hahelpers.cluster import (
    get_hacluster_config,
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
    apt_install(filter_installed_packages(['python-gnocchiclient']),
                fatal=True)


@hooks.hook("amqp-relation-changed",
            "amqp-relation-departed",
            "shared-db-relation-changed",
            "shared-db-relation-departed",
            "identity-service-relation-changed",
            "identity-service-relation-departed",
            "identity-credentials-relation-changed",
            "identity-credentials-relation-departed",
            "metric-service-relation-changed",
            "metric-service-relation-departed")
@restart_on_change(restart_map())
def any_changed():
    CONFIGS.write_all()
    configure_https()
    for rid in relation_ids('identity-service'):
        keystone_joined(relid=rid)
    ceilometer_joined()
    # NOTE(jamespage): ceilometer@ocata requires both gnocchi
    #                  and mongodb to be configured to successfully
    #                  upgrade the underlying data stores.
    if ('metric-service' in CONFIGS.complete_contexts() and
            'identity-service' in CONFIGS.complete_contexts()):
        cmp_codename = CompareOpenStackReleases(
            get_os_codename_install_source(config('openstack-origin')))
        # NOTE(jamespage): however at queens, this limitation has gone!
        if (cmp_codename < 'queens' and
                'mongodb' not in CONFIGS.complete_contexts()):
            return
        ceilometer_upgrade()


def configure_https():
    """Enables SSL API Apache config if appropriate."""
    # need to write all to ensure changes to the entire request pipeline
    # propagate (c-api, haprxy, apache)
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename >= 'queens':
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
        try:
            subprocess.check_call(['service', 'apache2', 'reload'])
        except subprocess.CalledProcessError:
            subprocess.call(['service', 'apache2', 'restart'])


@hooks.hook('config-changed')
@restart_on_change(restart_map())
@harden()
def config_changed():
    if not config('action-managed-upgrade'):
        if openstack_upgrade_available('ceilometer-common'):
            status_set('maintenance', 'Upgrading to new OpenStack release')
            do_openstack_upgrade(CONFIGS)
    install_event_pipeline_setting()
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


def install_event_pipeline_setting():
    src_file = 'files/event_pipeline_alarm.yaml'
    dest_file = '/etc/ceilometer/event_pipeline_alarm.yaml'
    if not os.path.isdir(os.path.dirname(dest_file)):
        os.makedirs(os.path.dirname(dest_file))
    shutil.copy(src_file, dest_file)


@hooks.hook('upgrade-charm')
@harden()
def upgrade_charm():
    install()
    update_nrpe_config()
    any_changed()
    for rid in relation_ids('cluster'):
        cluster_joined(relation_id=rid)


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
    cluster_config = get_hacluster_config()
    delete_resources = []
    delete_resources.append('res_ceilometer_polling')

    resources = {
        'res_ceilometer_haproxy': 'lsb:haproxy',
        'res_ceilometer_agent_central': 'lsb:ceilometer-agent-central',
    }

    resource_params = {
        'res_ceilometer_haproxy': 'op monitor interval="5s"',
        'res_ceilometer_agent_central': 'op monitor interval="30s"'
    }

    if config('dns-ha'):
        update_dns_ha_resource_params(relation_id=relation_id,
                                      resources=resources,
                                      resource_params=resource_params)
    else:
        vip_group = []
        for vip in cluster_config['vip'].split():
            if is_ipv6(vip):
                res_ceilometer_vip = 'ocf:heartbeat:IPv6addr'
                vip_params = 'ipv6addr'
            else:
                res_ceilometer_vip = 'ocf:heartbeat:IPaddr2'
                vip_params = 'ip'

            iface = get_iface_for_address(vip)
            if iface is not None:
                vip_key = 'res_ceilometer_{}_vip'.format(iface)
                if vip_key in vip_group:
                    if vip not in resource_params[vip_key]:
                        vip_key = '{}_{}'.format(vip_key, vip_params)
                    else:
                        log("Resource '%s' (vip='%s') already exists in "
                            "vip group - skipping" % (vip_key, vip), WARNING)
                        continue

                resources[vip_key] = res_ceilometer_vip
                resource_params[vip_key] = (
                    'params {ip}="{vip}" cidr_netmask="{netmask}"'
                    ' nic="{iface}"'
                    ''.format(ip=vip_params,
                              vip=vip,
                              iface=iface,
                              netmask=get_netmask_for_address(vip))
                )
                vip_group.append(vip_key)

        if len(vip_group) >= 1:
            relation_set(relation_id=relation_id,
                         groups={'grp_ceilometer_vips':
                                 ' '.join(vip_group)})

    init_services = {
        'res_ceilometer_haproxy': 'haproxy'
    }
    clones = {
        'cl_ceilometer_haproxy': 'res_ceilometer_haproxy'
    }
    relation_set(relation_id=relation_id,
                 init_services=init_services,
                 corosync_bindiface=cluster_config['ha-bindiface'],
                 corosync_mcastport=cluster_config['ha-mcastport'],
                 resources=resources,
                 resource_params=resource_params,
                 delete_resources=delete_resources,
                 clones=clones)


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
        with open(context['rabbit_ssl_ca']) as fh:
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


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    assess_status(CONFIGS)
