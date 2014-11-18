#!/usr/bin/python

import base64
import sys
import os
from charmhelpers.fetch import (
    apt_install, filter_installed_packages,
    apt_update
)
from charmhelpers.core.hookenv import (
    open_port,
    local_unit,
    relation_set,
    relation_ids,
    relations_of_type,
    config,
    Hooks, UnregisteredHookError,
    log
)
from charmhelpers.core.host import (
    restart_on_change,
    lsb_release
)
from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    openstack_upgrade_available
)
from ceilometer_utils import (
    get_packages,
    CEILOMETER_DB,
    CEILOMETER_SERVICE,
    CEILOMETER_ROLE,
    register_configs,
    restart_map,
    services,
    get_ceilometer_context,
    do_openstack_upgrade
)
from ceilometer_contexts import CEILOMETER_PORT
from charmhelpers.contrib.openstack.ip import (
    canonical_url,
    PUBLIC, INTERNAL, ADMIN
)
from charmhelpers.contrib.charmsupport.nrpe import NRPE

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook()
def install():
    origin = config('openstack-origin')
    if (lsb_release()['DISTRIB_CODENAME'] == 'precise'
            and origin == 'distro'):
        origin = 'cloud:precise-grizzly'
    configure_installation_source(origin)
    apt_update(fatal=True)
    apt_install(filter_installed_packages(get_packages()),
                fatal=True)
    open_port(CEILOMETER_PORT)


@hooks.hook("amqp-relation-joined")
def amqp_joined():
    relation_set(username=config('rabbit-user'),
                 vhost=config('rabbit-vhost'))


@hooks.hook("shared-db-relation-joined")
def db_joined():
    relation_set(ceilometer_database=CEILOMETER_DB)


@hooks.hook("amqp-relation-changed",
            "shared-db-relation-changed",
            "identity-service-relation-changed")
@restart_on_change(restart_map())
def any_changed():
    CONFIGS.write_all()
    ceilometer_joined()


@hooks.hook("amqp-relation-departed")
@restart_on_change(restart_map())
def amqp_departed():
    if 'amqp' not in CONFIGS.complete_contexts():
        log('amqp relation incomplete. Peer not ready?')
        return
    CONFIGS.write_all()


@hooks.hook('config-changed')
@restart_on_change(restart_map())
def config_changed():
    if openstack_upgrade_available('ceilometer-common'):
        do_openstack_upgrade(CONFIGS)
    update_nrpe_config()
    CONFIGS.write_all()
    ceilometer_joined()
    for rid in relation_ids('identity-service'):
        keystone_joined(relid=rid)


@hooks.hook('upgrade-charm')
def upgrade_charm():
    install()
    update_nrpe_config()
    any_changed()


@hooks.hook("identity-service-relation-joined")
def keystone_joined(relid=None):
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
    # Find out if nrpe set nagios_hostname
    hostname = None
    host_context = None
    for rel in relations_of_type('nrpe-external-master'):
        if 'nagios_hostname' in rel:
            hostname = rel['nagios_hostname']
            host_context = rel['nagios_host_context']
            break
    nrpe = NRPE(hostname=hostname)
    apt_install('python-dbus')

    if host_context:
        current_unit = "%s:%s" % (host_context, local_unit())
    else:
        current_unit = local_unit()

    services_to_monitor = services()

    for service in services_to_monitor:
        upstart_init = '/etc/init/%s.conf' % service
        sysv_init = '/etc/init.d/%s' % service
        if os.path.exists(upstart_init):
            nrpe.add_check(
                shortname=service,
                description='process check {%s}' % current_unit,
                check_cmd='check_upstart_job %s' % service,
                )
        elif os.path.exists(sysv_init):
            cronpath = '/etc/cron.d/nagios-service-check-%s' % service
            cron_template = '*/5 * * * * root \
/usr/local/lib/nagios/plugins/check_exit_status.pl -s /etc/init.d/%s \
status > /var/lib/nagios/service-check-%s.txt\n' % (service, service)
            f = open(cronpath, 'w')
            f.write(cron_template)
            f.close()
            nrpe.add_check(
                shortname=service,
                description='process check {%s}' % current_unit,
                check_cmd='check_status_file.py -f \
                           /var/lib/nagios/service-check-%s.txt' % service,
                )

    nrpe.write()

if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
