#!/usr/bin/python

import base64
import sys
from charmhelpers.fetch import (
    apt_install, filter_installed_packages,
    apt_update
)
from charmhelpers.core.hookenv import (
    open_port,
    relation_set,
    relation_ids,
    config,
    unit_get,
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
    get_ceilometer_context,
    do_openstack_upgrade
)
from ceilometer_contexts import CEILOMETER_PORT
from charmhelpers.contrib.network.ip import get_address_in_network

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
    CONFIGS.write_all()
    ceilometer_joined()
    for rid in relation_ids('identity-service'):
        keystone_joined(relid=rid)

@hooks.hook('upgrade-charm')
def upgrade_charm():
    install()
    any_changed()


@hooks.hook("identity-service-relation-joined")
def keystone_joined(relid=None):    
    public_url = "http://{}:{}".format(
        get_address_in_network(config('os-public-network'),
                               unit_get("public-address")),
        CEILOMETER_PORT
    )
    admin_url = "http://{}:{}".format(
        get_address_in_network(config('os-admin-network'),
                               unit_get("private-address")),
        CEILOMETER_PORT
    )
    internal_url = "http://{}:{}".format(
        get_address_in_network(config('os-internal-network'),
                               unit_get("private-address")),
        CEILOMETER_PORT
    )    
    region = config("region")
    relation_set(relation_id=relid,
                 service=CEILOMETER_SERVICE,
                 public_url=public_url, admin_url=admin_url, internal_url=internal_url,
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

if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
