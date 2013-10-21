#!/usr/bin/python

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
    restart_on_change
)
from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    openstack_upgrade_available
)
from ceilometer_utils import (
    CEILOMETER_PACKAGES,
    CEILOMETER_DB,
    CEILOMETER_SERVICE,
    CEILOMETER_ROLE,
    register_configs,
    restart_map,
    get_ceilometer_context,
    do_openstack_upgrade
)
from ceilometer_contexts import CEILOMETER_PORT

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook()
def install():
    configure_installation_source(config('openstack-origin'))
    apt_update(fatal=True)
    apt_install(filter_installed_packages(CEILOMETER_PACKAGES),
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


@hooks.hook('config-changed')
@restart_on_change(restart_map())
def config_changed():
    if openstack_upgrade_available('ceilometer-common'):
        do_openstack_upgrade(CONFIGS)
    CONFIGS.write_all()
    ceilometer_joined()


@hooks.hook('upgrade-charm')
def upgrade_charm():
    install()
    any_changed()


@hooks.hook("identity-service-relation-joined")
def keystone_joined():
    url = "http://{}:{}".format(unit_get("private-address"),
                                CEILOMETER_PORT)
    region = config("region")
    relation_set(service=CEILOMETER_SERVICE,
                 public_url=url, admin_url=url, internal_url=url,
                 requested_roles=CEILOMETER_ROLE,
                 region=region)


@hooks.hook("ceilometer-service-relation-joined")
def ceilometer_joined():
    # Pass local context data onto related agent services
    context = get_ceilometer_context()
    for relid in relation_ids('ceilometer-service'):
        relation_set(relid, context)

if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
