#!/usr/bin/python

import os
import sys
#import lib.utils as utils
from charmhelpers.fetch import (
    apt_install, filter_installed_packages,
    apt_update
)
from charmhelpers.core.hookenv import (
    open_port,
    relation_set,
    relation_get,
    relation_ids,
    related_units,
    config,
    unit_get,
    Hooks, UnregisteredHookError,
    log
)
from charmhelpers.core.host import (
    service_restart,
)
from charmhelpers.contrib.openstack.utils import (
    configure_installation_source
)
from ceilometer_utils import (
    CEILOMETER_PACKAGES,
    CEILOMETER_PORT,
    RABBIT_USER,
    RABBIT_VHOST,
    CEILOMETER_DB,
    CEILOMETER_SERVICES,
    CEILOMETER_SERVICE,
    CEILOMETER_ROLE,
    CEILOMETER_CONF,
    get_shared_secret,
    render_template
)

hooks = Hooks()


@hooks.hook()
def install():
    configure_installation_source(config('openstack-origin'))
    apt_update(fatal=True)
    apt_install(filter_installed_packages(CEILOMETER_PACKAGES),
                fatal=True)
    open_port(CEILOMETER_PORT)


@hooks.hook("amqp-relation-joined")
def amqp_joined():
    relation_set(username=RABBIT_USER,
                 vhost=RABBIT_VHOST)


@hooks.hook("shared-db-relation-joined")
def db_joined():
    relation_set(ceilometer_database=CEILOMETER_DB)


@hooks.hook("amqp-relation-changed",
            "shared-db-relation-changed",
            "identity-service-relation-changed")
def all_changed():
    if render_ceilometer_conf():
        for svc in CEILOMETER_SERVICES:
            service_restart(svc)
        ceilometer_joined()


@hooks.hook("identity-service-relation-joined")
def keystone_joined():
    url = "http://{}:{}".format(unit_get("private-address"),
                                CEILOMETER_PORT)
    region = config("region")

    relation_set(service=CEILOMETER_SERVICE,
                 public_url=url, admin_url=url, internal_url=url,
                 requested_roles=CEILOMETER_ROLE,
                 region=region)


def get_rabbit_conf():
    for relid in relation_ids('amqp'):
        for unit in related_units(relid):
            conf = {
                "rabbit_host": relation_get('private-address',
                                            unit, relid),
                "rabbit_virtual_host": RABBIT_VHOST,
                "rabbit_userid": RABBIT_USER,
                "rabbit_password": relation_get('password',
                                                unit, relid)
            }
            if relation_get('clustered',
                            unit, relid):
                conf["rabbit_host"] = relation_get('vip', unit, relid)
            if None not in conf.itervalues():
                return conf
    return None


def get_db_conf():
    for relid in relation_ids('shared-db'):
        for unit in related_units(relid):
            conf = {
                "db_host": relation_get('hostname', unit, relid),
                "db_port": relation_get('port', unit, relid),
                "db_name": CEILOMETER_DB
            }
            if None not in conf.itervalues():
                return conf
    return None


def get_keystone_conf():
    for relid in relation_ids('identity-service'):
        for unit in related_units(relid):
            keystone_username = relation_get('service_username',
                                             unit, relid)
            keystone_port = relation_get('service_port',
                                         unit, relid)
            keystone_host = relation_get('service_host',
                                         unit, relid)
            keystone_password = relation_get('service_password',
                                             unit, relid)
            keystone_tenant = relation_get('service_tenant',
                                           unit, relid)

            conf = {
                "keystone_os_username": keystone_username,
                "keystone_os_password": keystone_password,
                "keystone_os_tenant": keystone_tenant,
                "keystone_host": keystone_host,
                "keystone_port": keystone_port
            }
            if None not in conf.itervalues():
                return conf
    return None


def render_ceilometer_conf():
    context = get_rabbit_conf()
    contextdb = get_db_conf()
    contextkeystone = get_keystone_conf()

    if (context and contextdb and contextkeystone and
            os.path.exists(CEILOMETER_CONF)):
        # merge contexts
        context.update(contextkeystone)
        context.update(contextdb)
        context['metering_secret'] = get_shared_secret()
        context['service_port'] = CEILOMETER_PORT

        with open(CEILOMETER_CONF, "w") as conf:
            conf.write(render_template(os.path.basename(CEILOMETER_CONF),
                                       context))

        return True
    return False


@hooks.hook("ceilometer-service-relation-joined")
def ceilometer_joined():
    # set all relationships for ceilometer service
    context = get_rabbit_conf()
    contextdb = get_db_conf()
    contextkeystone = get_keystone_conf()
    if context and contextdb and contextkeystone:
        context.update(contextdb)
        context.update(contextkeystone)
        context["metering_secret"] = get_shared_secret()
        # set all that info into ceilometer-service relationship
        for relid in relation_ids('ceilometer-service'):
            relation_set(relid, context)

if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
