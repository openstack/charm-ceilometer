#!/usr/bin/python

import os
import lib.utils as utils
import ceilometer_utils


def install():
    utils.configure_source()
    utils.install(*ceilometer_utils.CEILOMETER_PACKAGES)
    utils.expose(ceilometer_utils.CEILOMETER_PORT)


def amqp_joined():
    utils.relation_set(username=ceilometer_utils.RABBIT_USER,
        vhost=ceilometer_utils.RABBIT_VHOST)


def amqp_changed():
    if render_ceilometer_conf():
        utils.restart(*ceilometer_utils.CEILOMETER_SERVICES)
        ceilometer_joined()


def db_joined():
    utils.relation_set(ceilometer_database=ceilometer_utils.CEILOMETER_DB)


def db_changed():
    if render_ceilometer_conf():
        utils.restart(*ceilometer_utils.CEILOMETER_SERVICES)
        ceilometer_joined()


def keystone_joined():
    port = ceilometer_utils.CEILOMETER_PORT
    url = "http://" + utils.unit_get("private-address") + ":" + str(port)
    region = utils.config_get("region")

    utils.relation_set(service=ceilometer_utils.CEILOMETER_SERVICE,
        public_url=url, admin_url=url, internal_url=url, region=region)


def keystone_changed():
    if render_ceilometer_conf():
        utils.restart(*ceilometer_utils.CEILOMETER_SERVICES)
        ceilometer_joined()


def get_rabbit_conf():
    for relid in utils.relation_ids('amqp'):
        for unit in utils.relation_list(relid):
            conf = {
                "rabbit_host": utils.relation_get('private-address',
                                                  unit, relid),
                "rabbit_virtual_host": ceilometer_utils.RABBIT_VHOST,
                "rabbit_userid": ceilometer_utils.RABBIT_USER,
                "rabbit_password": utils.relation_get('password',
                                                      unit, relid)
                }
            if utils.relation_get('clustered',
                                  unit, relid):
                conf["rabbit_host"] = utils.relation_get('vip',
                                                         unit, relid)
            if None not in conf.itervalues():
                return conf
    return None


def get_db_conf():
    for relid in utils.relation_ids('shared-db'):
        for unit in utils.relation_list(relid):
            conf = {
                "db_host": utils.relation_get('hostname', unit, relid),
                "db_port": utils.relation_get('port', unit, relid),
                "db_name": ceilometer_utils.CEILOMETER_DB
                }
            if None not in conf.itervalues():
                return conf
    return None


def get_keystone_conf():
    for relid in utils.relation_ids('identity-service'):
        for unit in utils.relation_list(relid):
            keystone_username = utils.relation_get('service_username',
                                                   unit, relid)
            keystone_port = utils.relation_get('service_port',
                                               unit, relid)
            keystone_host = utils.relation_get('service_host',
                                               unit, relid)
            keystone_password = utils.relation_get('service_password',
                                                   unit, relid)
            keystone_tenant = utils.relation_get('service_tenant',
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
        os.path.exists(ceilometer_utils.CEILOMETER_CONF)):
        # merge contexts
        context.update(contextkeystone)
        context.update(contextdb)
        context['metering_secret'] = ceilometer_utils.get_shared_secret()
        context['service_port'] = ceilometer_utils.CEILOMETER_PORT

        with open(ceilometer_utils.CEILOMETER_CONF, "w") as conf:
            conf.write(utils.render_template(
                os.path.basename(ceilometer_utils.CEILOMETER_CONF), context))

        return True
    return False


def ceilometer_joined():
    # set all relationships for ceilometer service
    context = get_rabbit_conf()
    contextdb = get_db_conf()
    contextkeystone = get_keystone_conf()
    if context and contextdb and contextkeystone:
        context.update(contextdb)
        context.update(contextkeystone)
        context["metering_secret"] = ceilometer_utils.get_shared_secret()
        # set all that info into ceilometer-service relationship
        for relid in utils.relation_ids('ceilometer-service'):
            context["rid"] = relid
            utils.relation_set(**context)


utils.do_hooks({
    "install": install,
    "amqp-relation-joined": amqp_joined,
    "amqp-relation-changed": amqp_changed,
    "shared-db-relation-joined": db_joined,
    "shared-db-relation-changed": db_changed,
    "identity-service-relation-joined": keystone_joined,
    "identity-service-relation-changed": keystone_changed,
    "ceilometer-service-relation-joined": ceilometer_joined
})
