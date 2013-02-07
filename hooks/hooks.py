#!/usr/bin/python

import sys
import time
import os
import utils
import ceilometer_utils

def install():
    utils.configure_source()
    packages = ['python-ceilometer', 'ceilometer-common', 'ceilometer-agent-central', 'ceilometer-collector', 'ceilometer-api']
    utils.install(*packages)

def amqp_joined():
    utils.relation_set(username=ceilometer_utils.RABBIT_USER, vhost=ceilometer_utils.RABBIT_VHOST)

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

def render_ceilometer_conf():
    context = get_rabbit_conf()
    contextdb = get_db_conf()

    if (context and contextdb and os.path.exists(ceilometer_utils.CEILOMETER_CONF)):
        context['metering_secret'] = ceilometer_utils.get_shared_secret()
        context['db_connection'] = "mongodb://"+contextdb["db_host"]+":"+contextdb["db_port"]+"/"+contextdb["db_name"]

        with open(ceilometer_utils.CEILOMETER_CONF, "w") as conf:
            conf.write(utils.render_template(os.path.basename(ceilometer_utils.CEILOMETER_CONF), context))

def amqp_changed():
    render_ceilometer_conf()
    utils.restart(*ceilometer_utils.CEILOMETER_SERVICES)

def db_joined():
    utils.relation_set(ceilometer_database=ceilometer_utils.CEILOMETER_DB)

def db_changed():
    render_ceilometer_conf()
    utils.restart(*ceilometer_utils.CEILOMETER_SERVICES)

utils.do_hooks({
    "install": install,
    "amqp-relation-joined": amqp_joined,
    "amqp-relation-changed": amqp_changed,
    "shared-db-relation-joined": db_joined,
    "shared-db-relation-changed": db_changed
})
sys.exit(0)
