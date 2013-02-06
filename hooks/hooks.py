#!/usr/bin/python

import sys
import time
import os
import utils
import ceilometer_utils

config = config_get()

service = "ceilometer"

def install():
    utils.configure_source()
    packages = ['python-ceilometer', 'ceilometer-common', 'ceilometer-agent-central', 'ceilometer-collector', 'ceilometer-api']
    utils.install(packages)

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

def render_ceilometer_conf():
    context = get_rabbit_conf()
    context['metering_secret'] = ceilometer_utils.get_shared_secret()

    if (context and os.path.exists(ceilometer_utils.CEILOMETER_CONF)):
        with open(ceilometer_utils.CEILOMETER_CONF, "w") as conf:
            conf.write(utils.render_template(os.path.basename(ceilometer_utils.CEILOMETER_CONF), context))

def amqp_changed():
    render_ceilometer_conf()
    utils.restart(['ceilometer-agent-central', 'ceilometer-collector'])

utils.do_hooks({
    "install": install,
    "amqp-relation-joined": amqp_joined,
    "amqp-relation-changed": amqp_changed
})
sys.exit(0)
