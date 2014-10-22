import os
import uuid
from charmhelpers.core.hookenv import (
    relation_ids,
    relation_get,
    related_units,
    config
)

from charmhelpers.contrib.openstack.context import (
    OSContextGenerator,
    context_complete,
    ApacheSSLContext as SSLContext,
)

from charmhelpers.contrib.hahelpers.cluster import (
    determine_apache_port
)

CEILOMETER_DB = 'ceilometer'


class LoggingConfigContext(OSContextGenerator):
    def __call__(self):
        return {'debug': config('debug'), 'verbose': config('verbose')}


class MongoDBContext(OSContextGenerator):
    interfaces = ['mongodb']

    def __call__(self):
        for relid in relation_ids('shared-db'):
            for unit in related_units(relid):
                conf = {
                    "db_host": relation_get('hostname', unit, relid),
                    "db_port": relation_get('port', unit, relid),
                    "db_name": CEILOMETER_DB
                }
                if context_complete(conf):
                    return conf
        return {}


SHARED_SECRET = "/etc/ceilometer/secret.txt"


def get_shared_secret():
    secret = None
    if not os.path.exists(SHARED_SECRET):
        secret = str(uuid.uuid4())
        with open(SHARED_SECRET, 'w') as secret_file:
            secret_file.write(secret)
    else:
        with open(SHARED_SECRET, 'r') as secret_file:
            secret = secret_file.read().strip()
    return secret

CEILOMETER_PORT = 8777


class CeilometerContext(OSContextGenerator):
    def __call__(self):
        ctxt = {
            'port': CEILOMETER_PORT,
            'metering_secret': get_shared_secret()
        }
        return ctxt


class CeilometerServiceContext(OSContextGenerator):
    interfaces = ['ceilometer-service']

    def __call__(self):
        for relid in relation_ids('ceilometer-service'):
            for unit in related_units(relid):
                conf = relation_get(unit=unit, rid=relid)
                if context_complete(conf):
                    return conf
        return {}


class HAProxyContext(OSContextGenerator):
    interfaces = ['ceilometer-haproxy']

    def __call__(self):
        '''Extends the main charmhelpers HAProxyContext with a port mapping
        specific to this charm.
        '''
        haproxy_port = CEILOMETER_PORT
        apache_port = determine_apache_port(CEILOMETER_PORT)

        ctxt = {
            'service_ports': {'ceilometer_api': [haproxy_port, apache_port]},
        }
        return ctxt


class ApacheSSLContext(SSLContext):

    service_namespace = "ceilometer"

    external_ports = [CEILOMETER_PORT+100]
