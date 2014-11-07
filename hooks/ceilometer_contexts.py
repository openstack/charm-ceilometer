import os
import uuid
from charmhelpers.core.hookenv import (
    relation_ids,
    relation_get,
    related_units,
    config
)

from charmhelpers.contrib.openstack.utils import os_release

from charmhelpers.contrib.openstack.context import (
    OSContextGenerator,
    context_complete,
    ApacheSSLContext as SSLContext,
)

from charmhelpers.contrib.hahelpers.cluster import (
    determine_apache_port,
    determine_api_port
)

CEILOMETER_DB = 'ceilometer'


class LoggingConfigContext(OSContextGenerator):
    def __call__(self):
        return {'debug': config('debug'), 'verbose': config('verbose')}


class MongoDBContext(OSContextGenerator):
    interfaces = ['mongodb']

    def __call__(self):
        hostnames = []
        port = None
        replset = None
        # TODO(wolsen) add a check in which will only execute this on a
        # supported level of ceilometer code, which would be a specific version
        # of the code, not just icehouse.
        support = os_release('ceilometer-api') >= 'icehouse'
        
        for relid in relation_ids('shared-db'):
            for unit in related_units(relid):
                replset = relation_get('replset', unit, relid)
                host = relation_get('hostname', unit, relid)
                if port is None:
                    port = relation_get('port', unit, relid)
                
                # If replica sets aren't used or aren't supported by ceilometer
                # then stop looping if there is enough data 
                if not support or not replset:
                    if context_complete({'db_host': host, 'db_port': port}):
                        hostnames.append(host)
                        #print "Either not supported or no replset"
                        break
                else:
                    hostnames.append('{}:{}'.format(host, port))

        # If there aren't any hosts, then there's no real configuration
        # to fill in here, so bail early
        if port is None or port == '':
            #print "Exiting early {}, {}".format(len(hostnames), port)
            return {}
        
        conf = {
            'db_host': ','.join(hostnames),
            'db_port': port,
            'db_name': CEILOMETER_DB
        }

        if replset:
            conf['db_replset'] = replset

        return conf


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
        api_port = determine_api_port(CEILOMETER_PORT)
        apache_port = determine_apache_port(CEILOMETER_PORT)

        ctxt = {
            'service_ports': {'ceilometer_api': [haproxy_port, apache_port]},
            'port': api_port
        }
        return ctxt


class ApacheSSLContext(SSLContext):

    service_namespace = "ceilometer"

    external_ports = [CEILOMETER_PORT+100]
