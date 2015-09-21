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
        mongo_servers = []
        replset = None
        use_replset = os_release('ceilometer-api') >= 'icehouse'

        for relid in relation_ids('shared-db'):
            rel_units = related_units(relid)
            use_replset = use_replset and (len(rel_units) > 1)

            for unit in rel_units:
                host = relation_get('hostname', unit, relid)
                port = relation_get('port', unit, relid)

                conf = {
                    "db_host": host,
                    "db_port": port,
                    "db_name": CEILOMETER_DB
                }

                if not context_complete(conf):
                    continue

                if not use_replset:
                    return conf

                if replset is None:
                    replset = relation_get('replset', unit, relid)

                mongo_servers.append('{}:{}'.format(host, port))

        if mongo_servers:
            return {
                'db_mongo_servers': ','.join(mongo_servers),
                'db_name': CEILOMETER_DB,
                'db_replset': replset
            }

        return {}


CEILOMETER_PORT = 8777


class CeilometerContext(OSContextGenerator):
    def __call__(self):
        # Lazy-import to avoid a circular dependency in the imports
        from ceilometer_utils import get_shared_secret

        ctxt = {
            'api_workers': config('api-workers'),
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
        api_port = determine_api_port(CEILOMETER_PORT, singlenode_mode=True)
        apache_port = determine_apache_port(CEILOMETER_PORT,
                                            singlenode_mode=True)

        ctxt = {
            'service_ports': {'ceilometer_api': [haproxy_port, apache_port]},
            'port': api_port
        }
        return ctxt


class ApacheSSLContext(SSLContext):

    external_ports = [CEILOMETER_PORT]
    service_namespace = "ceilometer"
