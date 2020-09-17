# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from charmhelpers.core.hookenv import (
    relation_ids,
    relation_get,
    related_units,
    config,
    log,
    INFO,
    WARNING,
)

from charmhelpers.contrib.openstack.utils import (
    get_os_codename_package,
    os_release,
    CompareOpenStackReleases,
)

from charmhelpers.contrib.openstack.context import (
    OSContextGenerator,
    context_complete,
    ApacheSSLContext as SSLContext,
    AMQPContext,
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
        _release = os_release('ceilometer-common')
        use_replset = CompareOpenStackReleases(_release) >= 'icehouse'

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

        if mongo_servers and replset:
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

        # Make sure to cast the time-to-live events to integer values.
        # For large enough numbers, Juju returns the value in scientific
        # notation which causes python to treat the number as a float
        # value, which in turn causes ceilometer to fail to start.
        # See LP#1651645 for more details.
        ctxt = {
            'port': CEILOMETER_PORT,
            'metering_secret': get_shared_secret(),
            'metering_time_to_live': int(config('metering-time-to-live')),
            'event_time_to_live': int(config('event-time-to-live')),
            'polling_interval': int(config('polling-interval')),
            'enable_all_pollsters': config('enable-all-pollsters'),
            'polling_batch_size': config('polling-batch-size'),
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


class CeilometerPipelineContext(OSContextGenerator):
    def __call__(self):
        ctxt = {
            'pipeline_yaml': config('pipeline-yaml')
        }
        return ctxt


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


class RemoteSinksContext(OSContextGenerator):
    interfaces = ['event-service']

    def __call__(self):
        '''Generates context for remote sinks for Panko and other compatible
        remote consumers of Ceilometer event data.
        '''
        ctxt = {}
        if config('remote-sink'):
            ctxt['remote_sinks'] = config('remote-sink').split(' ')
        for relid in relation_ids('event-service'):
            for unit in related_units(relid):
                publisher = relation_get('publisher', unit=unit, rid=relid)
                if publisher:
                    if not ctxt.get('internal_sinks'):
                        ctxt['internal_sinks'] = {}
                    ctxt['internal_sinks'][unit.split('/')[0]] = publisher

        release = get_os_codename_package('ceilometer-common', fatal=False)
        ctxt['event_sink_publisher'] = None
        if CompareOpenStackReleases(release) >= 'queens':
            # NOTE: see bug LP 1676586
            if config('events-publisher') == "aodh":
                ctxt['event_sink_publisher'] = 'notifier://?topic=alarm.all'
            elif config('events-publisher') == "gnocchi":
                if relation_ids('metric-service'):
                    ctxt['event_sink_publisher'] = 'gnocchi://'
                else:
                    log("Unable to configure event publisher '{}' since "
                        "no gnocchi relation found".
                        format(config('events-publisher')), level=INFO)
            elif config('events-publisher') == "":
                log("Not configuring any event publishers", level=INFO)
            else:
                log("Invalid event publisher config provided '{}'. Not "
                    "configuring any event publishers".
                    format(config('events-publisher')), level=WARNING)

        return ctxt


class ApacheSSLContext(SSLContext):

    external_ports = [CEILOMETER_PORT]
    service_namespace = "ceilometer"


class MetricServiceContext(OSContextGenerator):
    interfaces = ['metric-service']

    def __call__(self):

        for relid in relation_ids('metric-service'):
            for unit in related_units(relid):
                gnocchi_url = relation_get('gnocchi_url', unit=unit, rid=relid)
                if gnocchi_url:
                    return {'gnocchi_url': gnocchi_url,
                            'archive_policy': config('gnocchi-archive-policy')}
        return {}


class AMQPListenersContext(OSContextGenerator):
    interfaces = ['amqp-listener']

    def __init__(self, ssl_dir=None):
        self.ssl_dir = ssl_dir

    def __call__(self):
        ctxt = {}
        messaging_urls = []
        relids = relation_ids('amqp-listener') + relation_ids('amqp')
        for relid in relids:
            amqp_ctxt = AMQPContext(ssl_dir=self.ssl_dir, relation_id=relid)()
            if amqp_ctxt.get('transport_url'):
                messaging_urls.append(amqp_ctxt['transport_url'])
        if messaging_urls:
            ctxt['messaging_urls'] = messaging_urls
        return ctxt
