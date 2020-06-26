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

import collections
from mock import patch, MagicMock

import ceilometer_contexts as contexts
import ceilometer_utils as utils

from test_utils import CharmTestCase, mock_open

TO_PATCH = [
    'config',
    'relation_get',
    'relation_ids',
    'related_units',
    'os_release',
]


class CeilometerContextsTest(CharmTestCase):

    def setUp(self):
        super(CeilometerContextsTest, self).setUp(contexts, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.relation_get.side_effect = self.test_relation.get

    def tearDown(self):
        super(CeilometerContextsTest, self).tearDown()

    def test_logging_context(self):
        self.test_config.set('debug', False)
        self.test_config.set('verbose', False)
        self.assertEqual(contexts.LoggingConfigContext()(),
                         {'debug': False, 'verbose': False})
        self.test_config.set('debug', True)
        self.test_config.set('verbose', False)
        self.assertEqual(contexts.LoggingConfigContext()(),
                         {'debug': True, 'verbose': False})
        self.test_config.set('debug', True)
        self.test_config.set('verbose', True)
        self.assertEqual(contexts.LoggingConfigContext()(),
                         {'debug': True, 'verbose': True})

    def test_mongodb_context_not_related(self):
        self.relation_ids.return_value = []
        self.os_release.return_value = 'icehouse'
        self.assertEqual(contexts.MongoDBContext()(), {})

    def test_mongodb_context_related(self):
        self.relation_ids.return_value = ['shared-db:0']
        self.related_units.return_value = ['mongodb/0']
        data = {
            'hostname': 'mongodb',
            'port': 8090
        }
        self.test_relation.set(data)
        self.os_release.return_value = 'havana'
        self.assertEqual(contexts.MongoDBContext()(),
                         {'db_host': 'mongodb', 'db_port': 8090,
                          'db_name': 'ceilometer'})

    def test_mongodb_context_related_replset_single_mongo(self):
        self.relation_ids.return_value = ['shared-db:0']
        self.related_units.return_value = ['mongodb/0']
        data = {
            'hostname': 'mongodb-0',
            'port': 8090,
            'replset': 'replset-1'
        }
        self.test_relation.set(data)
        self.os_release.return_value = 'icehouse'
        self.assertEqual(contexts.MongoDBContext()(),
                         {'db_host': 'mongodb-0', 'db_port': 8090,
                          'db_name': 'ceilometer'})

    @patch.object(contexts, 'context_complete')
    def test_mongodb_context_related_replset_missing_values(self, mock_ctxcmp):
        mock_ctxcmp.return_value = False
        self.relation_ids.return_value = ['shared-db:0']
        self.related_units.return_value = ['mongodb/0']
        data = {
            'hostname': None,
            'port': 8090,
            'replset': 'replset-1'
        }
        self.test_relation.set(data)
        self.os_release.return_value = 'icehouse'
        self.assertEqual(contexts.MongoDBContext()(), {})

    def test_mongodb_context_related_replset_multiple_mongo(self):
        self.relation_ids.return_value = ['shared-db:0']
        related_units = collections.OrderedDict(
            [('mongodb/0', {'hostname': 'mongodb-0',
                            'port': 8090,
                            'replset': 'replset-1'}),
             ('mongodb/1', {'hostname': 'mongodb-1',
                            'port': 8090,
                            'replset': 'replset-1'})])
        self.related_units.return_value = [k for k in related_units.keys()]

        def relation_get(attr, unit, relid):
            values = related_units.get(unit)
            if attr is None:
                return values
            else:
                return values.get(attr, None)
        self.relation_get.side_effect = relation_get

        self.os_release.return_value = 'icehouse'
        self.assertEqual(contexts.MongoDBContext()(),
                         {'db_mongo_servers': 'mongodb-0:8090,mongodb-1:8090',
                          'db_name': 'ceilometer', 'db_replset': 'replset-1'})

    @patch.object(utils, 'get_shared_secret')
    def test_ceilometer_context(self, secret):
        secret.return_value = 'mysecret'
        self.assertEqual(contexts.CeilometerContext()(), {
            'port': 8777,
            'metering_secret': 'mysecret',
            'metering_time_to_live': -1,
            'event_time_to_live': -1,
            'polling_interval': 300,
            'enable_all_pollsters': False,
            'polling_batch_size': 50,
        })

    @patch.object(utils, 'get_shared_secret')
    def test_ceilometer_context_ttl_values(self, secret):
        secret.return_value = 'mysecret'
        self.test_config.set('metering-time-to-live', 7.776e+06)
        self.test_config.set('event-time-to-live', 7.776e+06)
        context = contexts.CeilometerContext()()
        self.assertEqual(context, {
            'port': 8777,
            'metering_secret': 'mysecret',
            'metering_time_to_live': 7776000,
            'event_time_to_live': 7776000,
            'polling_interval': 300,
            'enable_all_pollsters': False,
            'polling_batch_size': 50,
        })
        self.assertTrue(type(context['metering_time_to_live']) is int)
        self.assertTrue(type(context['event_time_to_live']) is int)

    @patch.object(utils, 'get_shared_secret')
    def test_ceilometer_context_enable_all_pollsters(self, secret):
        secret.return_value = 'mysecret'
        self.test_config.set('enable-all-pollsters', True)
        context = contexts.CeilometerContext()()
        self.assertEqual(context, {
            'port': 8777,
            'metering_secret': 'mysecret',
            'metering_time_to_live': -1,
            'event_time_to_live': -1,
            'polling_interval': 300,
            'enable_all_pollsters': True,
            'polling_batch_size': 50,
        })

    @patch.object(utils, 'get_shared_secret')
    def test_ceilometer_context_polling_interval(self, secret):
        secret.return_value = 'mysecret'
        self.test_config.set('polling-interval', 900)
        context = contexts.CeilometerContext()()
        self.assertEqual(context, {
            'port': 8777,
            'metering_secret': 'mysecret',
            'metering_time_to_live': -1,
            'event_time_to_live': -1,
            'polling_interval': 900,
            'enable_all_pollsters': False,
            'polling_batch_size': 50,
        })

    def test_ceilometer_service_context(self):
        self.relation_ids.return_value = ['ceilometer-service:0']
        self.related_units.return_value = ['ceilometer/0']
        data = {
            'metering_secret': 'mysecret',
            'keystone_host': 'test'
        }
        self.test_relation.set(data)
        self.assertEqual(contexts.CeilometerServiceContext()(), data)

    def test_ceilometer_service_context_not_related(self):
        self.relation_ids.return_value = []
        self.assertEqual(contexts.CeilometerServiceContext()(), {})

    @patch('os.path.exists')
    def test_get_shared_secret_existing(self, exists):
        exists.return_value = True
        with mock_open(utils.SHARED_SECRET, u'mysecret'):
            self.assertEqual(utils.get_shared_secret(),
                             'mysecret')

    @patch('uuid.uuid4')
    @patch('os.path.exists')
    def test_get_shared_secret_new(self, exists, uuid4):
        exists.return_value = False
        uuid4.return_value = 'newsecret'
        with patch('builtins.open'):
            self.assertEqual(utils.get_shared_secret(),
                             'newsecret')

    @patch.object(contexts, 'determine_apache_port')
    @patch.object(contexts, 'determine_api_port')
    def test_ha_proxy_context(self, determine_api_port, determine_apache_port):
        determine_api_port.return_value = contexts.CEILOMETER_PORT - 10
        determine_apache_port.return_value = contexts.CEILOMETER_PORT - 20

        haproxy_port = contexts.CEILOMETER_PORT
        api_port = haproxy_port - 10
        apache_port = api_port - 10

        expected = {
            'service_ports': {'ceilometer_api': [haproxy_port, apache_port]},
            'port': api_port
        }
        self.assertEqual(contexts.HAProxyContext()(), expected)

    @patch.object(contexts, 'get_os_codename_package')
    def test_remote_sink_context_no_config(self, mock_get_rel):
        mock_get_rel.return_value = 'mitaka'
        self.relation_ids.return_value = []
        self.os_release.return_value = 'mitaka'
        self.assertEqual(contexts.RemoteSinksContext()(), {
            'event_sink_publisher': None})

        mock_get_rel.return_value = 'queens'
        self.assertEqual(contexts.RemoteSinksContext()(),
                         {'event_sink_publisher':
                          'notifier://?topic=alarm.all'})

    @patch.object(contexts, 'get_os_codename_package')
    def test_remote_sink_context_event_service_relation(self, mock_get_rel):
        mock_get_rel.return_value = 'mitaka'
        self.relation_ids.return_value = ['event-service:0', 'meter-service:0']
        self.related_units.return_value = ['panko/0']
        self.os_release.return_value = 'mitaka'
        data = {
            'publisher': 'panko://'
        }
        self.test_relation.set(data)
        self.assertEqual(contexts.RemoteSinksContext()(),
                         {'internal_sinks': {'panko': 'panko://'},
                          'event_sink_publisher': None})

        mock_get_rel.return_value = 'queens'
        self.assertEqual(contexts.RemoteSinksContext()(),
                         {'internal_sinks': {'panko': 'panko://'},
                          'event_sink_publisher':
                          'notifier://?topic=alarm.all'})

        self.test_config.set('events-publisher', 'gnocchi')
        self.assertEqual(contexts.RemoteSinksContext()(),
                         {'internal_sinks': {'panko': 'panko://'},
                          'event_sink_publisher':
                          'gnocchi://'})

    @patch.object(contexts, 'get_os_codename_package')
    def test_remote_sink_context_with_single_config(self, mock_get_rel):
        mock_get_rel.return_value = 'mitaka'
        self.relation_ids.return_value = ['meter-service:0']
        self.os_release.return_value = 'mitaka'
        self.test_config.set('remote-sink', 'http://foo')
        self.assertEqual(contexts.RemoteSinksContext()(),
                         {'remote_sinks': ['http://foo'],
                          'event_sink_publisher': None})

        mock_get_rel.return_value = 'queens'
        self.assertEqual(contexts.RemoteSinksContext()(),
                         {'remote_sinks': ['http://foo'],
                          'event_sink_publisher':
                          'notifier://?topic=alarm.all'})

        self.test_config.set('events-publisher', 'gnocchi')
        self.assertEqual(contexts.RemoteSinksContext()(),
                         {'remote_sinks': ['http://foo'],
                          'event_sink_publisher':
                          'gnocchi://'})

    @patch.object(contexts, 'get_os_codename_package')
    def test_remote_sink_context_with_multiple_config(self, mock_get_rel):
        mock_get_rel.return_value = 'mitaka'
        self.relation_ids.return_value = ['meter-service:0']
        self.os_release.return_value = 'mitaka'
        self.test_config.set('remote-sink', 'http://foo http://bar')
        self.assertEqual(contexts.RemoteSinksContext()(),
                         {'remote_sinks': ['http://foo', 'http://bar'],
                          'event_sink_publisher': None})

        mock_get_rel.return_value = 'queens'
        self.assertEqual(contexts.RemoteSinksContext()(),
                         {'remote_sinks': ['http://foo', 'http://bar'],
                          'event_sink_publisher':
                          'notifier://?topic=alarm.all'})

        self.test_config.set('events-publisher', 'gnocchi')
        self.assertEqual(contexts.RemoteSinksContext()(),
                         {'remote_sinks': ['http://foo', 'http://bar'],
                          'event_sink_publisher':
                          'gnocchi://'})

    @patch.object(contexts, 'AMQPContext')
    def test_AMQPListenersContext(self, mock_AMQPContext):

        def _context(ssl_dir, relation_id):
            fake_context1 = MagicMock(
                return_value={'transport_url': 'rabbit://rab1:1010/os'})
            fake_context2 = MagicMock(
                return_value={'other_setting': 'sss'})
            fake_context3 = MagicMock(
                return_value={'transport_url': 'rabbit://rab2:1010/os'})
            rdata = {
                'amqp-listener:23': fake_context1,
                'amqp-listener:8': fake_context2,
                'amqp:2': fake_context3}

            return rdata[relation_id]

        mock_AMQPContext.side_effect = _context

        rids = {
            'amqp-listener': ['amqp-listener:23', 'amqp-listener:8'],
            'amqp': ['amqp:2']}
        self.relation_ids.side_effect = lambda x: rids[x]
        self.assertEqual(
            contexts.AMQPListenersContext()(),
            {'messaging_urls': [
                'rabbit://rab1:1010/os',
                'rabbit://rab2:1010/os']})

    @patch.object(contexts, 'AMQPContext')
    def test_AMQPListenersContext_no_transport_urls(self, mock_AMQPContext):

        def _context(ssl_dir, relation_id):
            fake_context1 = MagicMock(return_value={})
            fake_context2 = MagicMock(return_value={})
            fake_context3 = MagicMock(return_value={})
            rdata = {
                'amqp-listener:23': fake_context1,
                'amqp-listener:8': fake_context2,
                'amqp:2': fake_context3}
            return rdata[relation_id]

        mock_AMQPContext.side_effect = _context

        rids = {
            'amqp-listener': ['amqp-listener:23', 'amqp-listener:8'],
            'amqp': ['amqp:2']}
        self.relation_ids.side_effect = lambda x: rids[x]
        self.assertEqual(contexts.AMQPListenersContext()(), {})
