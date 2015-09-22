from mock import patch

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
        self.assertEquals(contexts.LoggingConfigContext()(),
                          {'debug': False, 'verbose': False})
        self.test_config.set('debug', True)
        self.test_config.set('verbose', False)
        self.assertEquals(contexts.LoggingConfigContext()(),
                          {'debug': True, 'verbose': False})
        self.test_config.set('debug', True)
        self.test_config.set('verbose', True)
        self.assertEquals(contexts.LoggingConfigContext()(),
                          {'debug': True, 'verbose': True})

    def test_mongodb_context_not_related(self):
        self.relation_ids.return_value = []
        self.os_release.return_value = 'icehouse'
        self.assertEquals(contexts.MongoDBContext()(), {})

    def test_mongodb_context_related(self):
        self.relation_ids.return_value = ['shared-db:0']
        self.related_units.return_value = ['mongodb/0']
        data = {
            'hostname': 'mongodb',
            'port': 8090
        }
        self.test_relation.set(data)
        self.assertEquals(contexts.MongoDBContext()(),
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
        self.assertEquals(contexts.MongoDBContext()(),
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
        self.assertEquals(contexts.MongoDBContext()(), {})

    def test_mongodb_context_related_replset_multiple_mongo(self):
        self.relation_ids.return_value = ['shared-db:0']
        related_units = {
            'mongodb/0': {'hostname': 'mongodb-0',
                          'port': 8090,
                          'replset': 'replset-1'},
            'mongodb/1': {'hostname': 'mongodb-1',
                          'port': 8090,
                          'replset': 'replset-1'}
        }
        self.related_units.return_value = [k for k in related_units.keys()]

        def relation_get(attr, unit, relid):
            values = related_units.get(unit)
            if attr is None:
                return values
            else:
                return values.get(attr, None)
        self.relation_get.side_effect = relation_get

        self.os_release.return_value = 'icehouse'
        self.assertEquals(contexts.MongoDBContext()(),
                          {'db_mongo_servers': 'mongodb-0:8090,mongodb-1:8090',
                           'db_name': 'ceilometer', 'db_replset': 'replset-1'})

    @patch.object(utils, 'get_shared_secret')
    def test_ceilometer_context(self, secret):
        secret.return_value = 'mysecret'
        self.assertEquals(contexts.CeilometerContext()(), {
            'port': 8777,
            'metering_secret': 'mysecret',
            'api_workers': 1,
        })

    def test_ceilometer_service_context(self):
        self.relation_ids.return_value = ['ceilometer-service:0']
        self.related_units.return_value = ['ceilometer/0']
        data = {
            'metering_secret': 'mysecret',
            'keystone_host': 'test'
        }
        self.test_relation.set(data)
        self.assertEquals(contexts.CeilometerServiceContext()(), data)

    def test_ceilometer_service_context_not_related(self):
        self.relation_ids.return_value = []
        self.assertEquals(contexts.CeilometerServiceContext()(), {})

    @patch('os.path.exists')
    def test_get_shared_secret_existing(self, exists):
        exists.return_value = True
        with mock_open(utils.SHARED_SECRET, u'mysecret'):
            self.assertEquals(utils.get_shared_secret(),
                              'mysecret')

    @patch('uuid.uuid4')
    @patch('os.path.exists')
    def test_get_shared_secret_new(self, exists, uuid4):
        exists.return_value = False
        uuid4.return_value = 'newsecret'
        with patch('__builtin__.open'):
            self.assertEquals(utils.get_shared_secret(),
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
        self.assertEquals(contexts.HAProxyContext()(), expected)
