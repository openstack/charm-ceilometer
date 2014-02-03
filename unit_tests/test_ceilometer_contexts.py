from mock import patch

import ceilometer_contexts as contexts

from test_utils import CharmTestCase, mock_open

TO_PATCH = [
    'relation_get',
    'relation_ids',
    'related_units',
    'config'
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

    @patch.object(contexts, 'get_shared_secret')
    def test_ceilometer_context(self, secret):
        secret.return_value = 'mysecret'
        self.assertEquals(contexts.CeilometerContext()(),
                          {'port': 8777, 'metering_secret': 'mysecret', 'use_syslog': False})

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
        with mock_open(contexts.SHARED_SECRET, u'mysecret'):
            self.assertEquals(contexts.get_shared_secret(),
                              'mysecret')

    @patch('uuid.uuid4')
    @patch('os.path.exists')
    def test_get_shared_secret_new(self, exists, uuid4):
        exists.return_value = False
        uuid4.return_value = 'newsecret'
        with patch('__builtin__.open'):
            self.assertEquals(contexts.get_shared_secret(),
                              'newsecret')
