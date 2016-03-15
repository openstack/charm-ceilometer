from mock import patch, call, MagicMock

import ceilometer_utils as utils

from test_utils import CharmTestCase

TO_PATCH = [
    'get_os_codename_package',
    'get_os_codename_install_source',
    'configure_installation_source',
    'templating',
    'LoggingConfigContext',
    'MongoDBContext',
    'CeilometerContext',
    'config',
    'log',
    'apt_install',
    'apt_update',
    'apt_upgrade',
]


class CeilometerUtilsTest(CharmTestCase):

    def setUp(self):
        super(CeilometerUtilsTest, self).setUp(utils, TO_PATCH)
        self.config.side_effect = self.test_config.get

    def tearDown(self):
        super(CeilometerUtilsTest, self).tearDown()

    def test_register_configs(self):
        configs = utils.register_configs()
        calls = []
        for conf in utils.CONFIG_FILES:
            calls.append(call(conf,
                              utils.CONFIG_FILES[conf]['hook_contexts']))
        configs.register.assert_has_calls(calls, any_order=True)

    def test_ceilometer_release_services(self):
        """Ensure that icehouse specific services are identified"""
        self.get_os_codename_install_source.return_value = 'icehouse'
        self.assertEqual(['ceilometer-alarm-notifier',
                          'ceilometer-alarm-evaluator',
                          'ceilometer-agent-notification'],
                         utils.ceilometer_release_services())

    def test_ceilometer_release_services_mitaka(self):
        """Ensure that mitaka specific services are identified"""
        self.get_os_codename_install_source.return_value = 'mitaka'
        self.assertEqual(['ceilometer-agent-notification'],
                         utils.ceilometer_release_services())

    def test_restart_map(self):
        """Ensure that alarming services are present for < OpenStack Mitaka"""
        self.get_os_codename_install_source.return_value = 'icehouse'
        restart_map = utils.restart_map()
        self.assertEquals(
            restart_map,
            {'/etc/ceilometer/ceilometer.conf': [
                'ceilometer-agent-central',
                'ceilometer-collector',
                'ceilometer-api',
                'ceilometer-alarm-notifier',
                'ceilometer-alarm-evaluator',
                'ceilometer-agent-notification'],
             '/etc/haproxy/haproxy.cfg': ['haproxy'],
             "/etc/apache2/sites-available/openstack_https_frontend": [
                 'apache2'],
             "/etc/apache2/sites-available/openstack_https_frontend.conf": [
                 'apache2']
             }
        )

    def test_restart_map_mitaka(self):
        """Ensure that alarming services are missing for OpenStack Mitaka"""
        self.get_os_codename_install_source.return_value = 'mitaka'
        restart_map = utils.restart_map()
        self.assertEquals(
            restart_map,
            {'/etc/ceilometer/ceilometer.conf': [
                'ceilometer-agent-central',
                'ceilometer-collector',
                'ceilometer-api',
                'ceilometer-agent-notification'],
             '/etc/haproxy/haproxy.cfg': ['haproxy'],
             "/etc/apache2/sites-available/openstack_https_frontend": [
                 'apache2'],
             "/etc/apache2/sites-available/openstack_https_frontend.conf": [
                 'apache2']
             }
        )

    def test_get_ceilometer_conf(self):
        class TestContext():

            def __call__(self):
                return {'data': 'test'}
        with patch.dict(utils.CONFIG_FILES,
                        {'/etc/ceilometer/ceilometer.conf': {
                            'hook_contexts': [TestContext()]
                        }}):
            self.assertTrue(utils.get_ceilometer_context(),
                            {'data': 'test'})

    def test_do_openstack_upgrade(self):
        self.config.side_effect = self.test_config.get
        self.test_config.set('openstack-origin', 'cloud:trusty-kilo')
        self.get_os_codename_install_source.return_value = 'kilo'
        configs = MagicMock()
        utils.do_openstack_upgrade(configs)
        configs.set_release.assert_called_with(openstack_release='kilo')
        self.assertTrue(self.log.called)
        self.apt_update.assert_called_with(fatal=True)
        dpkg_opts = [
            '--option', 'Dpkg::Options::=--force-confnew',
            '--option', 'Dpkg::Options::=--force-confdef',
        ]
        self.apt_install.assert_called_with(
            packages=utils.CEILOMETER_BASE_PACKAGES + utils.ICEHOUSE_PACKAGES,
            options=dpkg_opts, fatal=True
        )
        self.configure_installation_source.assert_called_with(
            'cloud:trusty-kilo'
        )

    def test_get_packages_icehouse(self):
        self.get_os_codename_install_source.return_value = 'icehouse'
        self.assertEqual(utils.get_packages(),
                         utils.CEILOMETER_BASE_PACKAGES +
                         utils.ICEHOUSE_PACKAGES)

    def test_get_packages_mitaka(self):
        self.get_os_codename_install_source.return_value = 'mitaka'
        self.assertEqual(utils.get_packages(),
                         utils.CEILOMETER_BASE_PACKAGES +
                         utils.MITAKA_PACKAGES)

    def test_assess_status(self):
        with patch.object(utils, 'assess_status_func') as asf:
            callee = MagicMock()
            asf.return_value = callee
            utils.assess_status('test-config')
            asf.assert_called_once_with('test-config')
            callee.assert_called_once_with()

    @patch.object(utils, 'REQUIRED_INTERFACES')
    @patch.object(utils, 'services')
    @patch.object(utils, 'determine_ports')
    @patch.object(utils, 'make_assess_status_func')
    def test_assess_status_func(self,
                                make_assess_status_func,
                                determine_ports,
                                services,
                                REQUIRED_INTERFACES):
        services.return_value = 's1'
        determine_ports.return_value = 'p1'
        utils.assess_status_func('test-config')
        make_assess_status_func.assert_called_once_with(
            'test-config', REQUIRED_INTERFACES, services='s1', ports='p1')

    def test_pause_unit_helper(self):
        with patch.object(utils, '_pause_resume_helper') as prh:
            utils.pause_unit_helper('random-config')
            prh.assert_called_once_with(utils.pause_unit, 'random-config')
        with patch.object(utils, '_pause_resume_helper') as prh:
            utils.resume_unit_helper('random-config')
            prh.assert_called_once_with(utils.resume_unit, 'random-config')

    @patch.object(utils, 'services')
    @patch.object(utils, 'determine_ports')
    def test_pause_resume_helper(self, determine_ports, services):
        f = MagicMock()
        services.return_value = 's1'
        determine_ports.return_value = 'p1'
        with patch.object(utils, 'assess_status_func') as asf:
            asf.return_value = 'assessor'
            utils._pause_resume_helper(f, 'some-config')
            asf.assert_called_once_with('some-config')
            f.assert_called_once_with('assessor', services='s1', ports='p1')
