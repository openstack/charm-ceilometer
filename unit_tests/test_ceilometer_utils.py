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
    'os_application_version_set',
    'init_is_systemd',
    'os',
    'enable_memcache',
    'token_cache_pkgs',
    'os_release',
    'is_leader',
    'reset_os_release',
]


class CeilometerUtilsTest(CharmTestCase):

    def setUp(self):
        super(CeilometerUtilsTest, self).setUp(utils, TO_PATCH)
        self.config.side_effect = self.test_config.get

    def tearDown(self):
        super(CeilometerUtilsTest, self).tearDown()

    def test_register_configs(self):
        self.os.path.exists.return_value = True
        self.init_is_systemd.return_value = False
        self.os_release.return_value = 'havana'
        configs = utils.register_configs()
        calls = []
        for conf in (utils.CEILOMETER_CONF, utils.HAPROXY_CONF,
                     utils.HTTPS_APACHE_24_CONF):
            calls.append(call(conf,
                              utils.CONFIG_FILES[conf]['hook_contexts']))
        configs.register.assert_has_calls(calls, any_order=True)

    def test_register_configs_apache22(self):
        self.os.path.exists.return_value = False
        self.init_is_systemd.return_value = False
        self.os_release.return_value = 'havana'
        configs = utils.register_configs()
        calls = []
        for conf in (utils.CEILOMETER_CONF, utils.HAPROXY_CONF,
                     utils.HTTPS_APACHE_CONF):
            calls.append(call(conf,
                              utils.CONFIG_FILES[conf]['hook_contexts']))
        configs.register.assert_has_calls(calls, any_order=True)

    def test_register_configs_systemd(self):
        self.os.path.exists.return_value = True
        self.init_is_systemd.return_value = True
        self.os_release.return_value = 'havana'
        configs = utils.register_configs()
        calls = []
        for conf in (utils.CEILOMETER_CONF, utils.HAPROXY_CONF,
                     utils.HTTPS_APACHE_24_CONF):
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
        self.os_release.return_value = 'icehouse'
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
             '/etc/systemd/system/ceilometer-api.service.d/override.conf': [
                'ceilometer-api'],
             '/etc/haproxy/haproxy.cfg': ['haproxy'],
             '/etc/memcached.conf': ['memcached'],
             "/etc/apache2/sites-available/openstack_https_frontend": [
                 'ceilometer-api', 'apache2'],
             "/etc/apache2/sites-available/openstack_https_frontend.conf": [
                 'ceilometer-api', 'apache2']
             }
        )

    def test_restart_map_mitaka(self):
        """Ensure that alarming services are missing for OpenStack Mitaka"""
        self.get_os_codename_install_source.return_value = 'mitaka'
        self.os_release.return_value = 'mitaka'
        self.maxDiff = None
        restart_map = utils.restart_map()
        self.assertEquals(
            restart_map,
            {'/etc/ceilometer/ceilometer.conf': [
                'ceilometer-agent-central',
                'ceilometer-collector',
                'ceilometer-api',
                'ceilometer-agent-notification'],
             '/etc/systemd/system/ceilometer-api.service.d/override.conf': [
                'ceilometer-api'],
             '/etc/haproxy/haproxy.cfg': ['haproxy'],
             '/etc/memcached.conf': ['memcached'],
             "/etc/apache2/sites-available/openstack_https_frontend": [
                 'ceilometer-api', 'apache2'],
             "/etc/apache2/sites-available/openstack_https_frontend.conf": [
                 'ceilometer-api', 'apache2']
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
        self.os_release.return_value = 'kilo'
        self.enable_memcache.return_value = False
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
        self.reset_os_release.assert_called()

    def test_get_packages_icehouse(self):
        self.get_os_codename_install_source.return_value = 'icehouse'
        self.token_cache_pkgs.return_value = []
        self.assertEqual(utils.get_packages(),
                         utils.CEILOMETER_BASE_PACKAGES +
                         utils.ICEHOUSE_PACKAGES)

    def test_get_packages_mitaka(self):
        self.get_os_codename_install_source.return_value = 'mitaka'
        self.token_cache_pkgs.return_value = ['memcached']
        self.assertEqual(utils.get_packages(),
                         utils.CEILOMETER_BASE_PACKAGES +
                         utils.MITAKA_PACKAGES +
                         ['memcached'])

    def test_assess_status(self):
        with patch.object(utils, 'assess_status_func') as asf:
            callee = MagicMock()
            asf.return_value = callee
            utils.assess_status('test-config')
            asf.assert_called_once_with('test-config')
            callee.assert_called_once_with()
            self.os_application_version_set.assert_called_with(
                utils.VERSION_PACKAGE
            )

    @patch.object(utils, 'resolve_required_interfaces')
    @patch.object(utils, 'services')
    @patch.object(utils, 'determine_ports')
    @patch.object(utils, 'make_assess_status_func')
    def test_assess_status_func(self,
                                make_assess_status_func,
                                determine_ports,
                                services,
                                resolve_required_interfaces):
        services.return_value = 's1'
        determine_ports.return_value = 'p1'
        resolve_required_interfaces.return_value = {'a': ['b']}
        utils.assess_status_func('test-config')
        make_assess_status_func.assert_called_once_with(
            'test-config', {'a': ['b']}, services='s1', ports='p1')

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

    def test_resolve_required_interfaces(self):
        self.os_release.side_effect = None
        self.os_release.return_value = 'icehouse'
        self.assertEqual(
            utils.resolve_required_interfaces(),
            {
                'database': ['mongodb'],
                'messaging': ['amqp'],
                'identity': ['identity-service'],
            }
        )

    def test_resolve_required_interfaces_mitaka(self):
        self.os_release.side_effect = None
        self.os_release.return_value = 'mitaka'
        self.assertEqual(
            utils.resolve_required_interfaces(),
            {
                'database': ['mongodb', 'metric-service'],
                'messaging': ['amqp'],
                'identity': ['identity-service'],
            }
        )

    @patch.object(utils, 'subprocess')
    def test_ceilometer_upgrade(self, mock_subprocess):
        self.is_leader.return_value = True
        self.os_release.return_value = 'ocata'
        utils.ceilometer_upgrade()
        mock_subprocess.check_call.assert_called_with(['ceilometer-upgrade'])

    @patch.object(utils, 'subprocess')
    def test_ceilometer_upgrade_mitaka(self, mock_subprocess):
        self.is_leader.return_value = True
        self.os_release.return_value = 'mitaka'
        utils.ceilometer_upgrade()
        mock_subprocess.check_call.assert_called_with(['ceilometer-dbsync'])

    @patch.object(utils, 'subprocess')
    def test_ceilometer_upgrade_follower(self, mock_subprocess):
        self.is_leader.return_value = False
        utils.ceilometer_upgrade()
        mock_subprocess.check_call.assert_not_called()
