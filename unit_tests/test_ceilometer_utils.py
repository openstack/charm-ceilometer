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
    'leader_set',
    'leader_get',
    'reset_os_release',
    'relation_ids',
]


class CeilometerUtilsTest(CharmTestCase):

    def setUp(self):
        super(CeilometerUtilsTest, self).setUp(utils, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.get_os_codename_install_source.return_value = 'icehouse'

    def tearDown(self):
        super(CeilometerUtilsTest, self).tearDown()

    def test_register_configs(self):
        self.os.path.exists.return_value = True
        self.init_is_systemd.return_value = False
        self.os_release.return_value = 'havana'
        self.get_os_codename_package.return_value = 'havana'
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
        self.get_os_codename_package.return_value = 'havana'
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
        self.get_os_codename_package.return_value = 'havana'
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

    def test_ceilometer_release_services_queens(self):
        """Ensure that queens specific services are identified"""
        self.get_os_codename_install_source.return_value = 'queens'
        self.assertEqual([],
                         utils.ceilometer_release_services())

    def test_restart_map(self):
        """Ensure that alarming services are present for < OpenStack Mitaka"""
        self.get_os_codename_install_source.return_value = 'icehouse'
        self.os_release.return_value = 'icehouse'
        restart_map = utils.restart_map()
        self.assertEqual(
            restart_map,
            {'/etc/ceilometer/ceilometer.conf': [
                'ceilometer-agent-central',
                'ceilometer-collector',
                'ceilometer-api',
                'ceilometer-alarm-notifier',
                'ceilometer-alarm-evaluator',
                'ceilometer-agent-notification'],
             '/etc/ceilometer/pipeline.yaml': [
                 'ceilometer-collector'],
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
        self.assertEqual(
            restart_map,
            {'/etc/ceilometer/ceilometer.conf': [
                'ceilometer-agent-central',
                'ceilometer-collector',
                'ceilometer-api',
                'ceilometer-agent-notification'],
             '/etc/ceilometer/pipeline.yaml': [
                 'ceilometer-collector'],
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

    def test_restart_map_queens(self):
        """Ensure that alarming services are missing for OpenStack Queens"""
        self.get_os_codename_install_source.return_value = 'queens'
        self.os_release.return_value = 'queens'
        self.maxDiff = None
        restart_map = utils.restart_map()
        self.assertEqual(
            restart_map,
            {'/etc/ceilometer/ceilometer.conf': [
                'ceilometer-agent-central',
                'ceilometer-agent-notification'],
             '/etc/ceilometer/polling.yaml': [
                'ceilometer-agent-central',
                'ceilometer-agent-notification'],
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

    def test_determine_purge_packages(self):
        'Ensure no packages are identified for purge prior to rocky'
        self.get_os_codename_install_source.return_value = 'queens'
        self.assertEqual(utils.determine_purge_packages(), [])

    def test_determine_purge_packages_rocky(self):
        'Ensure python packages are identified for purge at rocky'
        self.get_os_codename_install_source.return_value = 'rocky'
        self.assertEqual(utils.determine_purge_packages(),
                         [p for p in utils.CEILOMETER_BASE_PACKAGES
                          if p.startswith('python-')] +
                         ['python-ceilometer', 'python-memcache'])

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

    def test_get_packages_queens(self):
        self.get_os_codename_install_source.return_value = 'queens'
        self.token_cache_pkgs.return_value = []
        self.assertEqual(utils.get_packages(),
                         utils.QUEENS_PACKAGES)

    def test_get_packages_rocky(self):
        self.get_os_codename_install_source.return_value = 'rocky'
        self.token_cache_pkgs.return_value = []
        self.assertEqual(utils.get_packages(),
                         utils.QUEENS_PACKAGES +
                         ['python3-ceilometer'])

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

    @patch.object(utils, 'check_ceilometer_upgraded')
    @patch.object(utils, 'resolve_required_interfaces')
    @patch.object(utils, 'services')
    @patch.object(utils, 'determine_ports')
    @patch.object(utils, 'make_assess_status_func')
    def test_assess_status_func(self,
                                make_assess_status_func,
                                determine_ports,
                                services,
                                resolve_required_interfaces,
                                check_ceilometer_upgraded):
        check_ceilometer_upgraded.return_value = None, None
        services.return_value = 's1'
        determine_ports.return_value = 'p1'
        resolve_required_interfaces.return_value = {'a': ['b']}
        utils.assess_status_func('test-config')
        make_assess_status_func.assert_called_once_with(
            'test-config', {'a': ['b']}, charm_func=check_ceilometer_upgraded,
            services='s1', ports='p1')

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
        self.relation_ids.return_value = None
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
        self.relation_ids.return_value = None
        self.assertEqual(
            utils.resolve_required_interfaces(),
            {
                'database': ['mongodb', 'metric-service'],
                'messaging': ['amqp'],
                'identity': ['identity-service'],
            }
        )

    def test_resolve_required_interfaces_queens(self):
        self.os_release.side_effect = None
        self.os_release.return_value = 'queens'
        self.relation_ids.return_value = None
        self.assertEqual(
            utils.resolve_required_interfaces(),
            {
                'database': ['metric-service'],
                'messaging': ['amqp'],
                'identity': ['identity-credentials'],
            }
        )

    def test_resolve_optional_interfaces(self):
        self.os_release.side_effect = None
        self.os_release.return_value = 'icehouse'
        self.relation_ids.return_value = [0]
        self.assertEqual(
            utils.resolve_required_interfaces(),
            {
                'database': ['mongodb'],
                'messaging': ['amqp'],
                'identity': ['identity-service'],
                'event-service': ['event-service'],
            }
        )

    @patch.object(utils, 'subprocess')
    def test_ceilometer_upgrade(self, mock_subprocess):
        self.is_leader.return_value = True
        self.os_release.return_value = 'queens'
        utils.ceilometer_upgrade()
        mock_subprocess.check_call.assert_called_with(
            ['ceilometer-upgrade', '--debug', '--retry', '10'])

    @patch.object(utils, 'subprocess')
    def test_ceilometer_upgrade_ocata(self, mock_subprocess):
        self.is_leader.return_value = True
        self.os_release.return_value = 'ocata'
        utils.ceilometer_upgrade()
        mock_subprocess.check_call.assert_called_with(
            ['ceilometer-upgrade', '--debug'])

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

    @patch.object(utils, 'ceilometer_upgrade')
    @patch('charmhelpers.core.hookenv.config')
    def test_ceilometer_upgrade_helper_with_metrics(self, mock_config,
                                                    mock_ceilometer_upgrade):
        self.get_os_codename_install_source.return_value = 'ocata'
        self.CONFIGS = MagicMock()
        self.CONFIGS.complete_contexts.return_value = [
            'metric-service',
            'identity-service',
            'mongodb'
        ]
        utils.ceilometer_upgrade_helper(self.CONFIGS)
        mock_ceilometer_upgrade.assert_called_once_with(action=True)

    @patch.object(utils, 'ceilometer_upgrade')
    @patch('charmhelpers.core.hookenv.config')
    def test_ceilometer_upgrade_helper_queens(self, mock_config,
                                              mock_ceilometer_upgrade):
        self.get_os_codename_install_source.return_value = 'queens'
        self.CONFIGS = MagicMock()
        self.CONFIGS.complete_contexts.return_value = [
            'metric-service',
            'identity-credentials',
        ]
        utils.ceilometer_upgrade_helper(self.CONFIGS)
        mock_ceilometer_upgrade.assert_called_once_with(action=True)

    @patch.object(utils, 'ceilometer_upgrade')
    @patch('charmhelpers.core.hookenv.config')
    def test_ceilometer_upgrade_helper_incomplete(self, mock_config,
                                                  mock_ceilometer_upgrade):
        self.get_os_codename_install_source.return_value = 'ocata'
        self.CONFIGS = MagicMock()
        with self.assertRaises(utils.FailedAction):
            utils.ceilometer_upgrade_helper(self.CONFIGS)
        mock_ceilometer_upgrade.assert_not_called()

    @patch.object(utils, 'ceilometer_upgrade')
    @patch('charmhelpers.core.hookenv.config')
    def test_ceilometer_upgrade_helper_raise(self, mock_config,
                                             mock_ceilometer_upgrade):
        self.get_os_codename_install_source.return_value = 'ocata'
        self.CONFIGS = MagicMock()
        self.CONFIGS.complete_contexts.return_value = [
            'metric-service',
            'identity-service',
            'mongodb'
        ]
        # workaround Py3 constraint that raise only accepts an actual
        # exception, so we have to patch CalledProcessError back onto the
        # mocked out subprocess module
        import subprocess
        exc = subprocess.CalledProcessError
        mock_ceilometer_upgrade.side_effect = utils.FailedAction("message")
        with patch.object(utils, 'subprocess') as subp, \
                self.assertRaises(utils.FailedAction):
            subp.CalledProcessError = exc
            utils.ceilometer_upgrade_helper(self.CONFIGS)
        mock_ceilometer_upgrade.assert_called_once_with(action=True)

    def test_check_ceilometer_upgraded(self):
        self.CONFIGS = MagicMock()
        self.is_leader.return_value = True

        # Not related
        self.relation_ids.return_value = []
        self.assertEqual(
            (None, None),
            utils.check_ceilometer_upgraded(self.CONFIGS))

        # Related not ready
        self.relation_ids.return_value = ['metric:1']
        self.leader_get.return_value = False
        self.assertEqual(
            ("blocked", "Run the ceilometer-upgrade action on the leader "
                        "to initialize ceilometer and gnocchi"),
            utils.check_ceilometer_upgraded(self.CONFIGS))

        # Related ready
        self.leader_get.return_value = True
        self.assertEqual(
            (None, None),
            utils.check_ceilometer_upgraded(self.CONFIGS))
