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

import copy
import os
import sys

from unittest.mock import patch, MagicMock, call, mock_open

# python-apt is not installed as part of test-requirements but is imported by
# some charmhelpers modules so create a fake import.
mock_apt = MagicMock()
sys.modules['apt'] = mock_apt
mock_apt.apt_pkg = MagicMock()


import ceilometer_utils
# Patch out register_configs for import of hooks
_register_configs = ceilometer_utils.register_configs
ceilometer_utils.register_configs = MagicMock()

with patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    import ceilometer_hooks as hooks

# Renable old function
ceilometer_utils.register_configs = _register_configs

from test_utils import CharmTestCase

TO_PATCH = [
    'relation_get',
    'relation_set',
    'configure_installation_source',
    'openstack_upgrade_available',
    'do_openstack_upgrade',
    'apt_install',
    'apt_update',
    'open_port',
    'close_port',
    'config',
    'log',
    'relation_ids',
    'filter_installed_packages',
    'CONFIGS',
    'get_ceilometer_context',
    'lsb_release',
    'get_packages',
    'service_restart',
    'update_nrpe_config',
    'peer_retrieve',
    'peer_store',
    'configure_https',
    'status_set',
    'generate_ha_relation_data',
    'reload_systemd',
    'run_in_apache',
    'mkdir',
    'init_is_systemd',
    'get_relation_ip',
    'is_clustered',
    'get_os_codename_install_source',
    'services',
    'remove_old_packages',
    'is_leader',
    'leader_get',
    'leader_set',
]


CEIL_HA_SETTINGS = {
    'resources': {
        'res_ceilometer_agent_central': 'lsb:ceilometer-agent-central'},
    'resource_params': {
        'res_ceilometer_agent_central': 'op monitor interval="30s"'},
    'delete_resources': ['res_ceilometer_polling'],
}


class CeilometerHooksTest(CharmTestCase):

    def setUp(self):
        super(CeilometerHooksTest, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.get_packages.return_value = \
            ceilometer_utils.CEILOMETER_BASE_PACKAGES
        self.filter_installed_packages.return_value = \
            ceilometer_utils.CEILOMETER_BASE_PACKAGES
        self.lsb_release.return_value = {'DISTRIB_CODENAME': 'precise'}
        self.get_os_codename_install_source.return_value = 'mitaka'

    @patch('charmhelpers.payload.execd.default_execd_dir',
           return_value=os.path.join(os.getcwd(), 'exec.d'))
    @patch('charmhelpers.core.hookenv.config')
    def test_configure_source(self, mock_config, mock_execd_dir):
        self.test_config.set('openstack-origin', 'cloud:precise-havana')
        hooks.hooks.execute(['hooks/install.real'])
        self.configure_installation_source.\
            assert_called_with('cloud:precise-havana')

    @patch('charmhelpers.core.hookenv.config')
    def test_amqp_joined(self, mock_config):
        hooks.hooks.execute(['hooks/amqp-relation-joined'])
        self.relation_set.assert_called_with(
            username=self.test_config.get('rabbit-user'),
            vhost=self.test_config.get('rabbit-vhost'))

    @patch('charmhelpers.core.hookenv.config')
    def test_db_joined(self, mock_config):
        hooks.hooks.execute(['hooks/shared-db-relation-joined'])
        self.relation_set.assert_called_with(
            ceilometer_database='ceilometer')

    @patch.object(hooks, 'certs_changed')
    @patch.object(hooks, 'related_units')
    @patch.object(hooks, 'keystone_joined')
    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'ceilometer_joined')
    def test_any_changed(self, ceilometer_joined, mock_config,
                         keystone_joined, _related_units, _certs_changed):
        self.relation_ids.side_effect = [
            ['certificates:42'], ['identity-service:1']]
        _related_units.return_value = ['vault/0']
        hooks.hooks.execute(['hooks/shared-db-relation-changed'])
        self.assertTrue(self.CONFIGS.write_all.called)
        self.assertTrue(ceilometer_joined.called)
        _certs_changed.assert_called_once_with('certificates:42', 'vault/0')
        keystone_joined.assert_called_with(relid='identity-service:1')
        self.configure_https.assert_called_once()

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'install')
    @patch.object(hooks, 'any_changed')
    def test_upgrade_charm(self, changed, install, mock_config):
        self.remove_old_packages.return_value = False
        hooks.hooks.execute(['hooks/upgrade-charm'])
        self.assertTrue(changed.called)
        self.assertTrue(install.called)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'install')
    @patch.object(hooks, 'any_changed')
    def test_upgrade_charm_purge(self, changed, install, mock_config):
        self.remove_old_packages.return_value = True
        self.services.return_value = ['ceilometer-important-service']
        hooks.hooks.execute(['hooks/upgrade-charm'])
        self.assertTrue(changed.called)
        self.assertTrue(install.called)
        self.service_restart.assert_called_once_with(
            'ceilometer-important-service')

    @patch.object(hooks, 'any_changed')
    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'cluster_joined')
    def test_upgrade_charm_with_cluster(self, cluster_joined, mock_config,
                                        any_changed):
        self.relation_ids.return_value = ['ceilometer/0',
                                          'ceilometer/1',
                                          'ceilometer/2']
        hooks.hooks.execute(['hooks/upgrade-charm'])
        self.assertEqual(cluster_joined.call_count, 3)
        any_changed.assert_called_once()

    @patch.object(hooks, 'any_changed')
    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'cluster_joined')
    def test_upgrade_charm_set_ceilometer_upgraded(
            self, cluster_joined, mock_config, any_changed):
        self.is_leader.return_value = True
        self.leader_get.return_value = False
        self.relation_ids.return_value = ['metric-service:1']
        hooks.hooks.execute(['hooks/upgrade-charm'])
        self.leader_set.assert_called_once_with(ceilometer_upgrade_run=True)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'ceilometer_joined')
    def test_config_changed_no_upgrade(self,
                                       joined, mock_config):
        self.openstack_upgrade_available.return_value = False
        hooks.hooks.execute(['hooks/config-changed'])
        self.openstack_upgrade_available.\
            assert_called_with('ceilometer-common')
        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertTrue(self.CONFIGS.write_all.called)
        self.assertTrue(joined.called)
        self.assertTrue(self.reload_systemd.called)
        self.open_port.assert_called_with(hooks.CEILOMETER_PORT)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'ceilometer_joined')
    def test_config_changed_queens(self,
                                   joined, mock_config):
        self.openstack_upgrade_available.return_value = False
        self.get_os_codename_install_source.return_value = 'queens'
        hooks.hooks.execute(['hooks/config-changed'])
        self.openstack_upgrade_available.\
            assert_called_with('ceilometer-common')
        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertTrue(self.CONFIGS.write_all.called)
        self.assertTrue(joined.called)
        self.assertTrue(self.reload_systemd.called)
        self.close_port.assert_called_with(hooks.CEILOMETER_PORT)
        self.open_port.assert_not_called()

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'ceilometer_joined')
    def test_config_changed_upgrade(self,
                                    joined, mock_config):
        self.openstack_upgrade_available.return_value = True
        hooks.hooks.execute(['hooks/config-changed'])
        self.openstack_upgrade_available.\
            assert_called_with('ceilometer-common')
        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(self.CONFIGS.write_all.called)
        self.assertTrue(joined.called)
        self.assertTrue(self.reload_systemd.called)
        self.open_port.assert_called_with(hooks.CEILOMETER_PORT)

    def test_config_changed_with_openstack_upgrade_action(self):
        self.openstack_upgrade_available.return_value = True
        self.test_config.set('action-managed-upgrade', True)

        hooks.hooks.execute(['hooks/config-changed'])

        self.assertFalse(self.do_openstack_upgrade.called)
        self.open_port.assert_called_with(hooks.CEILOMETER_PORT)

    def test_keystone_credentials_joined(self):
        hooks.hooks.execute(['hooks/identity-credentials-relation-joined'])
        self.relation_set.assert_called_with(
            username=hooks.CEILOMETER_SERVICE,
            requested_roles=hooks.CEILOMETER_ROLE,
            relation_id=None)

    @patch.object(hooks, 'canonical_url')
    @patch('charmhelpers.core.hookenv.config')
    def test_keystone_joined(self, mock_config, _canonical_url):
        _canonical_url.return_value = "http://thishost"
        self.test_config.set('region', 'myregion')
        hooks.hooks.execute(['hooks/identity-service-relation-joined'])
        url = "http://{}:{}".format('thishost', hooks.CEILOMETER_PORT)
        self.relation_set.assert_called_with(
            service=hooks.CEILOMETER_SERVICE,
            public_url=url, admin_url=url, internal_url=url,
            requested_roles=hooks.CEILOMETER_ROLE,
            region='myregion', relation_id=None)

    @patch('charmhelpers.contrib.openstack.ip.service_name',
           lambda *args: 'ceilometer')
    @patch('charmhelpers.contrib.openstack.ip.unit_get')
    @patch('charmhelpers.contrib.openstack.ip.is_clustered')
    @patch('charmhelpers.core.hookenv.config')
    @patch('charmhelpers.contrib.openstack.ip.config')
    def test_keystone_joined_url_override(self, _config, mock_config,
                                          _is_clustered, _unit_get):
        _unit_get.return_value = "thishost"
        _is_clustered.return_value = False
        _config.side_effect = self.test_config.get
        mock_config.side_effect = self.test_config.get
        self.test_config.set('region', 'myregion')
        self.test_config.set('os-public-hostname', 'ceilometer.example.com')
        hooks.keystone_joined(None)
        url = "http://{}:{}".format('thishost', hooks.CEILOMETER_PORT)
        public_url = "http://{}:{}".format('ceilometer.example.com',
                                           hooks.CEILOMETER_PORT)
        self.relation_set.assert_called_with(
            service=hooks.CEILOMETER_SERVICE,
            public_url=public_url, admin_url=url, internal_url=url,
            requested_roles=hooks.CEILOMETER_ROLE,
            region='myregion', relation_id=None)

    def test_keystone_joined_partial_cluster(self):
        self.is_clustered.return_value = False
        self.test_config.set('vip', '10.0.0.10')
        hooks.keystone_joined()
        self.assertFalse(self.relation_set.called)

    @patch('charmhelpers.core.hookenv.config')
    def test_ceilometer_joined(self, mock_config):
        self.relation_ids.return_value = ['ceilometer:0']
        self.get_ceilometer_context.return_value = {
            'test': 'data',
            'rabbit_ssl_ca': '/etc/certs/rabbit.pem'}
        with patch.object(
                hooks,
                'open',
                mock_open(read_data=b'dGVzdCBjZXJ0Cg==')):
            hooks.hooks.execute(['hooks/ceilometer-service-relation-joined'])
        self.relation_set.assert_called_with(
            'ceilometer:0',
            {'test': 'data', 'rabbit_ssl_ca': 'ZEdWemRDQmpaWEowQ2c9PQ=='})

    @patch('charmhelpers.core.hookenv.config')
    def test_identity_notifications_changed(self, mock_config):
        self.services.return_value = ['svc1', 'svc2']
        self.relation_ids.return_value = ['keystone-notifications:0']

        self.relation_get.return_value = None
        hooks.hooks.execute(['hooks/identity-notifications-relation-changed'])

        self.relation_get.return_value = {('%s-endpoint-changed' %
                                          (hooks.CEILOMETER_SERVICE)): 1}

        hooks.hooks.execute(['hooks/identity-notifications-relation-changed'])
        call1 = call('svc1')
        call2 = call('svc2')
        self.service_restart.assert_has_calls([call1, call2], any_order=False)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'is_elected_leader')
    def test_cluster_joined_not_leader(self, mock_leader,
                                       mock_config):
        mock_leader.return_value = False

        hooks.hooks.execute(['hooks/cluster-relation-joined'])
        self.assertTrue(self.relation_set.called)
        self.assertTrue(self.CONFIGS.write_all.called)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'get_shared_secret')
    @patch.object(hooks, 'is_elected_leader')
    def test_cluster_joined_is_leader(self, mock_leader,
                                      shared_secret, mock_config):
        mock_leader.return_value = True
        shared_secret.return_value = 'secret'

        hooks.hooks.execute(['hooks/cluster-relation-joined'])
        self.assertTrue(self.peer_store.called)
        self.peer_store.assert_called_with('shared_secret', 'secret')
        self.assertTrue(self.CONFIGS.write_all.called)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'is_elected_leader')
    def test_cluster_joined(self, mock_leader, mock_config):
        mock_leader.return_value = False
        self.get_relation_ip.side_effect = [
            '10.0.0.100', '10.0.1.100', '10.0.2.100', '10.0.3.100']
        rel_settings = {'private-address': '10.0.3.100',
                        'public-address': '10.0.2.100',
                        'internal-address': '10.0.1.100',
                        'admin-address': '10.0.0.100'}
        hooks.hooks.execute(['hooks/cluster-relation-joined'])
        self.relation_set.assert_called_with(relation_id=None,
                                             relation_settings=rel_settings)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'set_shared_secret')
    def test_cluster_changed(self, shared_secret, mock_config):
        self.peer_retrieve.return_value = None
        hooks.hooks.execute(['hooks/cluster-relation-changed'])
        self.assertFalse(shared_secret.called)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'get_shared_secret')
    @patch.object(hooks, 'set_shared_secret')
    def test_cluster_changed_new_secret(self, mock_set_secret, mock_get_secret,
                                        mock_config):
        self.peer_retrieve.return_value = "leader_secret"
        mock_get_secret.return_value = "my_secret"
        hooks.hooks.execute(['hooks/cluster-relation-changed'])
        mock_set_secret.assert_called_with("leader_secret")

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'get_shared_secret')
    @patch.object(hooks, 'set_shared_secret')
    def test_cluster_changed_old_secret(self, mock_set_secret, mock_get_secret,
                                        mock_config):
        self.peer_retrieve.return_value = "leader_secret"
        mock_get_secret.return_value = "leader_secret"
        hooks.hooks.execute(['hooks/cluster-relation-changed'])
        self.assertEqual(mock_set_secret.call_count, 0)

    def test_ha_relation_joined(self):
        self.generate_ha_relation_data.return_value = {'rel_data': 'data'}
        hooks.hooks.execute(['hooks/ha-relation-joined'])
        self.generate_ha_relation_data.assert_has_calls([
            call(
                'ceilometer',
                haproxy_enabled=True,
                extra_settings=CEIL_HA_SETTINGS)
        ])
        self.relation_set.assert_called_once_with(
            relation_id=None, rel_data='data')

    def test_ha_relation_joiend_queens(self):
        self.get_os_codename_install_source.return_value = 'queens'
        self.generate_ha_relation_data.return_value = {'rel_data': 'data'}
        hooks.hooks.execute(['hooks/ha-relation-joined'])
        ceil_ha_settings = copy.deepcopy(CEIL_HA_SETTINGS)
        ceil_ha_settings['delete_resources'].append('res_ceilometer_haproxy')
        self.generate_ha_relation_data.assert_has_calls([
            call(
                'ceilometer',
                haproxy_enabled=False,
                extra_settings=ceil_ha_settings)
        ])
        self.relation_set.assert_called_once_with(
            relation_id=None, rel_data='data')

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'keystone_joined')
    def test_ha_changed_not_clustered(self, mock_keystone_joined, mock_config):
        self.relation_get.return_value = None
        hooks.hooks.execute(['hooks/ha-relation-changed'])
        self.assertEqual(mock_keystone_joined.call_count, 0)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'keystone_joined')
    def test_ha_changed_clustered(self, mock_keystone_joined, mock_config):
        self.relation_get.return_value = 'yes'
        self.relation_ids.return_value = ['identity-service/0']
        hooks.hooks.execute(['hooks/ha-relation-changed'])
        self.assertEqual(mock_keystone_joined.call_count, 1)

    def test_metric_service_joined_queens(self):
        self.filter_installed_packages.return_value = ['python-gnocchiclient']
        self.get_os_codename_install_source.return_value = 'queens'
        hooks.hooks.execute(['hooks/metric-service-relation-joined'])
        self.filter_installed_packages.assert_called_with(
            ['python-gnocchiclient']
        )
        self.apt_install.assert_called_with(['python-gnocchiclient'],
                                            fatal=True)

    def test_metric_service_joined_rocky(self):
        self.filter_installed_packages.return_value = ['python3-gnocchiclient']
        self.get_os_codename_install_source.return_value = 'rocky'
        hooks.hooks.execute(['hooks/metric-service-relation-joined'])
        self.filter_installed_packages.assert_called_with(
            ['python3-gnocchiclient']
        )
        self.apt_install.assert_called_with(['python3-gnocchiclient'],
                                            fatal=True)

    @patch.object(hooks.cert_utils, 'get_certificate_request')
    @patch.object(hooks, 'relation_set')
    def test_certs_joined(self, _relation_set, _get_certificate_request):
        hooks.hooks.execute(['hooks/certificates-relation-joined'])
        _get_certificate_request.assert_called_once_with()
        _relation_set.assert_called_once_with(
            relation_id=None,
            relation_settings=_get_certificate_request())

    @patch.object(hooks, 'configure_https')
    @patch.object(hooks.cert_utils, 'process_certificates')
    def test_certs_changed(self, _process_certificates, _configure_https):
        hooks.hooks.execute(['hooks/certificates-relation-changed'])
        _process_certificates.assert_called_once_with(
            'ceilometer', None, None)
        _configure_https.assert_called_once_with()
