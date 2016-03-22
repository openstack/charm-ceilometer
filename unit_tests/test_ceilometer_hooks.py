import os
import sys

from mock import patch, MagicMock, call

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
]


class CeilometerHooksTest(CharmTestCase):

    def setUp(self):
        super(CeilometerHooksTest, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.get_packages.return_value = \
            ceilometer_utils.CEILOMETER_BASE_PACKAGES
        self.filter_installed_packages.return_value = \
            ceilometer_utils.CEILOMETER_BASE_PACKAGES
        self.lsb_release.return_value = {'DISTRIB_CODENAME': 'precise'}

    @patch('charmhelpers.payload.execd.default_execd_dir',
           return_value=os.path.join(os.getcwd(), 'exec.d'))
    @patch('charmhelpers.core.hookenv.config')
    def test_configure_source(self, mock_config, mock_execd_dir):
        self.test_config.set('openstack-origin', 'cloud:precise-havana')
        hooks.hooks.execute(['hooks/install.real'])
        self.configure_installation_source.\
            assert_called_with('cloud:precise-havana')

    @patch('charmhelpers.payload.execd.default_execd_dir',
           return_value=os.path.join(os.getcwd(), 'exec.d'))
    @patch('charmhelpers.core.hookenv.config')
    def test_install_hook_precise(self, mock_config, mock_execd_dir):
        hooks.hooks.execute(['hooks/install.real'])
        self.configure_installation_source.\
            assert_called_with('cloud:precise-grizzly')
        self.open_port.assert_called_with(hooks.CEILOMETER_PORT)
        self.apt_update.assert_called_with(fatal=True)
        self.apt_install.assert_called_with(
            ceilometer_utils.CEILOMETER_BASE_PACKAGES,
            fatal=True
        )

    @patch('charmhelpers.payload.execd.default_execd_dir',
           return_value=os.path.join(os.getcwd(), 'exec.d'))
    @patch('charmhelpers.core.hookenv.config')
    def test_install_hook_distro(self, mock_config, mock_execd_dir):
        self.lsb_release.return_value = {'DISTRIB_CODENAME': 'saucy'}
        hooks.hooks.execute(['hooks/install.real'])
        self.configure_installation_source.\
            assert_called_with('distro')
        self.open_port.assert_called_with(hooks.CEILOMETER_PORT)
        self.apt_update.assert_called_with(fatal=True)
        self.apt_install.assert_called_with(
            ceilometer_utils.CEILOMETER_BASE_PACKAGES,
            fatal=True
        )

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

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'ceilometer_joined')
    def test_any_changed(self, joined, mock_config):
        hooks.hooks.execute(['hooks/shared-db-relation-changed'])
        self.assertTrue(self.CONFIGS.write_all.called)
        self.assertTrue(joined.called)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'install')
    @patch.object(hooks, 'any_changed')
    def test_upgrade_charm(self, changed, install, mock_config):
        hooks.hooks.execute(['hooks/upgrade-charm'])
        self.assertTrue(changed.called)
        self.assertTrue(install.called)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'ceilometer_joined')
    def test_config_changed_no_upgrade(self, joined, mock_config):
        self.openstack_upgrade_available.return_value = False
        hooks.hooks.execute(['hooks/config-changed'])
        self.openstack_upgrade_available.\
            assert_called_with('ceilometer-common')
        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertTrue(self.CONFIGS.write_all.called)
        self.assertTrue(joined.called)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'ceilometer_joined')
    def test_config_changed_upgrade(self, joined, mock_config):
        self.openstack_upgrade_available.return_value = True
        hooks.hooks.execute(['hooks/config-changed'])
        self.openstack_upgrade_available.\
            assert_called_with('ceilometer-common')
        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(self.CONFIGS.write_all.called)
        self.assertTrue(joined.called)

    def test_config_changed_with_openstack_upgrade_action(self):
        self.openstack_upgrade_available.return_value = True
        self.test_config.set('action-managed-upgrade', True)

        hooks.hooks.execute(['hooks/config-changed'])

        self.assertFalse(self.do_openstack_upgrade.called)

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

    @patch('charmhelpers.core.hookenv.config')
    def test_ceilometer_joined(self, mock_config):
        self.relation_ids.return_value = ['ceilometer:0']
        self.get_ceilometer_context.return_value = {'test': 'data'}
        hooks.hooks.execute(['hooks/ceilometer-service-relation-joined'])
        self.relation_set.assert_called_with('ceilometer:0',
                                             {'test': 'data'})

    @patch('charmhelpers.core.hookenv.config')
    def test_identity_notifications_changed(self, mock_config):
        self.relation_ids.return_value = ['keystone-notifications:0']

        self.relation_get.return_value = None
        hooks.hooks.execute(['hooks/identity-notifications-relation-changed'])

        self.relation_get.return_value = {('%s-endpoint-changed' %
                                          (hooks.CEILOMETER_SERVICE)): 1}

        hooks.hooks.execute(['hooks/identity-notifications-relation-changed'])
        call1 = call('ceilometer-alarm-evaluator')
        call2 = call('ceilometer-alarm-notifier')
        self.service_restart.assert_has_calls([call1, call2], any_order=False)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'install_ceilometer_ocf')
    @patch.object(hooks, 'is_elected_leader')
    def test_cluster_joined_not_leader(self, mock_leader, mock_install_ocf,
                                       mock_config):
        mock_leader.return_value = False

        hooks.hooks.execute(['hooks/cluster-relation-joined'])
        self.assertFalse(self.relation_set.called)
        self.assertTrue(self.CONFIGS.write_all.called)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'get_shared_secret')
    @patch.object(hooks, 'install_ceilometer_ocf')
    @patch.object(hooks, 'is_elected_leader')
    def test_cluster_joined_is_leader(self, mock_leader, mock_install_ocf,
                                      shared_secret, mock_config):
        mock_leader.return_value = True
        shared_secret.return_value = 'secret'

        hooks.hooks.execute(['hooks/cluster-relation-joined'])
        self.assertTrue(self.peer_store.called)
        self.peer_store.assert_called_with('shared_secret', 'secret')
        self.assertTrue(self.CONFIGS.write_all.called)

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
        self.assertEquals(mock_set_secret.call_count, 0)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'get_hacluster_config')
    @patch.object(hooks, 'get_iface_for_address')
    @patch.object(hooks, 'get_netmask_for_address')
    def test_ha_joined(self, mock_netmask, mock_iface, mock_cluster_config,
                       mock_config):
        mock_cluster_config.return_value = {'vip': '10.0.5.100',
                                            'ha-bindiface': 'bnd0',
                                            'ha-mcastport': 5802}
        mock_iface.return_value = 'eth0'
        mock_netmask.return_value = '255.255.255.10'
        hooks.hooks.execute(['hooks/ha-relation-joined'])
        self.assertEquals(self.relation_set.call_count, 2)

        exp_resources = {
            'res_ceilometer_haproxy': 'lsb:haproxy',
            'res_ceilometer_agent_central': ('ocf:openstack:'
                                             'ceilometer-agent-central'),
            'res_ceilometer_eth0_vip': 'ocf:heartbeat:IPaddr2'
        }
        exp_resource_params = {
            'res_ceilometer_haproxy': 'op monitor interval="5s"',
            'res_ceilometer_agent_central': 'op monitor interval="30s"',
            'res_ceilometer_eth0_vip': ('params ip="10.0.5.100" '
                                        'cidr_netmask="255.255.255.10" '
                                        'nic="eth0"')
        }
        exp_clones = {'cl_ceilometer_haproxy': 'res_ceilometer_haproxy'}
        call1 = call(groups={'grp_ceilometer_vips': 'res_ceilometer_eth0_vip'})
        call2 = call(init_services={'res_ceilometer_haproxy': 'haproxy'},
                     corosync_bindiface='bnd0',
                     corosync_mcastport=5802,
                     resources=exp_resources,
                     resource_params=exp_resource_params,
                     clones=exp_clones)
        self.relation_set.assert_has_calls([call1, call2], any_order=False)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'get_netmask_for_address')
    @patch.object(hooks, 'get_hacluster_config')
    @patch.object(hooks, 'get_iface_for_address')
    @patch.object(hooks, 'relation_ids')
    @patch.object(hooks, 'related_units')
    @patch.object(hooks, 'relation_get')
    def test_ha_joined_ssl(self, mock_rel_get, mock_rel_units, mock_rel_ids,
                           mock_iface, mock_cluster_config, mock_netmask,
                           mock_config):
        mock_rel_ids.return_value = 'amqp:0'
        mock_rel_units.return_value = 'rabbitmq-server/0'
        mock_rel_get.return_value = '5671'

        mock_iface.return_value = 'eth0'
        mock_netmask.return_value = '255.255.255.10'
        mock_cluster_config.return_value = {'vip': '10.0.5.100',
                                            'ha-bindiface': 'bnd0',
                                            'ha-mcastport': 5802}

        hooks.hooks.execute(['hooks/ha-relation-joined'])
        self.assertEquals(self.relation_set.call_count, 2)

        exp_resources = {
            'res_ceilometer_haproxy': 'lsb:haproxy',
            'res_ceilometer_agent_central': ('ocf:openstack:'
                                             'ceilometer-agent-central'),
            'res_ceilometer_eth0_vip': 'ocf:heartbeat:IPaddr2'
        }
        exp_resource_params = {
            'res_ceilometer_haproxy': 'op monitor interval="5s"',
            'res_ceilometer_agent_central': ('params amqp_server_port="5671" '
                                             'op monitor interval="30s"'),
            'res_ceilometer_eth0_vip': ('params ip="10.0.5.100" '
                                        'cidr_netmask="255.255.255.10" '
                                        'nic="eth0"')
        }
        exp_clones = {'cl_ceilometer_haproxy': 'res_ceilometer_haproxy'}
        call1 = call(groups={'grp_ceilometer_vips': 'res_ceilometer_eth0_vip'})
        call2 = call(init_services={'res_ceilometer_haproxy': 'haproxy'},
                     corosync_bindiface='bnd0',
                     corosync_mcastport=5802,
                     resources=exp_resources,
                     resource_params=exp_resource_params,
                     clones=exp_clones)
        self.relation_set.assert_has_calls([call1, call2], any_order=False)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'keystone_joined')
    def test_ha_changed_not_clustered(self, mock_keystone_joined, mock_config):
        self.relation_get.return_value = None
        hooks.hooks.execute(['hooks/ha-relation-changed'])
        self.assertEquals(mock_keystone_joined.call_count, 0)

    @patch('charmhelpers.core.hookenv.config')
    @patch.object(hooks, 'keystone_joined')
    def test_ha_changed_clustered(self, mock_keystone_joined, mock_config):
        self.relation_get.return_value = 'yes'
        self.relation_ids.return_value = ['identity-service/0']
        hooks.hooks.execute(['hooks/ha-relation-changed'])
        self.assertEquals(mock_keystone_joined.call_count, 1)
