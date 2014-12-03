#!/usr/bin/python

import base64
import os
import shutil
import sys
from charmhelpers.fetch import (
    apt_install, filter_installed_packages,
    apt_update
)
from charmhelpers.core.hookenv import (
    open_port,
    relation_get,
    relation_set,
    relation_ids,
    config,
    Hooks, UnregisteredHookError,
    log
)
from charmhelpers.core.host import (
    restart_on_change,
    lsb_release
)
from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    openstack_upgrade_available
)
from ceilometer_utils import (
    get_packages,
    CEILOMETER_DB,
    CEILOMETER_SERVICE,
    CEILOMETER_ROLE,
    register_configs,
    restart_map,
    get_ceilometer_context,
    get_shared_secret,
    do_openstack_upgrade,
    set_shared_secret
)
from ceilometer_contexts import CEILOMETER_PORT
from charmhelpers.contrib.openstack.ip import (
    canonical_url,
    PUBLIC, INTERNAL, ADMIN
)
from charmhelpers.contrib.network.ip import (
    get_iface_for_address,
    get_netmask_for_address
)
from charmhelpers.contrib.hahelpers.cluster import (
    get_hacluster_config,
    is_elected_leader
)

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook()
def install():
    origin = config('openstack-origin')
    if (lsb_release()['DISTRIB_CODENAME'] == 'precise'
            and origin == 'distro'):
        origin = 'cloud:precise-grizzly'
    configure_installation_source(origin)
    apt_update(fatal=True)
    apt_install(filter_installed_packages(get_packages()),
                fatal=True)
    open_port(CEILOMETER_PORT)


@hooks.hook("amqp-relation-joined")
def amqp_joined():
    relation_set(username=config('rabbit-user'),
                 vhost=config('rabbit-vhost'))


@hooks.hook("shared-db-relation-joined")
def db_joined():
    relation_set(ceilometer_database=CEILOMETER_DB)


@hooks.hook("amqp-relation-changed",
            "shared-db-relation-changed",
            "shared-db-relation-departed",
            "identity-service-relation-changed")
@restart_on_change(restart_map())
def any_changed():
    CONFIGS.write_all()
    ceilometer_joined()


@hooks.hook("amqp-relation-departed")
@restart_on_change(restart_map())
def amqp_departed():
    if 'amqp' not in CONFIGS.complete_contexts():
        log('amqp relation incomplete. Peer not ready?')
        return
    CONFIGS.write_all()


@hooks.hook('config-changed')
@restart_on_change(restart_map())
def config_changed():
    if openstack_upgrade_available('ceilometer-common'):
        do_openstack_upgrade(CONFIGS)
    CONFIGS.write_all()
    ceilometer_joined()
    for rid in relation_ids('identity-service'):
        keystone_joined(relid=rid)


@hooks.hook('upgrade-charm')
def upgrade_charm():
    install()
    any_changed()


def install_ceilometer_ocf():
    dest_file = "/usr/lib/ocf/resource.d/openstack/ceilometer-agent-central"
    src_file = 'ocf/openstack/ceilometer-agent-central'

    if not os.path.isdir(os.path.dirname(dest_file)):
        os.makedirs(os.path.dirname(dest_file))
    if not os.path.exists(dest_file):
        shutil.copy(src_file, dest_file)


@hooks.hook('cluster-relation-joined')
@restart_on_change(restart_map(), stopstart=True)
def cluster_joined():
    install_ceilometer_ocf()

    # If this node is the elected leader then share our secret with other nodes
    if is_elected_leader('grp_ceilometer_vips'):
        relation_set(shared_secret=get_shared_secret())

    CONFIGS.write_all()


@hooks.hook('cluster-relation-changed',
            'cluster-relation-departed')
@restart_on_change(restart_map(), stopstart=True)
def cluster_changed():
    shared_secret = relation_get('shared_secret')
    if shared_secret is None or shared_secret.strip() == '':
        log('waiting for shared secret to be provided by leader')
    elif not shared_secret == get_shared_secret():
        set_shared_secret(shared_secret)

    CONFIGS.write_all()


@hooks.hook('ha-relation-joined')
def ha_joined():
    cluster_config = get_hacluster_config()

    resources = {
        'res_ceilometer_haproxy': 'lsb:haproxy',
        'res_ceilometer_agent_central': ('ocf:openstack:'
                                         'ceilometer-agent-central')
    }

    resource_params = {
        'res_ceilometer_haproxy': 'op monitor interval="5s"',
        'res_ceilometer_agent_central': 'op monitor interval="30s"'
    }

    vip_group = []
    for vip in cluster_config['vip'].split():
        res_ceilometer_vip = 'ocf:heartbeat:IPaddr2'
        vip_params = 'ip'

        iface = get_iface_for_address(vip)
        if iface is not None:
            vip_key = 'res_ceilometer_{}_vip'.format(iface)
            resources[vip_key] = res_ceilometer_vip
            resource_params[vip_key] = (
                'params {ip}="{vip}" cidr_netmask="{netmask}"'
                ' nic="{iface}"'.format(ip=vip_params,
                                        vip=vip,
                                        iface=iface,
                                        netmask=get_netmask_for_address(vip))
            )
            vip_group.append(vip_key)

    if len(vip_group) >= 1:
        relation_set(groups={'grp_ceilometer_vips': ' '.join(vip_group)})

    init_services = {
        'res_ceilometer_haproxy': 'haproxy'
    }
    clones = {
        'cl_ceilometer_haproxy': 'res_ceilometer_haproxy'
    }
    relation_set(init_services=init_services,
                 corosync_bindiface=cluster_config['ha-bindiface'],
                 corosync_mcastport=cluster_config['ha-mcastport'],
                 resources=resources,
                 resource_params=resource_params,
                 clones=clones)


@hooks.hook('ha-relation-changed')
def ha_changed():
    clustered = relation_get('clustered')
    if not clustered or clustered in [None, 'None', '']:
        log('ha_changed: hacluster subordinate not fully clustered.')
    else:
        log('Cluster configured, notifying other services and updating '
            'keystone endpoint configuration')
        for rid in relation_ids('identity-service'):
            keystone_joined(relid=rid)


@hooks.hook("identity-service-relation-joined")
def keystone_joined(relid=None):
    public_url = "{}:{}".format(
        canonical_url(CONFIGS, PUBLIC),
        CEILOMETER_PORT
    )
    admin_url = "{}:{}".format(
        canonical_url(CONFIGS, ADMIN),
        CEILOMETER_PORT
    )
    internal_url = "{}:{}".format(
        canonical_url(CONFIGS, INTERNAL),
        CEILOMETER_PORT
    )
    region = config("region")
    relation_set(relation_id=relid,
                 service=CEILOMETER_SERVICE,
                 public_url=public_url,
                 admin_url=admin_url,
                 internal_url=internal_url,
                 requested_roles=CEILOMETER_ROLE,
                 region=region)


@hooks.hook("ceilometer-service-relation-joined")
def ceilometer_joined():
    # Pass local context data onto related agent services
    context = get_ceilometer_context()
    # This value gets tranformed to a path by the context we need to
    # pass the data to agents.
    if 'rabbit_ssl_ca' in context:
        with open(context['rabbit_ssl_ca']) as fh:
            context['rabbit_ssl_ca'] = base64.b64encode(fh.read())
    for relid in relation_ids('ceilometer-service'):
        relation_set(relid, context)

if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
