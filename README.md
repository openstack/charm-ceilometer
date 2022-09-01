# Overview

This charm provides the Ceilometer service for OpenStack.

Ceilometer is made up of 2 separate services: an API service, and a collector
service. This charm allows them to be deployed in different combination,
depending on user preference and requirements.

## Usage

In order to deploy Ceilometer service (prior to Queens), the MongoDB
service is required:

    juju deploy mongodb
    juju deploy ceilometer
    juju add-relation ceilometer mongodb

For OpenStack Queens or later, Gnocchi should be used instead of MongoDB
for resource, metrics and measure storage:

    juju add-relation ceilometer gnocchi

Note: When ceilometer is related to gnocchi the ceilometer-upgrade action
must be run post deployment in order to update its data store in gnocchi. It
is not strictly necessary to re-run this action on every charm or OpenStack
release upgrade. If re-running it, be aware that it may override any
gnocchi resource-type adjustments that would have been made.

    juju run-action ceilometer/0 ceilometer-upgrade

then Keystone and Rabbit relationships need to be established:

    juju add-relation ceilometer:amqp rabbitmq
    juju add-relation ceilometer keystone:identity-service
    juju add-relation ceilometer keystone:identity-notifications

For OpenStack Queens, the identity-service relation must be replaced
with the identity-credentials relation:

    juju add-relation ceilometer keystone:identity-credentials

Ceilometer@Queens does not provide an API service.

In order to capture the calculations, a Ceilometer compute agent needs to be
installed in each nova node, and be related with Ceilometer service:

    juju deploy ceilometer-agent
    juju add-relation ceilometer-agent nova-compute
    juju add-relation ceilometer-agent:amqp rabbitmq-server:amqp
    juju add-relation ceilometer:ceilometer-service ceilometer-agent:ceilometer-service

Ceilometer provides an API service that can be used to retrieve
Openstack metrics.

If ceilometer needs to listen to multiple message queues then use the amqp interface
to relate ceilometer to the message broker that it should publish to and use the
amqp-listener interface for all message brokers ceilometer should monitor.

    juju add-relation ceilometer:amqp rabbitmq-central
    juju add-relation ceilometer:amqp-listener rabbitmq-neutron
    juju add-relation ceilometer:amqp-listener rabbitmq-nova-cell2

## High availability

When more than one unit is deployed with the [hacluster][hacluster-charm]
application the charm will bring up an HA active/active cluster.

There are two mutually exclusive high availability options: using virtual IP(s)
or DNS. In both cases the hacluster subordinate charm is used to provide the
Corosync and Pacemaker backend HA functionality.

See [OpenStack high availability][cdg-ha-apps] in the [OpenStack Charms
Deployment Guide][cdg] for details.

## Network Space support

This charm supports the use of Juju Network Spaces, allowing the charm to be bound to network space configurations managed directly by Juju.  This is only supported with Juju 2.0 and above.

API endpoints can be bound to distinct network spaces supporting the network separation of public, internal and admin endpoints.

To use this feature, use the --bind option when deploying the charm:

    juju deploy ceilometer --bind "public=public-space internal=internal-space admin=admin-space"

alternatively these can also be provided as part of a juju native bundle configuration:

    ceilometer:
      charm: cs:ceilometer
      bindings:
        public: public-space
        admin: admin-space
        internal: internal-space

NOTE: Spaces must be configured in the underlying provider prior to attempting to use them.

NOTE: Existing deployments using os-*-network configuration options will continue to function; these options are preferred over any network space binding provided if set.

<!-- LINKS -->

[hacluster-charm]: https://jaas.ai/hacluster
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide
[cdg-ha-apps]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-ha.html#ha-applications
