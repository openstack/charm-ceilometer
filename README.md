Overview
--------

This charm provides the Ceilometer service for OpenStack.  It is intended to
be used alongside the other OpenStack components, starting with the Folsom
release.

Ceilometer is made up of 2 separate services: an API service, and a collector
service. This charm allows them to be deployed in different combination,
depending on user preference and requirements.

This charm was developed to support deploying Folsom on both Ubuntu Quantal
and Ubuntu Precise.  Since Ceilometer is only available for Ubuntu 12.04 via
the Ubuntu Cloud Archive, deploying this charm to a Precise machine will by
default install Ceilometer and its dependencies from the Cloud Archive.

Usage
-----

In order to deploy Ceilometer service, the MongoDB service is required:

    juju deploy mongodb
    juju deploy ceilometer
    juju add-relation ceilometer mongodb

then Keystone and Rabbit relationships need to be established:

    juju add-relation ceilometer rabbitmq
    juju add-relation ceilometer keystone:identity-service
    juju add-relation ceilometer keystone:identity-notifications

In order to capture the calculations, a Ceilometer compute agent needs to be
installed in each nova node, and be related with Ceilometer service:

    juju deploy ceilometer-agent
    juju add-relation ceilometer-agent nova-compute
    juju add-relation ceilometer:ceilometer-service ceilometer-agent:ceilometer-service

Ceilometer provides an API service that can be used to retrieve
Openstack metrics.

Network Space support
---------------------

This charm supports the use of Juju Network Spaces, allowing the charm to be bound to network space configurations managed directly by Juju.  This is only supported with Juju 2.0 and above.

API endpoints can be bound to distinct network spaces supporting the network separation of public, internal and admin endpoints.

To use this feature, use the --bind option when deploying the charm:

    juju deploy ceilometer --bind "public=public-space internal=internal-space admin=admin-space"

alternatively these can also be provided as part of a juju native bundle configuration:

    ceilometer:
      charm: cs:xenial/ceilometer
      bindings:
        public: public-space
        admin: admin-space
        internal: internal-space

NOTE: Spaces must be configured in the underlying provider prior to attempting to use them.

NOTE: Existing deployments using os-*-network configuration options will continue to function; these options are preferred over any network space binding provided if set.
