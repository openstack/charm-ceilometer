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

In order to deploy Ceilometer service (prior to Queens), the MongoDB
service is required:

    juju deploy mongodb
    juju deploy ceilometer
    juju add-relation ceilometer mongodb

For OpenStack Queens or later, Gnocchi should be used instead of MongoDB
for resource, metrics and measure storage:

    juju add-relation ceilometer gnocchi

Note: When ceilometer is related to gnocchi the ceilometer-upgrade action
must be run post deployment in order to update its data store in gnocchi.

    juju run-action ceilometer-upgrade

then Keystone and Rabbit relationships need to be established:

    juju add-relation ceilometer rabbitmq
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
    juju add-relation ceilometer:ceilometer-service ceilometer-agent:ceilometer-service

Ceilometer provides an API service that can be used to retrieve
Openstack metrics.

HA/Clustering
-------------

There are two mutually exclusive high availability options: using virtual
IP(s) or DNS. In both cases, a relationship to hacluster is required which
provides the corosync back end HA functionality.

To use virtual IP(s) the clustered nodes must be on the same subnet such that
the VIP is a valid IP on the subnet for one of the node's interfaces and each
node has an interface in said subnet. The VIP becomes a highly-available API
endpoint.

At a minimum, the config option 'vip' must be set in order to use virtual IP
HA. If multiple networks are being used, a VIP should be provided for each
network, separated by spaces. Optionally, vip_iface or vip_cidr may be
specified.

To use DNS high availability there are several prerequisites. However, DNS HA
does not require the clustered nodes to be on the same subnet.
Currently the DNS HA feature is only available for MAAS 2.0 or greater
environments. MAAS 2.0 requires Juju 2.0 or greater. The clustered nodes must
have static or "reserved" IP addresses registered in MAAS. The DNS hostname(s)
must be pre-registered in MAAS before use with DNS HA.

At a minimum, the config option 'dns-ha' must be set to true and at least one
of 'os-public-hostname', 'os-internal-hostname' or 'os-internal-hostname' must
be set in order to use DNS HA. One or more of the above hostnames may be set.

The charm will throw an exception in the following circumstances:
If neither 'vip' nor 'dns-ha' is set and the charm is related to hacluster
If both 'vip' and 'dns-ha' are set as they are mutually exclusive
If 'dns-ha' is set and none of the os-{admin,internal,public}-hostname(s) are
set

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
