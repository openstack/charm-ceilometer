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

import os
import uuid
import subprocess
import traceback

from collections import OrderedDict

from charmhelpers.contrib.openstack import (
    templating,
    context,
)
from ceilometer_contexts import (
    ApacheSSLContext,
    LoggingConfigContext,
    MongoDBContext,
    CeilometerContext,
    HAProxyContext,
    MetricServiceContext,
    CEILOMETER_PORT,
)
from charmhelpers.contrib.openstack.utils import (
    get_os_codename_package,
    get_os_codename_install_source,
    configure_installation_source,
    os_release,
    pause_unit,
    resume_unit,
    make_assess_status_func,
    os_application_version_set,
    token_cache_pkgs,
    enable_memcache,
    CompareOpenStackReleases,
    reset_os_release,
)
from charmhelpers.core.hookenv import (
    config,
    is_leader,
    log,
    DEBUG,
)
from charmhelpers.fetch import apt_update, apt_install, apt_upgrade
from charmhelpers.core.host import init_is_systemd
from copy import deepcopy

HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'
CEILOMETER_CONF_DIR = "/etc/ceilometer"
CEILOMETER_CONF = "%s/ceilometer.conf" % CEILOMETER_CONF_DIR
CEILOMETER_API_SYSTEMD_CONF = (
    '/etc/systemd/system/ceilometer-api.service.d/override.conf'
)
HTTPS_APACHE_CONF = "/etc/apache2/sites-available/openstack_https_frontend"
HTTPS_APACHE_24_CONF = "/etc/apache2/sites-available/" \
    "openstack_https_frontend.conf"
CLUSTER_RES = 'grp_ceilometer_vips'
MEMCACHED_CONF = '/etc/memcached.conf'

CEILOMETER_BASE_SERVICES = [
    'ceilometer-agent-central',
    'ceilometer-collector',
    'ceilometer-api',
]

QUEENS_SERVICES = [
    'ceilometer-agent-central',
    'ceilometer-agent-notification'
]

ICEHOUSE_SERVICES = [
    'ceilometer-alarm-notifier',
    'ceilometer-alarm-evaluator',
    'ceilometer-agent-notification'
]

MITAKA_SERVICES = [
    'ceilometer-agent-notification'
]

CEILOMETER_DB = "ceilometer"
CEILOMETER_SERVICE = "ceilometer"

CEILOMETER_BASE_PACKAGES = [
    'haproxy',
    'apache2',
    'ceilometer-agent-central',
    'ceilometer-collector',
    'ceilometer-api',
    'python-pymongo',
]

ICEHOUSE_PACKAGES = [
    'ceilometer-alarm-notifier',
    'ceilometer-alarm-evaluator',
    'ceilometer-agent-notification'
]

MITAKA_PACKAGES = [
    'ceilometer-agent-notification'
]

QUEENS_PACKAGES = [
    'ceilometer-agent-central',
    'ceilometer-agent-notification'
]

REQUIRED_INTERFACES = {
    'database': ['mongodb'],
    'messaging': ['amqp'],
    'identity': ['identity-service'],
}

CEILOMETER_ROLE = "ResellerAdmin"
SVC = 'ceilometer'
WSGI_CEILOMETER_API_CONF = '/etc/apache2/sites-enabled/wsgi-openstack-api.conf'
PACKAGE_CEILOMETER_API_CONF = '/etc/apache2/sites-enabled/ceilometer-api.conf'

QUEENS_CONFIG_FILES = OrderedDict([
    (CEILOMETER_CONF, {
        'hook_contexts': [
            context.IdentityCredentialsContext(service=SVC,
                                               service_user=SVC),
            context.AMQPContext(ssl_dir=CEILOMETER_CONF_DIR),
            LoggingConfigContext(),
            MongoDBContext(),
            CeilometerContext(),
            context.SyslogContext(),
            context.MemcacheContext(),
            MetricServiceContext(),
            context.WorkerConfigContext()],
        'services': QUEENS_SERVICES
    }),
])

CONFIG_FILES = OrderedDict([
    (CEILOMETER_CONF, {
        'hook_contexts': [context.IdentityServiceContext(service=SVC,
                                                         service_user=SVC),
                          context.AMQPContext(ssl_dir=CEILOMETER_CONF_DIR),
                          context.InternalEndpointContext(),
                          LoggingConfigContext(),
                          MongoDBContext(),
                          CeilometerContext(),
                          context.SyslogContext(),
                          HAProxyContext(),
                          context.MemcacheContext(),
                          MetricServiceContext(),
                          context.WorkerConfigContext()],
        'services': CEILOMETER_BASE_SERVICES
    }),
    (CEILOMETER_API_SYSTEMD_CONF, {
        'hook_contexts': [HAProxyContext()],
        'services': ['ceilometer-api'],
    }),
    (HAPROXY_CONF, {
        'hook_contexts': [context.HAProxyContext(singlenode_mode=True),
                          HAProxyContext()],
        'services': ['haproxy'],
    }),
    (HTTPS_APACHE_CONF, {
        'hook_contexts': [ApacheSSLContext()],
        # Include ceilometer-api to fix Bug #1632287 This is a temporary
        # tactival fix as the charm will be rewritten to use mod_wsgi next
        # cycle
        'services': ['ceilometer-api', 'apache2'],
    }),
    (HTTPS_APACHE_24_CONF, {
        'hook_contexts': [ApacheSSLContext()],
        'services': ['ceilometer-api', 'apache2'],
    }),
])

TEMPLATES = 'templates'

SHARED_SECRET = "/etc/ceilometer/secret.txt"

VERSION_PACKAGE = 'ceilometer-common'


def register_configs():
    """
    Register config files with their respective contexts.
    Regstration of some configs may not be required depending on
    existing of certain relations.
    """
    # if called without anything installed (eg during install hook)
    # just default to earliest supported release. configs dont get touched
    # till post-install, anyway.

    release = get_os_codename_package('ceilometer-common', fatal=False)
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    if not release:
        log("Not installed yet, no way to determine the OS release. "
            "Skipping register configs", DEBUG)
        return configs

    if CompareOpenStackReleases(release) >= 'queens':
        for conf in QUEENS_CONFIG_FILES:
            configs.register(conf, QUEENS_CONFIG_FILES[conf]['hook_contexts'])
    else:
        for conf in (CEILOMETER_CONF, HAPROXY_CONF):
            configs.register(conf, CONFIG_FILES[conf]['hook_contexts'])

        if init_is_systemd():
            configs.register(
                CEILOMETER_API_SYSTEMD_CONF,
                CONFIG_FILES[CEILOMETER_API_SYSTEMD_CONF]['hook_contexts']
            )

        if os.path.exists('/etc/apache2/conf-available'):
            configs.register(
                HTTPS_APACHE_24_CONF,
                CONFIG_FILES[HTTPS_APACHE_24_CONF]['hook_contexts']
            )
        else:
            configs.register(
                HTTPS_APACHE_CONF,
                CONFIG_FILES[HTTPS_APACHE_CONF]['hook_contexts']
            )
        if enable_memcache(release=release):
            configs.register(MEMCACHED_CONF, [context.MemcacheContext()])

        if run_in_apache():
            wsgi_script = "/usr/share/ceilometer/app.wsgi"
            configs.register(
                WSGI_CEILOMETER_API_CONF,
                [context.WSGIWorkerConfigContext(name="ceilometer",
                                                 script=wsgi_script),
                 CeilometerContext(),
                 HAProxyContext()]
            )
    return configs


def restart_map():
    """
    Determine the correct resource map to be passed to
    charmhelpers.core.restart_on_change() based on the services configured.

    :returns: dict: A dictionary mapping config file to lists of services
                    that should be restarted when file changes.
    """
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename >= 'queens':
        _config_files = QUEENS_CONFIG_FILES
    else:
        _config_files = CONFIG_FILES
    _map = {}
    for f, ctxt in _config_files.items():
        svcs = []
        for svc in ctxt['services']:
            svcs.append(svc)
        if f == CEILOMETER_CONF:
            for svc in ceilometer_release_services():
                svcs.append(svc)
        if svcs:
            _map[f] = svcs

    if (cmp_codename < 'queens' and
            enable_memcache(source=config('openstack-origin'))):
        _map[MEMCACHED_CONF] = ['memcached']

    if cmp_codename < 'queens' and run_in_apache():
        for cfile in _map:
            svcs = _map[cfile]
            if 'ceilometer-api' in svcs:
                svcs.remove('ceilometer-api')
                if 'apache2' not in svcs:
                    svcs.append('apache2')
        _map['WSGI_CEILOMETER_API_CONF'] = ['apache2']

    return _map


def services():
    """ Returns a list of services associate with this charm """
    _services = []
    for v in restart_map().values():
        _services = _services + v
    _services = set(_services)
    # Bug#1664898 Remove check for ceilometer-agent-central
    # service.
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename >= 'liberty' and 'ceilometer-agent-central' in _services:
        _services.remove('ceilometer-agent-central')
    return list(_services)


def determine_ports():
    """Assemble a list of API ports for services the charm is managing

    @returns [ports] - list of ports that the charm manages.
    """
    # TODO(ajkavanagh) - determine what other ports the service listens on
    # apart from the main CEILOMETER port
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename >= 'queens':
        # NOTE(jamespage): No API service for queens or later
        return []
    return [CEILOMETER_PORT]


def get_ceilometer_context():
    """ Retrieve a map of all current relation data for agent configuration """
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename >= 'queens':
        _config_files = QUEENS_CONFIG_FILES
    else:
        _config_files = CONFIG_FILES
    ctxt = {}
    for hcontext in _config_files[CEILOMETER_CONF]['hook_contexts']:
        ctxt.update(hcontext())
    return ctxt


def do_openstack_upgrade(configs):
    """
    Perform an upgrade.  Takes care of upgrading packages, rewriting
    configs, database migrations and potentially any other post-upgrade
    actions.

    :param configs: The charms main OSConfigRenderer object.
    """
    new_src = config('openstack-origin')
    new_os_rel = get_os_codename_install_source(new_src)

    log('Performing OpenStack upgrade to %s.' % (new_os_rel))

    configure_installation_source(new_src)
    dpkg_opts = [
        '--option', 'Dpkg::Options::=--force-confnew',
        '--option', 'Dpkg::Options::=--force-confdef',
    ]
    apt_update(fatal=True)
    apt_upgrade(options=dpkg_opts, fatal=True, dist=True)
    reset_os_release()
    apt_install(packages=get_packages(),
                options=dpkg_opts,
                fatal=True)

    # set CONFIGS to load templates from new release
    configs.set_release(openstack_release=new_os_rel)

    if run_in_apache():
        disable_package_apache_site()


def ceilometer_release_services():
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename >= 'mitaka' and cmp_codename < 'queens':
        return MITAKA_SERVICES
    elif cmp_codename >= 'icehouse' and cmp_codename < 'mitaka':
        return ICEHOUSE_SERVICES
    else:
        return []


def ceilometer_release_packages():
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename >= 'mitaka' and cmp_codename < 'queens':
        return MITAKA_PACKAGES
    elif cmp_codename >= 'icehouse':
        return ICEHOUSE_PACKAGES
    else:
        return []


def get_packages():
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))

    # NOTE(jamespage): @queens ceilometer has no API service, so
    #                  no requirement for token caching.
    if cmp_codename >= 'queens':
        return deepcopy(QUEENS_PACKAGES)

    packages = (deepcopy(CEILOMETER_BASE_PACKAGES) +
                ceilometer_release_packages())
    packages.extend(token_cache_pkgs(source=config('openstack-origin')))
    return packages


def get_shared_secret():
    """
    Returns the current shared secret for the ceilometer node. If the shared
    secret does not exist, this method will generate one.
    """
    secret = None
    if not os.path.exists(SHARED_SECRET):
        secret = str(uuid.uuid4())
        set_shared_secret(secret)
    else:
        with open(SHARED_SECRET, 'r') as secret_file:
            secret = secret_file.read().strip()
    return secret


def set_shared_secret(secret):
    """
    Sets the shared secret which is used to sign ceilometer messages.

    :param secret: the secret to set
    """
    with open(SHARED_SECRET, 'w') as secret_file:
        secret_file.write(secret)


def assess_status(configs):
    """Assess status of current unit

    Decides what the state of the unit should be based on the current
    configuration.

    SIDE EFFECT: calls set_os_workload_status(...) which sets the workload
    status of the unit.
    Also calls status_set(...) directly if paused state isn't complete.

    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    assess_status_func(configs)()
    os_application_version_set(VERSION_PACKAGE)


def resolve_required_interfaces():
    """Helper function to build a map of required interfaces based on the
    OpenStack release being deployed.

    @returns dict - a dictionary keyed by high-level type of interfaces names
    """
    required_ints = deepcopy(REQUIRED_INTERFACES)
    if CompareOpenStackReleases(os_release('ceilometer-common')) >= 'mitaka':
        required_ints['database'].append('metric-service')
    if CompareOpenStackReleases(os_release('ceilometer-common')) >= 'queens':
        required_ints['database'].remove('mongodb')
        required_ints['identity'] = ['identity-credentials']
    return required_ints


def assess_status_func(configs):
    """Helper function to create the function that will assess_status() for
    the unit.
    Uses charmhelpers.contrib.openstack.utils.make_assess_status_func() to
    create the appropriate status function and then returns it.
    Used directly by assess_status() and also for pausing and resuming
    the unit.

    @param configs: a templating.OSConfigRenderer() object
    @return f() -> None : a function that assesses the unit's workload status
    """
    return make_assess_status_func(
        configs, resolve_required_interfaces(),
        services=services(), ports=determine_ports())


def pause_unit_helper(configs):
    """Helper function to pause a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.pause_unit() to do the work.

    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(pause_unit, configs)


def resume_unit_helper(configs):
    """Helper function to resume a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.resume_unit() to do the work.

    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(resume_unit, configs)


def _pause_resume_helper(f, configs):
    """Helper function that uses the make_assess_status_func(...) from
    charmhelpers.contrib.openstack.utils to create an assess_status(...)
    function that can be used with the pause/resume of the unit

    @param f: the function to be used with the assess_status(...) function
    @returns None - this function is executed for its side-effect
    """
    # TODO(ajkavanagh) - ports= has been left off because of the race hazard
    # that exists due to service_start()
    f(assess_status_func(configs),
      services=services(),
      ports=determine_ports())


# NOTE(jamespage): Drop once charm switches to apache+mod_wsgi.
def reload_systemd():
    """Reload systemd configuration on systemd based installs
    """
    if init_is_systemd():
        subprocess.check_call(['systemctl', 'daemon-reload'])


def run_in_apache():
    """Return true if ceilometer API is run under apache2 with mod_wsgi in
    this release.
    """
    os_cmp = CompareOpenStackReleases(os_release('ceilometer-common'))
    return (os_cmp >= 'ocata' and os_cmp < 'queens')


def disable_package_apache_site():
    """Ensure that the package-provided apache configuration is disabled to
    prevent it from conflicting with the charm-provided version.
    """
    if os.path.exists(PACKAGE_CEILOMETER_API_CONF):
        subprocess.check_call(['a2dissite', 'ceilometer-api'])


class FailedAction(Exception):
    """
    A custom error to inform the caller that the action has failed.
    Provides message, output and traceback.
    """

    def __init__(self, message, outcome=None, trace=None):
        self.outcome = outcome
        self.trace = trace
        super(FailedAction, self).__init__(message)


def ceilometer_upgrade_helper(CONFIGS):
    """Helper function to run ceilomter-upgrde, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses ceilomter_upgrde to do the work.

    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    cmp_codename = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin')))
    if cmp_codename < 'queens':
        identity_relation = 'identity-service'
    else:
        identity_relation = 'identity-credentials'
    # NOTE(jamespage): ceilometer@ocata requires both gnocchi
    #                  and mongodb to be configured to successfully
    #                  upgrade the underlying data stores.
    if ('metric-service' not in CONFIGS.complete_contexts() or
            identity_relation not in CONFIGS.complete_contexts()):
        raise FailedAction('The {} and or metric-service relations are not '
                           'complete. ceilometer-upgrade cannot be run until '
                           'they are ready.'.format(identity_relation))
    # NOTE(jamespage): however at queens, this limitation has gone!
    if (cmp_codename < 'pike' and
            'mongodb' not in CONFIGS.complete_contexts()):
        raise FailedAction('This version of ceilometer requires both gnocchi '
                           'and mongodb. Mongodb relation incomplete.')
    try:
        ceilometer_upgrade(action=True)
    except subprocess.CalledProcessError as e:
        raise FailedAction('ceilometer-upgrade resulted in an '
                           'unexpected error: {}'.format(e.message),
                           outcome='ceilometer-upgrade failed, see traceback.',
                           trace=traceback.format_exc())


def ceilometer_upgrade(action=False):
    """Execute ceilometer-upgrade command, with retry on failure if gnocchi
    API is not ready for requests"""
    if is_leader() or action:
        if (CompareOpenStackReleases(os_release('ceilometer-common')) >=
                'newton'):
            cmd = ['ceilometer-upgrade']
        else:
            cmd = ['ceilometer-dbsync']
        log("Running ceilomter-upgrade: {}".format(" ".join(cmd)), DEBUG)
        subprocess.check_call(cmd)
        log("ceilometer-upgrade succeeded", DEBUG)
