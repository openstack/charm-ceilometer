# Copyright 2021 Canonical Limited.
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

"""Module for managing deferred service events.

This module is used to manage deferred service events from both charm actions
and package actions.
"""

import datetime
import glob
import yaml
import os
import time
import uuid

import charmhelpers.contrib.openstack.policy_rcd as policy_rcd
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.host as host
import charmhelpers.core.unitdata as unitdata

import subprocess


# Deferred events generated from the charm are stored along side those
# generated from packaging.
DEFERRED_EVENTS_DIR = policy_rcd.POLICY_DEFERRED_EVENTS_DIR


class ServiceEvent():

    def __init__(self, timestamp, service, reason, action,
                 policy_requestor_name=None, policy_requestor_type=None):
        self.timestamp = timestamp
        self.service = service
        self.reason = reason
        self.action = action
        if policy_requestor_name:
            self.policy_requestor_name = policy_requestor_name
        else:
            self.policy_requestor_name = hookenv.service_name()
        if policy_requestor_type:
            self.policy_requestor_type = policy_requestor_type
        else:
            self.policy_requestor_type = 'charm'

    def __eq__(self, other):
        for attr in vars(self):
            if getattr(self, attr) != getattr(other, attr):
                return False
        return True

    def matching_request(self, other):
        for attr in ['service', 'action', 'reason']:
            if getattr(self, attr) != getattr(other, attr):
                return False
        return True

    @classmethod
    def from_dict(cls, data):
        return cls(
            data['timestamp'],
            data['service'],
            data['reason'],
            data['action'],
            data.get('policy_requestor_name'),
            data.get('policy_requestor_type'))


def deferred_events_files():
    """Deferred event files

    Deferred event files that were generated by service_name() policy.

    :returns: Deferred event files
    :rtype: List[str]
    """
    return glob.glob('{}/*.deferred'.format(DEFERRED_EVENTS_DIR))


def read_event_file(file_name):
    """Read a file and return the corresponding objects.

    :param file_name: Name of file to read.
    :type file_name: str
    :returns: ServiceEvent from file.
    :rtype: ServiceEvent
    """
    with open(file_name, 'r') as f:
        contents = yaml.safe_load(f)
    event = ServiceEvent(
        contents['timestamp'],
        contents['service'],
        contents['reason'],
        contents['action'],
        policy_requestor_name=contents.get('policy_requestor_name'),
        policy_requestor_type=contents.get('policy_requestor_type'))
    return event


def deferred_events():
    """Get list of deferred events.

    List of deferred events. Events are represented by dicts of the form:

       {
           action: restart,
           policy_requestor_name: neutron-openvswitch,
           policy_requestor_type: charm,
           reason: 'Pkg update',
           service: openvswitch-switch,
           time: 1614328743}

    :returns: List of deferred events.
    :rtype: List[ServiceEvent]
    """
    events = []
    for defer_file in deferred_events_files():
        events.append((defer_file, read_event_file(defer_file)))
    return events


def duplicate_event_files(event):
    """Get list of event files that have equivalent deferred events.

    :param event: Event to compare
    :type event: ServiceEvent
    :returns: List of event files
    :rtype: List[str]
    """
    duplicates = []
    for event_file, existing_event in deferred_events():
        if event.matching_request(existing_event):
            duplicates.append(event_file)
    return duplicates


def get_event_record_file(policy_requestor_type, policy_requestor_name):
    """Generate filename for storing a new event.

    :param policy_requestor_type: System that blocked event
    :type policy_requestor_type: str
    :param policy_requestor_name: Name of application that blocked event
    :type policy_requestor_name: str
    :returns: File name
    :rtype: str
    """
    file_name = '{}/{}-{}-{}.deferred'.format(
        DEFERRED_EVENTS_DIR,
        policy_requestor_type,
        policy_requestor_name,
        uuid.uuid1())
    return file_name


def save_event(event):
    """Write deferred events to backend.

    :param event: Event to save
    :type event: ServiceEvent
    """
    requestor_name = hookenv.service_name()
    requestor_type = 'charm'
    init_policy_log_dir()
    if duplicate_event_files(event):
        hookenv.log(
            "Not writing new event, existing event found. {} {} {}".format(
                event.service,
                event.action,
                event.reason),
            level="DEBUG")
    else:
        record_file = get_event_record_file(
            policy_requestor_type=requestor_type,
            policy_requestor_name=requestor_name)

        with open(record_file, 'w') as f:
            data = {
                'timestamp': event.timestamp,
                'service': event.service,
                'action': event.action,
                'reason': event.reason,
                'policy_requestor_type': requestor_type,
                'policy_requestor_name': requestor_name}
            yaml.dump(data, f)


def clear_deferred_events(svcs, action):
    """Remove any outstanding deferred events.

    Remove a deferred event if its service is in the services list and its
    action matches.

    :param svcs: List of services to remove.
    :type svcs: List[str]
    :param action: Action to remove
    :type action: str
    """
    # XXX This function is not currently processing the action. It needs to
    #     match the action and also take account of try-restart and the
    #     equivalnce of stop-start and restart.
    for defer_file in deferred_events_files():
        deferred_event = read_event_file(defer_file)
        if deferred_event.service in svcs:
            os.remove(defer_file)


def init_policy_log_dir():
    """Ensure directory to store events exists."""
    if not os.path.exists(DEFERRED_EVENTS_DIR):
        os.mkdir(DEFERRED_EVENTS_DIR)


def get_deferred_events():
    """Return a list of deferred events requested by the charm and packages.

    :returns: List of deferred events
    :rtype: List[ServiceEvent]
    """
    events = []
    for _, event in deferred_events():
        events.append(event)
    return events


def get_deferred_restarts():
    """List of deferred restart events requested by the charm and packages.

    :returns: List of deferred restarts
    :rtype: List[ServiceEvent]
    """
    return [e for e in get_deferred_events() if e.action == 'restart']


def clear_deferred_restarts(services):
    """Clear deferred restart events targeted at `services`.

    :param services: Services with deferred actions to clear.
    :type services: List[str]
    """
    clear_deferred_events(services, 'restart')


def process_svc_restart(service):
    """Respond to a service restart having occurred.

    :param service: Services that the action was performed against.
    :type service: str
    """
    clear_deferred_restarts([service])


def is_restart_permitted():
    """Check whether restarts are permitted.

    :returns: Whether restarts are permitted
    :rtype: bool
    """
    if hookenv.config('enable-auto-restarts') is None:
        return True
    return hookenv.config('enable-auto-restarts')


def check_and_record_restart_request(service, changed_files):
    """Check if restarts are permitted, if they are not log the request.

    :param service: Service to be restarted
    :type service: str
    :param changed_files: Files that have changed to trigger restarts.
    :type changed_files: List[str]
    :returns: Whether restarts are permitted
    :rtype: bool
    """
    changed_files = sorted(list(set(changed_files)))
    permitted = is_restart_permitted()
    if not permitted:
        save_event(ServiceEvent(
            timestamp=round(time.time()),
            service=service,
            reason='File(s) changed: {}'.format(
                ', '.join(changed_files)),
            action='restart'))
    return permitted


def deferrable_svc_restart(service, reason=None):
    """Restarts service if permitted, if not defer it.

    :param service: Service to be restarted
    :type service: str
    :param reason: Reason for restart
    :type reason: Union[str, None]
    """
    if is_restart_permitted():
        host.service_restart(service)
    else:
        save_event(ServiceEvent(
            timestamp=round(time.time()),
            service=service,
            reason=reason,
            action='restart'))


def configure_deferred_restarts(services):
    """Setup deferred restarts.

    :param services: Services to block restarts of.
    :type services: List[str]
    """
    policy_rcd.install_policy_rcd()
    if is_restart_permitted():
        policy_rcd.remove_policy_file()
    else:
        blocked_actions = ['stop', 'restart', 'try-restart']
        for svc in services:
            policy_rcd.add_policy_block(svc, blocked_actions)


def get_service_start_time(service):
    """Find point in time when the systemd unit transitioned to active state.

    :param service: Services to check timetsamp of.
    :type service: str
    """
    start_time = None
    out = subprocess.check_output(
        [
            'systemctl',
            'show',
            service,
            '--property=ActiveEnterTimestamp'])
    str_time = out.decode().rstrip().replace('ActiveEnterTimestamp=', '')
    if str_time:
        start_time = datetime.datetime.strptime(
            str_time,
            '%a %Y-%m-%d %H:%M:%S %Z')
    return start_time


def check_restart_timestamps():
    """Check deferred restarts against systemd units start time.

    Check if a service has a deferred event and clear it if it has been
    subsequently restarted.
    """
    for event in get_deferred_restarts():
        start_time = get_service_start_time(event.service)
        deferred_restart_time = datetime.datetime.fromtimestamp(
            event.timestamp)
        if start_time and start_time < deferred_restart_time:
            hookenv.log(
                ("Restart still required, {} was started at {}, restart was "
                 "requested after that at {}").format(
                    event.service,
                    start_time,
                    deferred_restart_time),
                level='DEBUG')
        else:
            clear_deferred_restarts([event.service])


def set_deferred_hook(hookname):
    """Record that a hook has been deferred.

    :param hookname: Name of hook that was deferred.
    :type hookname: str
    """
    with unitdata.HookData()() as t:
        kv = t[0]
        deferred_hooks = kv.get('deferred-hooks', [])
        if hookname not in deferred_hooks:
            deferred_hooks.append(hookname)
            kv.set('deferred-hooks', sorted(list(set(deferred_hooks))))


def get_deferred_hooks():
    """Get a list of deferred hooks.

    :returns: List of hook names.
    :rtype: List[str]
    """
    with unitdata.HookData()() as t:
        kv = t[0]
        return kv.get('deferred-hooks', [])


def clear_deferred_hooks():
    """Clear any deferred hooks."""
    with unitdata.HookData()() as t:
        kv = t[0]
        kv.set('deferred-hooks', [])


def clear_deferred_hook(hookname):
    """Clear a specific deferred hooks.

    :param hookname: Name of hook to remove.
    :type hookname: str
    """
    with unitdata.HookData()() as t:
        kv = t[0]
        deferred_hooks = kv.get('deferred-hooks', [])
        if hookname in deferred_hooks:
            deferred_hooks.remove(hookname)
            kv.set('deferred-hooks', deferred_hooks)
