#!/usr/bin/python

import os
import sys

from charmhelpers.core.host import service_pause, service_resume
from charmhelpers.core.hookenv import action_fail, status_set

CEILOMETER_SERVICES = [
    'ceilometer-agent-central',
    'ceilometer-collector',
    'ceilometer-api',
    'ceilometer-alarm-evaluator',
    'ceilometer-alarm-notifier',
    'ceilometer-agent-notification',
]


def pause(args):
    """Pause the Ceilometer services.

    @raises Exception should the service fail to stop.
    """
    for service in CEILOMETER_SERVICES:
        if not service_pause(service):
            raise Exception("Failed to %s." % service)
    status_set(
        "maintenance", "Paused. Use 'resume' action to resume normal service.")

def resume(args):
    """Resume the Ceilometer services.

    @raises Exception should the service fail to start."""
    for service in CEILOMETER_SERVICES:
        if not service_resume(service):
            raise Exception("Failed to resume %s." % service)
    status_set("active", "")


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"pause": pause, "resume": resume}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return "Action %s undefined" % action_name
    else:
        try:
            action(args)
        except Exception as e:
            action_fail(str(e))


if __name__ == "__main__":
    sys.exit(main(sys.argv))

