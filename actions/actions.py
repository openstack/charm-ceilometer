#!/usr/bin/python

import os
import sys

from charmhelpers.core.host import service_pause, service_resume
from charmhelpers.core.hookenv import action_fail, status_set
from charmhelpers.core.unitdata import kv
from ceilometer_utils import (
    CEILOMETER_BASE_SERVICES, assess_status, ceilometer_release_services,
)
from ceilometer_hooks import CONFIGS


def pause(args):
    """Pause the Ceilometer services.

    @raises Exception should the service fail to stop.
    """
    services = CEILOMETER_BASE_SERVICES + ceilometer_release_services()
    for service in services:
        if not service_pause(service):
            raise Exception("Failed to %s." % service)

    db = kv()
    db.set('unit-paused', True)
    db.flush()

    status_set(
        "maintenance",
        "Unit paused - use 'resume' action to resume normal service")


def resume(args):
    """Resume the Ceilometer services.

    @raises Exception should the service fail to start."""
    services = CEILOMETER_BASE_SERVICES + ceilometer_release_services()
    for service in services:
        if not service_resume(service):
            raise Exception("Failed to resume %s." % service)

    db = kv()
    db.set('unit-paused', False)
    db.flush()

    assess_status(CONFIGS)


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
