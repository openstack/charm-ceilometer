#!/usr/bin/python
#
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
import sys

from charmhelpers.core.hookenv import (
    action_fail,
    action_set,
)
from ceilometer_utils import (
    assess_status,
    ceilometer_upgrade_helper,
    pause_unit_helper,
    register_configs,
    resume_unit_helper,
    FailedAction,
)


def pause(args):
    """Pause the Ceilometer services.

    @raises Exception should the service fail to stop.
    """
    pause_unit_helper(register_configs())


def resume(args):
    """Resume the Ceilometer services.

    @raises Exception should the service fail to start."""
    resume_unit_helper(register_configs())


def ceilometer_upgrade(args):
    """Run ceilometer-upgrade

    @raises Exception if the ceilometer-upgrade fails.
    """
    try:
        ceilometer_upgrade_helper(register_configs())
        action_set({'outcome': 'success, ceilometer-upgrade completed.'})
    except FailedAction as e:
        if e.outcome:
            action_set({'outcome': e.outcome})
        if e.trace:
            action_set({'traceback': e.trace})
        raise Exception(str(e.message))
    assess_status(register_configs())


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"pause": pause, "resume": resume,
           "ceilometer-upgrade": ceilometer_upgrade}


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
