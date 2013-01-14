#!/usr/bin/python
import subprocess
import sys
import json
import os
import time

from lib.openstack_common import *

ceilometer_conf = "/etc/ceilometer/ceilometer.conf"

def execute(cmd, die=False, echo=False):
    """ Executes a command 

    if die=True, script will exit(1) if command does not return 0
    if echo=True, output of command will be printed to stdout

    returns a tuple: (stdout, stderr, return code)
    """
    p = subprocess.Popen(cmd.split(" "),
                         stdout=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout=""
    stderr=""

    def print_line(l):
        if echo:
            print l.strip('\n')
            sys.stdout.flush()

    for l in iter(p.stdout.readline, ''):
        print_line(l)
        stdout += l
    for l in iter(p.stderr.readline, ''):
        print_line(l)
        stderr += l

    p.communicate()
    rc = p.returncode

    if die and rc != 0:
        error_out("ERROR: command %s return non-zero.\n" % cmd)
    return (stdout, stderr, rc)


def config_get():
    """ Obtain the units config via 'config-get' 
    Returns a dict representing current config.
    private-address and IP of the unit is also tacked on for
    convienence
    """
    output = execute("config-get --format json")[0]
    if output:
        config = json.loads(output)
        # make sure no config element is blank after config-get
        for c in config.keys():
            if not config[c]:
                error_out("ERROR: Config option has no paramter: %s" % c)
        # tack on our private address and ip
        hostname = execute("unit-get private-address")[0].strip()
        config["hostname"] = execute("unit-get private-address")[0].strip()
    else:
        config = {}
    return config

def relation_ids(relation_name=None):
    j = execute('relation-ids --format=json %s' % relation_name)[0]
    return json.loads(j)

def relation_list(relation_id=None):
    cmd = 'relation-list --format=json'
    if relation_id:
        cmd += ' -r %s' % relation_id
    j = execute(cmd)[0]
    return json.loads(j)

def relation_set(relation_data):
    """ calls relation-set for all key=values in dict """
    for k in relation_data:
        execute("relation-set %s=%s" % (k, relation_data[k]), die=True)

def relation_get(relation_data):
    """ Obtain all current relation data
    relation_data is a list of options to query from the relation
    Returns a k,v dict of the results. 
    Leave empty responses out of the results as they haven't yet been
    set on the other end. 
    Caller can then "len(results.keys()) == len(relation_data)" to find out if
    all relation values have been set on the other side
    """
    results = {}
    for r in relation_data:
        result = execute("relation-get %s" % r, die=True)[0].strip('\n')
        if result != "":
           results[r] = result
    return results

def relation_get_dict(relation_id=None, remote_unit=None):
    """Obtain all relation data as dict by way of JSON"""
    cmd = 'relation-get --format=json'
    if relation_id:
        cmd += ' -r %s' % relation_id
    if remote_unit:
        remote_unit_orig = os.getenv('JUJU_REMOTE_UNIT', None)
        os.environ['JUJU_REMOTE_UNIT'] = remote_unit
    j = execute(cmd, die=True)[0]
    if remote_unit and remote_unit_orig:
        os.environ['JUJU_REMOTE_UNIT'] = remote_unit_orig
    d = json.loads(j)
    settings = {}
    # convert unicode to strings
    for k, v in d.iteritems():
        settings[str(k)] = str(v)
    return settings

def update_config_block(block, **kwargs):
    """ Updates ceilometer.conf blocks given kwargs.
    Can be used to update driver settings for a particular backend,
    setting the sql connection, etc.

    Parses block heading as '[block]'

    If block does not exist, a new block will be created at end of file with
    given kwargs
    """
    f = open(ceilometer_conf, "r+")
    orig = f.readlines()
    new = []
    found_block = ""
    heading = "[%s]\n" % block

    lines = len(orig)
    ln = 0

    def update_block(block):
        for k, v in kwargs.iteritems():
            for l in block:
                if l.strip().split(" ")[0] == k:
                    block[block.index(l)] = "%s = %s\n" % (k, v)
                    return
            block.append('%s = %s\n' % (k, v))
            block.append('\n')

    try:
        found = False
        while ln < lines:
            if orig[ln] != heading:
                new.append(orig[ln])
                ln += 1
            else:
                new.append(orig[ln])
                ln += 1
                block = []
                while orig[ln].strip() != '':
                    block.append(orig[ln])
                    ln += 1
                update_block(block)
                new += block
                found = True

        if not found:
            if new[(len(new) - 1)].strip() != '':
                new.append('\n')
            new.append('%s' % heading)
            for k, v in kwargs.iteritems():
                new.append('%s = %s\n' % (k, v))
            new.append('\n')
    except:
        error_out('Error while attempting to update config block. '\
                  'Refusing to overwite existing config.')

        return

    # backup original config
    backup = open(ceilometer_conf + '.juju-back', 'w+')
    for l in orig:
        backup.write(l)
    backup.close()

    # update config
    f.seek(0)
    f.truncate()
    for l in new:
        f.write(l)


def ceilometer_conf_update(opt, val):
    """ Updates ceilometer.conf values 
    If option exists, it is reset to new value
    If it does not, it added to the top of the config file after the [DEFAULT]
    heading to keep it out of the paste deploy config
    """
    f = open(ceilometer_conf, "r+")
    orig = f.readlines()
    new = ""
    found = False
    for l in orig:
        if l.split(' ')[0] == opt:
            juju_log("Updating %s, setting %s = %s" % (keystone_conf, opt, val))
            new += "%s = %s\n" % (opt, val)
            found  = True
        else:
            new += l
    new = new.split('\n')
    # insert a new value at the top of the file, after the 'DEFAULT' header so
    # as not to muck up paste deploy configuration later in the file 
    if not found:
        juju_log("Adding new config option %s = %s" % (opt, val))
        header = new.index("[DEFAULT]")
        new.insert((header+1), "%s = %s" % (opt, val))
    f.seek(0)
    f.truncate()
    for l in new:
        f.write("%s\n" % l)
    f.close
