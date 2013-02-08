import os
import uuid

RABBIT_USER="nova"
RABBIT_VHOST="nova"
CEILOMETER_CONF="/etc/ceilometer/ceilometer.conf"

SHARED_SECRET = "/etc/ceilometer/secret.txt"
CEILOMETER_SERVICES = ['ceilometer-agent-central', 'ceilometer-collector', 'ceilometer-api']
CEILOMETER_DB="ceilometer"
CEILOMETER_SERVICE = "ceilometer"

def get_shared_secret():
    secret = None
    if not os.path.exists(SHARED_SECRET):
        secret = str(uuid.uuid4())
        with open(SHARED_SECRET, 'w') as secret_file:
            secret_file.write(secret)
    else:
        with open(SHARED_SECRET, 'r') as secret_file:
            secret = secret_file.read().strip()
    return secret
