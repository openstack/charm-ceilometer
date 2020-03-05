#!/usr/bin/make
PYTHON := /usr/bin/env python3

clean:
	rm -rf .coverage .tox .testrepository trusty .unit-state.db
	find . -iname '*.pyc' -delete

lint:
	@tox -e pep8

test:
	@# Bundletester expects unit tests here.
	@tox -e py37

functional_test:
	@echo Starting Zaza functional tests...
	@tox -e func

bin/charm_helpers_sync.py:
	@mkdir -p bin
	@curl -o bin/charm_helpers_sync.py https://raw.githubusercontent.com/juju/charm-helpers/master/tools/charm_helpers_sync/charm_helpers_sync.py


sync: bin/charm_helpers_sync.py
	@$(PYTHON) bin/charm_helpers_sync.py -c charm-helpers-hooks.yaml

publish: lint test
	bzr push lp:charms/ceilometer
	bzr push lp:charms/trusty/ceilometer
