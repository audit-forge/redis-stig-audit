PYTHON ?= python3

run:
	$(PYTHON) audit.py --mode docker --container redis

json:
	$(PYTHON) audit.py --mode docker --container redis --json output/results.json

sarif:
	$(PYTHON) audit.py --mode docker --container redis --sarif output/results.sarif

bundle:
	$(PYTHON) audit.py --mode docker --container redis --bundle output/audit-bundle.zip

all-outputs:
	$(PYTHON) audit.py --mode docker --container redis \
		--json output/results.json \
		--sarif output/results.sarif \
		--bundle output/audit-bundle.zip

test:
	$(PYTHON) -m unittest discover -s test -p 'test_*.py' -v

test-unittest:
	$(PYTHON) -m unittest discover -s test -p 'test_*.py' -v

.PHONY: run json sarif bundle all-outputs test test-unittest
