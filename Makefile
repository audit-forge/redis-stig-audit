PYTHON ?= python3

run:
	$(PYTHON) audit.py --mode docker --container redis

json:
	$(PYTHON) audit.py --mode docker --container redis --json output/results.json

test:
	$(PYTHON) -m pytest test/ -v

test-unittest:
	$(PYTHON) -m unittest discover -s test -v

.PHONY: run json test test-unittest
