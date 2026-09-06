PYTHON ?= python3
.PHONY: check verify test

check:
	$(PYTHON) -I -B scripts/validate.py check
	$(PYTHON) -B -m unittest discover -s tests

verify:
	$(PYTHON) -I -B scripts/validate.py verify

test:
	$(PYTHON) -B -m unittest discover -s tests
