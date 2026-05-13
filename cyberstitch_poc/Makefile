.PHONY: help test doctor manifest sqir roundtrip fcir semantic-mine stitch validate rewrite report db-create analyze db-bundle score baseline

PYTHON ?= python

help:
	$(PYTHON) -m cyberstitch.cli --help

test:
	$(PYTHON) -m unittest discover -s tests

doctor:
	$(PYTHON) -m cyberstitch.cli doctor

manifest:
	$(PYTHON) -m cyberstitch.cli manifest

sqir:
	$(PYTHON) -m cyberstitch.cli sqir

roundtrip:
	$(PYTHON) -m cyberstitch.cli roundtrip

fcir:
	$(PYTHON) -m cyberstitch.cli fcir

semantic-mine:
	$(PYTHON) -m cyberstitch.cli semantic-mine --merge

stitch:
	$(PYTHON) -m cyberstitch.cli stitch --mode offline

validate:
	$(PYTHON) -m cyberstitch.cli validate

rewrite:
	$(PYTHON) -m cyberstitch.cli rewrite

report:
	$(PYTHON) -m cyberstitch.cli report

db-create:
	$(PYTHON) -m cyberstitch.cli db-create

analyze:
	$(PYTHON) -m cyberstitch.cli analyze --queries original

db-bundle:
	$(PYTHON) -m cyberstitch.cli db-bundle

score:
	$(PYTHON) -m cyberstitch.cli score

baseline:
	$(PYTHON) -m cyberstitch.cli baseline
