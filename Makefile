SHELL := /bin/bash

# target: all - Default target. Does nothing.
all:
	@echo "Hello $(LOGNAME), nothing to do by default."
	@echo "Try 'make help'"

help:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$'

install:
	poetry install

activate:
	poetry shell

clean:
	find . -type f -name "*.py[co]" -delete
	find . -type d -name "__pycache__" -delete

doc: openapi
	rm -Rf docs/_build
	sphinx-build docs/ docs/_build/html

multidoc: openapi
	rm -Rf docs/_build
	sphinx-multiversion docs/ docs/_build/html

openapi:
	python contrib/openapi.py
