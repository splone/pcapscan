VIRTUALENV ?= env
SOURCEDIR = pcapscanner

help:
	@echo PCAPScanner
	@echo
	@echo The makefile provides some help utilities to setup environment
	@echo	or to check your code to match pep8.
	@echo
	@echo usage:
	@echo
	@echo   make install      -- install environment
	@echo 	make help					-- print this help
	@echo 	make lint					-- check coding style
	@echo

install:
	if [ ! -f $(VIRTUALENV)/bin/python3 ]; then python3 -m venv $(VIRTUALENV); fi
	$(VIRTUALENV)/bin/python3 -m pip install --upgrade -r requirements.txt

lint:
	$(VIRTUALENV)/bin/flake8 $(SOURCEDIR)
