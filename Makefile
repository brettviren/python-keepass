# This Makefile is only used by developers.
PYVER:=2.7
PYTHON:=python$(PYVER)
ifeq ($(shell uname),Darwin)
  CHMODMINUSMINUS:=
else
  CHMODMINUSMINUS:=--
endif
PY_FILES:=\
	setup.py \
	keepassc \
	keepasslib/__init__.py \
	keepasslib/decorators.py \
	keepasslib/header.py \
	keepasslib/hier.py \
	keepasslib/infoblock.py \
	keepasslib/kpdb.py

PY2APPOPTS?=

MANIFEST: MANIFEST.in setup.py
	$(PYTHON) setup.py sdist --manifest-only

chmod:
	-chmod -R a+rX,u+w,go-w $(CHMODMINUSMINUS) *
	find . -type d -exec chmod 755 {} \;

dist: MANIFEST chmod
	$(PYTHON) setup.py sdist --formats=bztar

app: chmod
	$(PYTHON) setup.py py2app $(PY2APPOPTS)

doccheck:
	py-check-docstrings --force $(PY_FILES)

check:
	check-copyright
	py-tabdaddy
	$(MAKE) doccheck
	-$(MAKE) pyflakes
	$(PYTHON) setup.py check --restructuredtext

pyflakes:
	pyflakes $(PY_FILES)

test:
	./test.sh

.PHONY: dist chmod check pyflakes doccheck test
