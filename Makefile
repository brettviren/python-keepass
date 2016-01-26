# This Makefile is only used by developers.
PYVER:=2.7
PYTHON:=python$(PYVER)
VERSION:=$(shell $(PYTHON) setup.py --version)
APPNAME:=$(shell $(PYTHON) setup.py --name)


PY_FILES:=\
	setup.py \
	keepassc \
	keepasslib/__init__.py \
	keepasslib/baker.py

chmod:
	-chmod -R a+rX,u+w,go-w $(CHMODMINUSMINUS) *
	find . -type d -exec chmod 755 {} \;

dist: chmod
	$(PYTHON) setup.py sdist --formats=tar bdist_wheel
	gzip --best dist/$(APPNAME)-$(VERSION).tar

doc/keepassc.1.html: doc/keepassc.1
	man2html -r $< | tail -n +2 | sed 's/Time:.*//g' | sed 's@/:@/@g' > $@

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

.PHONY: dist chmod check pyflakes doccheck
