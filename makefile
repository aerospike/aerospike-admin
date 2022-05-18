# Copyright 2013-2021 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

OS = $(shell uname)
SOURCE_ROOT = $(realpath .)
BUILD_ROOT = $(SOURCE_ROOT)/build/
SYMLINK_ASADM = /usr/local/bin/asadm
INSTALL_USER = aerospike
INSTALL_GROUP = aerospike

ifneq (,$(filter $(OS),Darwin))
INSTALL_ROOT = /usr/local/aerospike/bin/
else
INSTALL_ROOT = /opt/aerospike/bin/
endif

SHELL := /bin/bash

define make_build
	mkdir -p $(BUILD_ROOT)tmp
	mkdir -p $(BUILD_ROOT)bin
	make clean
	cp -f *.spec $(BUILD_ROOT)tmp/
	cp -f *.py $(BUILD_ROOT)tmp/
	rsync -aL lib $(BUILD_ROOT)tmp/

	$(if $(filter $(OS),Darwin),
	(git describe && sed -i "" s/[$$][$$]__version__[$$][$$]/`git describe`/g $(BUILD_ROOT)tmp/asadm.py) || true ,
	(sed -i'' "s/[$$][$$]__version__[$$][$$]/`git describe`/g" $(BUILD_ROOT)tmp/asadm.py) || true
	)
	

endef

.PHONY: default
default: one-dir

.PHONY: one-file
one-file: init
	$(call make_build)
	pipenv run bash -c "(cd $(BUILD_ROOT)tmp && pyinstaller asadm-one-file.spec --distpath $(BUILD_ROOT)bin)"
	@echo Check $(BUILD_ROOT)bin for asadm executable

# For macOS but can be used for any OS.
.PHONY: one-dir
one-dir: init
	$(call make_build)
	pipenv run bash -c "(cd $(BUILD_ROOT)tmp && pyinstaller asadm-one-dir.spec --distpath $(BUILD_ROOT)bin)"
	@echo Check $(BUILD_ROOT)bin for bundle

.PHONY: init
init:
	pipenv clean
	pipenv install --dev
	pipenv graph

.PHONY: install
install: uninstall
	install -d -m 755 $(INSTALL_ROOT)
ifneq ($(wildcard $(BUILD_ROOT)bin/asadm/*),)
	@echo "Asadm was built in one-dir mode"
	cp -r $(BUILD_ROOT)bin/asadm $(INSTALL_ROOT)asadm
	ln -sf $(INSTALL_ROOT)asadm/asadm $(SYMLINK_ASADM)
else
	@echo "Asadm was built in one-file mode"
	install -m 755 $(BUILD_ROOT)bin/asadm $(INSTALL_ROOT)asadm
	ln -sf $(INSTALL_ROOT)asadm $(SYMLINK_ASADM)

endif

.PHONY: uninstall
uninstall:
	rm -r $(INSTALL_ROOT)asadm || true
	rm $(SYMLINK_ASADM) || true
	

.PHONY: clean
clean:
	rm -rf $(BUILD_ROOT)tmp/*
	rm -rf $(BUILD_ROOT)bin/*
	rm -f `find . -type f -name '*.pyc' | xargs`