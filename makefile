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

SOURCE_ROOT = $(realpath .)
BUILD_ROOT = $(SOURCE_ROOT)/build/
INSTALL_ROOT = /opt/aerospike/bin/
SYMLINK = /usr/bin/asadm
INSTALL_USER = aerospike
INSTALL_GROUP = aerospike


SHELL := /bin/bash

define make_build
	mkdir -p $(BUILD_ROOT)tmp
	mkdir -p $(BUILD_ROOT)bin
	rm -rf $(BUILD_ROOT)tmp/*
	rm -rf $(BUILD_ROOT)bin/*
	rm -f `find . -type f -name '*.pyc' | xargs`
	mkdir $(BUILD_ROOT)tmp/asadm
	mkdir $(BUILD_ROOT)tmp/asinfo
	cp -f *.spec $(BUILD_ROOT)tmp/
	cp -f asadm.py $(BUILD_ROOT)tmp/asadm
	rsync -aL lib $(BUILD_ROOT)tmp/asadm
	cp -rf asinfo/* $(BUILD_ROOT)tmp/asinfo

	$(if $(filter $(OS),Darwin),
	(git describe && sed -i "" s/[$$][$$]__version__[$$][$$]/`git describe`/g $(BUILD_ROOT)tmp/asadm/asadm.py) || true ,
	(sed -i'' "s/[$$][$$]__version__[$$][$$]/`git describe`/g" $(BUILD_ROOT)tmp/asadm/asadm.py) || true
	)

	$(if $(filter $(OS),Darwin),
	(git describe && sed -i "" s/[$$][$$]__version__[$$][$$]/`git describe`/g $(BUILD_ROOT)tmp/asinfo/asinfo.py) || true ,
	(sed -i'' "s/[$$][$$]__version__[$$][$$]/`git describe`/g" $(BUILD_ROOT)tmp/asinfo/asinfo.py) || true
	)
	

endef

all:
	$(call make_build)
	pipenv install --dev
	pipenv graph
	pipenv run bash -c "(cd $(BUILD_ROOT)tmp && pyinstaller asadm-asinfo.spec --distpath $(BUILD_ROOT)bin --workpath $(BUILD_ROOT)tmp/ --codesign-identity 'Developer ID Application: Aerospike, Inc.')"

install:
	install -d -m 755 $(INSTALL_ROOT)
	install -m 755 $(BUILD_ROOT)bin/asadm $(INSTALL_ROOT)asadm
	ln -sf $(INSTALL_ROOT)asadm $(SYMLINK)
