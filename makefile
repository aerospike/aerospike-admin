# Copyright 2013-2014 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SOURCE_ROOT = $(realpath .)
BUILD_ROOT = $(SOURCE_ROOT)/build/
INSTALL_ROOT = /opt/aerospike/bin/
SYMLINK = /usr/bin/asadmin
INSTALL_USER = aerospike
INSTALL_GROUP = aerospike
INSTALL = "install -o aerospike -g aerospike"

all:
	mkdir --parents $(BUILD_ROOT)tmp
	mkdir --parents $(BUILD_ROOT)bin
	rm -rf $(BUILD_ROOT)tmp/*
	rm -rf $(BUILD_ROOT)bin/*
	rm -f `find . -type f -name '*.pyc' | xargs`
	mkdir $(BUILD_ROOT)tmp/asadmin
	cp -f *.py $(BUILD_ROOT)tmp/asadmin
	rsync -aL lib $(BUILD_ROOT)tmp/asadmin
	sed -i s/[$$][$$]__version__[$$][$$]/`git describe`/g $(BUILD_ROOT)tmp/asadmin/asadmin.py
	cd $(BUILD_ROOT)tmp/asadmin && zip -r ../asadmin *
	cp $(BUILD_ROOT)tmp/asadmin.zip $(BUILD_ROOT)bin/asadmin
	cp run_asadmin.sh $(BUILD_ROOT)bin/

install:
	install -o $(INSTALL_USER) -g $(INSTALL_GROUP) -d -m 755 $(INSTALL_ROOT)
	install -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755 $(BUILD_ROOT)bin/asadmin $(INSTALL_ROOT)asadmin
	install -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755 $(BUILD_ROOT)bin/run_asadmin.sh $(INSTALL_ROOT)run_asadmin.sh
	ln -sf $(INSTALL_ROOT)run_asadmin.sh $(SYMLINK)
