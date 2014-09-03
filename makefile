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

all:
	mkdir --parents build/tmp
	mkdir --parents build/bin
	rm -rf build/tmp/*
	rm -rf build/bin/*
	rm -f `find . -type f -name '*.pyc' | xargs`
	mkdir build/tmp/asadmin
	cp -f *.py build/tmp/asadmin
	rsync -aL lib build/tmp/asadmin
	sed -i s/[$$][$$]__version__[$$][$$]/`git describe`/g build/tmp/asadmin/asadmin.py
	cd build/tmp/asadmin && zip -r ../asadmin *
	cp build/tmp/asadmin.zip build/bin/asadmin

# Alternative
# pyinstaller -F asadmin.py
# Requires compilation on each supported linux platofrm
