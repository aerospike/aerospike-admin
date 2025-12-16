# Variables required for this Makefile
PKG_DIR = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TOP_DIR = $(PKG_DIR)/../build/bin
BUILD_DIR = $(PKG_DIR)/build
TARGET_DIR = $(PKG_DIR)/target
CONFIG_DIR = /etc/aerospike
# Package variables
PACKAGE_NAME = asadm
VERSION = $(shell git describe --tags --always --abbrev=7)
RPM_VERSION = $(shell git describe --tags --always --abbrev=7 | tr '-' '_')
BUILD_DISTRO ?= $(shell $(PKG_DIR)/../.github/packaging/common/os_version.sh)
NAME = aerospike-$(PACKAGE_NAME)
MAINTAINER = "Aerospike"
DESCRIPTION = "Aerospike Admin, a tool for managing Aerospike database."
LICENSE = "Apache License 2.0"
URL = "https://github.com/aerospike/$(PACKAGE_NAME)"
VENDOR = "Aerospike, Inc."
ARCH = $(shell uname -m)


.PHONY: all
all: deb rpm tar

.PHONY: deb
deb: prep
	fpm --force \
		--config-files $(CONFIG_DIR) \
		--input-type dir \
		--output-type deb \
		--chdir $(BUILD_DIR)/ \
		--name $(NAME) \
		--version $(VERSION) \
		--maintainer $(MAINTAINER) \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--package $(TARGET_DIR)/$(NAME)_$(VERSION)_$(BUILD_DISTRO)_$(ARCH).deb

.PHONY: rpm
rpm: prep
	fpm --force \
		--config-files $(CONFIG_DIR) \
		--input-type dir \
		--output-type rpm \
		--chdir $(BUILD_DIR)/ \
		--name $(NAME) \
		--version $(RPM_VERSION) \
		--maintainer $(MAINTAINER) \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--package $(TARGET_DIR)/$(NAME)-$(RPM_VERSION).$(BUILD_DISTRO).$(ARCH).rpm

.PHONY: tar
tar: prep
	fpm --force \
		--config-files $(CONFIG_DIR) \
		--input-type dir \
		--output-type tar \
		--chdir $(BUILD_DIR)/ \
		--name $(NAME) \
		--version $(VERSION) \
		--maintainer $(MAINTAINER) \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--package $(TARGET_DIR)/$(NAME)-$(BUILD_DISTRO)-$(VERSION)-$(ARCH).tar

.PHONY: prep
prep:
	install -d $(TARGET_DIR)
	install -d $(BUILD_DIR)/$(CONFIG_DIR)
	install -d $(BUILD_DIR)/usr/bin
	install -d $(BUILD_DIR)/opt/aerospike/bin/asadm
	cp -a $(TOP_DIR)/asadm/. $(BUILD_DIR)/opt/aerospike/bin/asadm/
	ln -sf /opt/aerospike/bin/asadm/asadm $(BUILD_DIR)/usr/bin/asadm
	ln -sf /opt/aerospike/bin/asadm/asinfo $(BUILD_DIR)/usr/bin/asinfo

.PHONY: clean
clean:
	rm -rf $(TARGET_DIR)
	rm -rf $(BUILD_DIR)/opt
	rm -rf $(BUILD_DIR)/var
