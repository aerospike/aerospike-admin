# Variables required for this Makefile
PKG_DIR = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TOP_DIR = $(PKG_DIR)/../build/bin
BUILD_DIR = $(PKG_DIR)/build
TARGET_DIR = $(PKG_DIR)/target
CONFIG_DIR = /etc/aerospike
# Package variables
PACKAGE_NAME = asadm
VERSION ?= $(shell git describe --tags --always --abbrev=9)
RPM_VERSION := $(subst -,_,$(VERSION))
# pkgbuild --version allows alphanumerics; git describe uses hyphens.
MAC_VERSION := $(RPM_VERSION)
MAC_ROOT = $(BUILD_DIR)/mac-root
DMG_STAGING = $(BUILD_DIR)/dmg-staging
PKG_ID = com.aerospike.asadm
MAC_PKG = $(TARGET_DIR)/$(NAME)-$(MAC_VERSION)-$(ARCH).pkg
MAC_DMG = $(TARGET_DIR)/$(NAME)-$(MAC_VERSION)-$(ARCH).dmg
BUILD_DISTRO ?= $(shell $(PKG_DIR)/../.github/bin/os_version.sh)
NAME = aerospike-$(PACKAGE_NAME)
MAINTAINER = "Aerospike"
DESCRIPTION = "asadm and asinfo, tools for managing Aerospike database."
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
		--rpm-rpmbuild-define '_build_id_links none' \
		--exclude 'usr/lib/.build-id/*' \
		--exclude 'usr/lib64/*' \
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

# Staging for macOS installer: matches root makefile Darwin INSTALL_ROOT and symlinks.
.PHONY: prep-mac
prep-mac:
	install -d $(TARGET_DIR)
	rm -rf $(MAC_ROOT)
	install -d $(MAC_ROOT)/usr/local/aerospike/bin/asadm
	install -d $(MAC_ROOT)/usr/local/bin
	cp -a $(TOP_DIR)/asadm/. $(MAC_ROOT)/usr/local/aerospike/bin/asadm/
	ln -sf ../aerospike/bin/asadm/asadm $(MAC_ROOT)/usr/local/bin/asadm
	ln -sf ../aerospike/bin/asadm/asinfo $(MAC_ROOT)/usr/local/bin/asinfo

.PHONY: osx-pkg
osx-pkg: prep-mac
	pkgbuild \
		--root $(MAC_ROOT) \
		--identifier $(PKG_ID) \
		--version $(MAC_VERSION) \
		--install-location / \
		$(MAC_PKG)

.PHONY: osx-dmg
osx-dmg: osx-pkg
	rm -rf $(DMG_STAGING)
	install -d $(DMG_STAGING)
	cp -a $(MAC_PKG) $(DMG_STAGING)/
	hdiutil create -volname "Aerospike asadm $(MAC_VERSION)" -srcfolder $(DMG_STAGING) -ov -format UDZO $(MAC_DMG)

.PHONY: clean
clean:
	rm -rf $(TARGET_DIR)
	rm -rf $(BUILD_DIR)/opt
	rm -rf $(BUILD_DIR)/var
	rm -rf $(MAC_ROOT)
	rm -rf $(DMG_STAGING)
