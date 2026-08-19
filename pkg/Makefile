# Variables required for this Makefile
PKG_DIR = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TOP_DIR = $(PKG_DIR)/../build/bin
BUILD_DIR = $(PKG_DIR)/build
TARGET_DIR = $(PKG_DIR)/target
CONFIG_DIR = /etc/aerospike
DOC_DIR = /opt/aerospike/doc/$(PACKAGE_NAME)
MAC_DOC_DIR = /usr/local/aerospike/doc/$(PACKAGE_NAME)
# Package variables
PACKAGE_NAME = asadm
# Source of truth for the version, in precedence order:
#   1. $VERSION env (CI sets this from VERSION file via build_package.sh)
#   2. VERSION file at repo root
#   3. git describe (legacy clones without VERSION file)
ifeq ($(wildcard $(PKG_DIR)/../VERSION),)
VERSION ?= $(shell git describe --tags --always --abbrev=9)
else
VERSION ?= $(shell tr -d '[:space:]' < $(PKG_DIR)/../VERSION)
endif
# Package names never carry the "rcN" pre-release tag: rcN becomes the package
# iteration, so 5.0.3-rc2 packages as version 5.0.3 iteration 2. VERSION itself
# is untouched — it is what asadm --version reports.
PKG_RELEASE_SH = $(PKG_DIR)/../.github/bin/pkg_release.sh
PKG_VERSION := $(shell $(PKG_RELEASE_SH) '$(VERSION)' version)
ITERATION ?= $(shell $(PKG_RELEASE_SH) '$(VERSION)' iteration)
# For names with no iteration field of their own (.tar, macOS .pkg).
RELEASE = $(PKG_VERSION)-$(ITERATION)
RPM_VERSION := $(subst -,_,$(PKG_VERSION))
# rpm Release / deb revision. The deb revision embeds the distro per Debian
# convention (e.g. 5.0.3-1debian12), like the rpm dist tag.
DEB_ITERATION = $(ITERATION)$(BUILD_DISTRO)
# pkgbuild --version rejects hyphens and underscores; collapse both to dots
# (5.0.3-1 -> 5.0.3.1, 5.0.3-master.abc-1 -> 5.0.3.master.abc.1), and
# defensively normalize any underscore-form inputs (env overrides) too.
MAC_VERSION = $(subst _,.,$(subst -,.,$(RELEASE)))
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

# aerospike-tools older than TOOLS_SPLIT_VERSION is the monolithic bundle that
# ships these same /opt/aerospike/bin/asadm paths. From TOOLS_SPLIT_VERSION on
# it is a transitional metapackage that ships no binaries and Depends on this
# package instead, on its way to being retired entirely. The versioned
# relations below are the standard package-split handoff (Debian Policy 7.6.1:
# files moving between packages get versioned Breaks + Replaces).
#
# Keep this value in step with the metapackage cutover in
# citrusleaf/aerospike-tools and with the other standalone tool repos.
TOOLS_SPLIT_VERSION = 13.0.3

# deb: Breaks forces the old file-shipping bundle to be upgraded to the
# metapackage (or removed) in the same transaction, and Replaces lets dpkg hand
# the overlapping paths over during that transaction. Both are bounded to
# (<< TOOLS_SPLIT_VERSION): the metapackage and anything newer ship none of
# these files, so they coexist freely and no ownership ping-pong is possible.
# A bare `dpkg -i` over an old bundle refuses with a named break naming
# aerospike-tools; `apt install` resolves it. fpm has no --deb-breaks flag, so
# Breaks goes in via --deb-field.
.PHONY: deb
deb: prep
	fpm --force \
		--config-files $(CONFIG_DIR) \
		--input-type dir \
		--output-type deb \
		--chdir $(BUILD_DIR)/ \
		--name $(NAME) \
		--version $(PKG_VERSION) \
		--iteration $(DEB_ITERATION) \
		--maintainer $(MAINTAINER) \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--after-install $(PKG_DIR)/postinst.sh \
		--after-upgrade $(PKG_DIR)/postinst.sh \
		--replaces "aerospike-tools (<< $(TOOLS_SPLIT_VERSION))" \
		--deb-field "Breaks: aerospike-tools (<< $(TOOLS_SPLIT_VERSION))" \
		--package $(TARGET_DIR)/$(NAME)_$(PKG_VERSION)-$(DEB_ITERATION)_$(ARCH).deb

# rpm has no Replaces equivalent for a partial file takeover (fpm's --replaces
# maps to Obsoletes, which erases the other package wholesale), so the split is
# expressed as a versioned Conflicts against the file-shipping bundles: a named
# conflict at depsolve time instead of an opaque file collision at
# transaction-test time. Upgrading the old bundle to the metapackage and
# installing this package in one dnf transaction resolves it; the bound means
# the metapackage (>= TOOLS_SPLIT_VERSION) is never conflicted, so this flag
# never needs to be revisited.
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
		--iteration $(ITERATION) \
		--maintainer $(MAINTAINER) \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--after-install $(PKG_DIR)/postinst.sh \
		--after-upgrade $(PKG_DIR)/postinst.sh \
		--conflicts "aerospike-tools < $(TOOLS_SPLIT_VERSION)" \
		--package $(TARGET_DIR)/$(NAME)-$(RPM_VERSION)-$(ITERATION).$(BUILD_DISTRO).$(ARCH).rpm

.PHONY: tar
tar: prep
	fpm --force \
		--config-files $(CONFIG_DIR) \
		--input-type dir \
		--output-type tar \
		--chdir $(BUILD_DIR)/ \
		--name $(NAME) \
		--version $(PKG_VERSION) \
		--iteration $(ITERATION) \
		--maintainer $(MAINTAINER) \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--package $(TARGET_DIR)/$(NAME)-$(BUILD_DISTRO)-$(RELEASE)-$(ARCH).tar

.PHONY: prep
prep:
	install -d $(TARGET_DIR)
	install -d $(BUILD_DIR)/$(CONFIG_DIR)
	install -d $(BUILD_DIR)/usr/bin
	install -d $(BUILD_DIR)/opt/aerospike/bin/asadm
	cp -a $(TOP_DIR)/asadm/. $(BUILD_DIR)/opt/aerospike/bin/asadm/
	ln -sf /opt/aerospike/bin/asadm/asadm $(BUILD_DIR)/usr/bin/asadm
	ln -sf /opt/aerospike/bin/asadm/asinfo $(BUILD_DIR)/usr/bin/asinfo
	install -d $(BUILD_DIR)$(DOC_DIR)
	install -pm 644 $(PKG_DIR)/astools.conf.sample $(BUILD_DIR)$(DOC_DIR)/astools.conf.sample

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
	install -d $(MAC_ROOT)$(MAC_DOC_DIR)
	install -pm 644 $(PKG_DIR)/astools.conf.sample $(MAC_ROOT)$(MAC_DOC_DIR)/astools.conf.sample

.PHONY: osx-pkg
osx-pkg: prep-mac
	pkgbuild \
		--root $(MAC_ROOT) \
		--identifier $(PKG_ID) \
		--version $(MAC_VERSION) \
		--install-location / \
		--scripts $(PKG_DIR)/mac-scripts \
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
