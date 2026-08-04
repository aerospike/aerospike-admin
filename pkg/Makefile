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

# The aerospike-tools bundle ships the same /opt/aerospike/bin/asadm paths this
# package does (see prep, below). deb Replaces without Conflicts lets dpkg hand
# file ownership to this package while both stay installed; Conflicts would make
# a plain `dpkg -i` hard-fail instead of resolving.
#
# The takeover is NOT sticky. Replaces is evaluated on every unpack, and the
# bundle declares the mirror Replaces, so a later `apt upgrade` of the bundle
# takes the paths back. Because the bundle's payload is a superset of this
# package's file list, that unpack also trips dpkg's disappearance rule and
# leaves aerospike-asadm not-installed. Recovery is `apt install aerospike-asadm`.
# Only the metapackage conversion (see the rpm target) makes ownership durable.
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
		--replaces "aerospike-tools" \
		--package $(TARGET_DIR)/$(NAME)_$(PKG_VERSION)-$(DEB_ITERATION)_$(ARCH).deb

# rpm has no Replaces equivalent for a partial file takeover (fpm's --replaces
# maps to Obsoletes, which erases the other package wholesale), so Conflicts is
# the best available outcome: a named conflict at depsolve time instead of an
# opaque file collision at transaction-test time. The bundle must still be
# removed by hand (dnf remove aerospike-tools) before this package will
# install — a known gap, not an oversight.
#
# Unversioned on purpose: the bundle ships these paths at every version, and a
# version bound would let rpm attempt the transaction for bundles above it and
# fail on the raw file conflict instead. But REMOVE this --conflicts before
# aerospike-tools becomes a metapackage that Requires this package — an
# unversioned Conflicts makes such a metapackage unsatisfiable. That conversion
# is tracked against the aerospike-tools bundle; see the Known gap section of
# the PR that introduced this flag.
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
		--conflicts "aerospike-tools" \
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
