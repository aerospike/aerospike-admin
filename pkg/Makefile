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
RELEASE := $(PKG_VERSION)-$(ITERATION)
RPM_VERSION := $(subst -,_,$(PKG_VERSION))
# rpm Release / deb revision. The deb revision embeds the distro per Debian
# convention (e.g. 5.0.3-1debian12), like the rpm dist tag.
DEB_ITERATION = $(ITERATION)$(BUILD_DISTRO)
# pkgbuild --version rejects hyphens and underscores; collapse both to dots
# (5.0.3-1 -> 5.0.3.1, 5.0.3-master.abc-1 -> 5.0.3.master.abc.1), and
# defensively normalize any underscore-form inputs (env overrides) too. This is
# the CFBundleShortVersionString-style version *inside* the pkg only; the file
# name below keeps the canonical hyphenated RELEASE.
MAC_VERSION = $(subst _,.,$(subst -,.,$(RELEASE)))
MAC_ROOT = $(BUILD_DIR)/mac-root
PKG_ID = com.aerospike.asadm
# macOS artifact file name:
#
#     <name>-<version>-<iteration>-macos<major>-<arch>.pkg
#     e.g. aerospike-asadm-5.0.3-1-macos15-arm64.pkg
#
# The bare .pkg is the shipping artifact -- there is deliberately no .dmg. asadm
# is a CLI installed under /usr/local, so a disk image has nothing to drag and
# would be a second container needing its own signature, notarization and
# staple. Homebrew consumes the .pkg directly (url + `pkg` stanza), and
# `sudo installer -pkg ... -target /` needs no hdiutil attach.
#
# Every field is lower case and '-' separated so the name is machine-parsable
# and directly interpolatable by a Homebrew cask:
#
#     arch arm: "arm64", intel: "x86_64"
#     url ".../aerospike-asadm-#{version}-macos15-#{arch}.pkg"
#
#   * <arch> is `uname -m` (arm64 / x86_64) -- the same tokens a cask's `arch`
#     stanza emits. Never runner.arch (ARM64 / X64): those are upper case and
#     "X64" is not a macOS arch.
#   * macos<major> is the macOS generation the artifact was built on, not a
#     minimum it supports (nothing pins MACOSX_DEPLOYMENT_TARGET). It is what
#     makes the names unique when one version ships several pkgs -- we build
#     one per (macOS major, arch) pair, and without it the three arm64 builds
#     of a release would collide.
#   * RELEASE (version + iteration) rather than MAC_VERSION, so an rc respin of
#     the same version is a distinct file (5.0.3-2 vs 5.0.3-3) and the name
#     matches the deb/rpm/tar naming.
# Captured once (`:=`), so prep-mac's guard below checks the very token that
# lands in the file name, and os_version.sh is not re-run per expansion.
MAC_PLATFORM := $(shell $(PKG_DIR)/../.github/bin/os_version.sh)
MAC_PKG = $(TARGET_DIR)/$(NAME)-$(RELEASE)-$(MAC_PLATFORM)-$(ARCH).pkg
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
		--version $(PKG_VERSION) \
		--iteration $(DEB_ITERATION) \
		--maintainer $(MAINTAINER) \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--after-install $(PKG_DIR)/postinst.sh \
		--after-upgrade $(PKG_DIR)/postinst.sh \
		--package $(TARGET_DIR)/$(NAME)_$(PKG_VERSION)-$(DEB_ITERATION)_$(ARCH).deb

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
		--package $(TARGET_DIR)/$(NAME)-$(RELEASE)-$(BUILD_DISTRO)-$(ARCH).tar

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
	@test -n "$(PKG_VERSION)" && test -n "$(ITERATION)" || { echo "ERROR: empty version/iteration -- .github/bin/pkg_release.sh failed for VERSION='$(VERSION)'; refusing to build an unnamed pkg" >&2; exit 1; }
	@test -n "$(MAC_PLATFORM)" || { echo "ERROR: empty macOS platform token -- .github/bin/os_version.sh failed; refusing to build an unnamed pkg" >&2; exit 1; }
	install -d $(TARGET_DIR)
	rm -rf $(MAC_ROOT)
	install -d $(MAC_ROOT)/usr/local/aerospike/bin/asadm
	install -d $(MAC_ROOT)/usr/local/bin
	cp -a $(TOP_DIR)/asadm/. $(MAC_ROOT)/usr/local/aerospike/bin/asadm/
	ln -sf ../aerospike/bin/asadm/asadm $(MAC_ROOT)/usr/local/bin/asadm
	ln -sf ../aerospike/bin/asadm/asinfo $(MAC_ROOT)/usr/local/bin/asinfo
	install -d $(MAC_ROOT)$(MAC_DOC_DIR)
	install -pm 644 $(PKG_DIR)/astools.conf.sample $(MAC_ROOT)$(MAC_DOC_DIR)/astools.conf.sample
	$(PKG_DIR)/strip-foreign-signatures.sh $(MAC_ROOT)

.PHONY: osx-pkg
osx-pkg: prep-mac
	pkgbuild \
		--root $(MAC_ROOT) \
		--identifier $(PKG_ID) \
		--version $(MAC_VERSION) \
		--install-location / \
		--scripts $(PKG_DIR)/mac-scripts \
		$(MAC_PKG)

.PHONY: clean
clean:
	rm -rf $(TARGET_DIR)
	rm -rf $(BUILD_DIR)/opt
	rm -rf $(BUILD_DIR)/var
	rm -rf $(MAC_ROOT)
