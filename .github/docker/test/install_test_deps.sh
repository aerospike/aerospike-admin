#!/usr/bin/env bash
UBUNTU_DEPS="git wget gpg lsb-release sudo"
REDHAT_DEPS="git wget gpg sudo"

function install_test_framework() {
  cd /tmp
  git clone https://github.com/bats-core/bats-core.git
  cd bats-core
  ./install.sh /usr/local
}

function install_yum_repo() {
  # This script creates an Aerospike yum .repo file for the detected OS and arch
  # Only the TEST repo is enabled; all other SDLC-stage repos are disabled by default.
  # Get JFrog credentials
  if [ -z "$JF_USERNAME" ]; then
      echo "JF_USERNAME not present"
      exit 1
  fi
  JF_USERNAME="${JF_USERNAME//@/%40}"
  if [ -z "$JF_TOKEN" ]; then
      echo "JF_TOKEN not present"
      exit 1
  fi
  # Detect OS distro and version
  if [ -f /etc/os-release ]; then
      . /etc/os-release
      case "$ID" in
          rhel|centos|almalinux|rocky)
              DIST="el${VERSION_ID%%.*}"
              ;;
          amzn)
              if [[ "$VERSION_ID" == "2023" ]]; then
                  DIST="amzn2023"
              else
                  echo "Unsupported Amazon Linux version: $VERSION_ID"
                  exit 1
              fi
              ;;
          *)
              echo "Unsupported distro: $ID"
              exit 1
              ;;
      esac
  else
      echo "Cannot determine OS version"
      exit 1
  fi
  ARCH=$(uname -m)   # e.g., x86_64, aarch64
  REPO_FILE="/etc/yum.repos.d/aerospike-${DIST,,}-all.repo"
  # Write .repo content
  sudo tee "$REPO_FILE" > /dev/null <<EOF
[aerospike-${DIST,,}-dev]
name=Aerospike RPM Repo DEV for ${DIST^^} (\$basearch)
baseurl=https://${JF_USERNAME}:${JF_TOKEN}@artifact.aerospike.io/artifactory/database-rpm-dev-local/${DIST,,}/$ARCH/
enabled=1
gpgcheck=1
gpgkey=https://artifact.aerospike.io/artifactory/api/security/keypair/aerospike/public
[aerospike-${DIST,,}-test]
name=Aerospike RPM Repo TEST for ${DIST^^} (\$basearch)
baseurl=https://${JF_USERNAME}:${JF_TOKEN}@artifact.aerospike.io/artifactory/database-rpm-test-local/${DIST,,}/$ARCH/
enabled=0
gpgcheck=1
gpgkey=https://artifact.aerospike.io/artifactory/api/security/keypair/aerospike/public
[aerospike-${DIST,,}-stage]
name=Aerospike RPM Repo STAGE for ${DIST^^} (\$basearch)
baseurl=https://${JF_USERNAME}:${JF_TOKEN}@artifact.aerospike.io/artifactory/database-rpm-stage-local/${DIST,,}/$ARCH/
enabled=0
gpgcheck=1
gpgkey=https://artifact.aerospike.io/artifactory/api/security/keypair/aerospike/public
[aerospike-${DIST,,}-preview]
name=Aerospike RPM Repo PREVIEW for ${DIST^^} (\$basearch)
baseurl=https://${JF_USERNAME}:${JF_TOKEN}@artifact.aerospike.io/artifactory/database-rpm-preview-local/${DIST,,}/$ARCH/
enabled=0
gpgcheck=1
gpgkey=https://artifact.aerospike.io/artifactory/api/security/keypair/aerospike/public
[aerospike-${DIST,,}-stable]
name=Aerospike RPM Repo STABLE for ${DIST^^} (\$basearch)
baseurl=https://${JF_USERNAME}:${JF_TOKEN}@artifact.aerospike.io/artifactory/database-rpm-stable-local/${DIST,,}/$ARCH/
enabled=0
gpgcheck=1
gpgkey=https://artifact.aerospike.io/artifactory/api/security/keypair/aerospike/public
[aerospike-${DIST,,}-internal]
name=Aerospike RPM Repo INTERNAL for ${DIST^^} (\$basearch)
baseurl=https://${JF_USERNAME}:${JF_TOKEN}@artifact.aerospike.io/artifactory/database-rpm-internal-local/${DIST,,}/$ARCH/
enabled=0
gpgcheck=1
gpgkey=https://artifact.aerospike.io/artifactory/api/security/keypair/aerospike/public
EOF
  echo "Aerospike .repo file written to $REPO_FILE"
}

function install_deb_repo() {
  CODENAME=$(lsb_release -sc)             # e.g. bookworm, jammy, noble
  ARCH=$(dpkg --print-architecture)       # e.g. amd64, arm64
  KEYRING=/usr/share/keyrings/aerospike.gpg
  REPO_URL="https://artifact.aerospike.io/artifactory/deb"
  apt -y install $UBUNTU_DEPS
  # https://aerospike.atlassian.net/wiki/spaces/DevOps/pages/4371644510/Installing+deb+and+rpm+for+internal+password+protected+use
  # Fetch Aerospike key (if not already present)

  wget -qO - https://aerospike.jfrog.io/artifactory/api/security/keypair/aerospike/public | gpg --batch --no-tty --dearmor -o $KEYRING
  # 2. Add the Aerospike repository to the sources list
  echo "deb [arch=$ARCH signed-by=$KEYRING] $REPO_URL $CODENAME main" >> /etc/apt/sources.list.d/aerospike.list
  apt-get update



  # This script creates an Aerospike apt sources.list.d file for the detected OS and arch
  # Only the TEST repo is enabled; all other SDLC-stage repos are disabled by default.
  # Get JFrog credentials
  if [ -z "$JF_USERNAME" ]; then
      echo "JF_USERNAME not present"
      exit 1
  fi
  JF_USERNAME="${JF_USERNAME//@/%40}"
  if [ -z "$JF_TOKEN" ]; then
      echo "JF_TOKEN not present"
      exit 1
  fi
  # Detect OS distro and version
  if [ -f /etc/os-release ]; then
      . /etc/os-release
      CODENAME="$VERSION_CODENAME"
  else
      echo "Cannot determine OS distribution/version"
      exit 1
  fi
  # Fetch Aerospike key (if not already present)
#  wget -qO - https://artifact.aerospike.io/artifactory/api/security/keypair/aerospike/public | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/aerospike.gpg
  # Output file
  REPO_FILE="/etc/apt/sources.list.d/aerospike-${CODENAME}-all.list"
  # Write sources.list content
  tee "$REPO_FILE" > /dev/null <<EOF
# Aerospike DEB Repository Configuration
# Leave only one of the following entries enabled
# DEV repository
deb [arch=$ARCH signed-by=/usr/share/keyrings/aerospike.gpg] https://${JF_USERNAME}:${JF_TOKEN}@artifact.aerospike.io/artifactory/database-deb-dev-local $CODENAME main
# TEST repository
# deb [arch=$ARCH signed-by=/usr/share/keyrings/aerospike.gpg] https://${JF_USERNAME}:${JF_TOKEN}@artifact.aerospike.io/artifactory/database-deb-test-local $CODENAME main
# STAGE repository
# deb [arch=$ARCH signed-by=/usr/share/keyrings/aerospike.gpg] https://${JF_USERNAME}:${JF_TOKEN}@artifact.aerospike.io/artifactory/database-deb-stage-local $CODENAME main
# INTERNAL repository
# deb [arch=$ARCH signed-by=/usr/share/keyrings/aerospike.gpg] https://${JF_USERNAME}:${JF_TOKEN}@artifact.aerospike.io/artifactory/database-deb-internal-local $CODENAME main
# PREVIEW repository
# deb [arch=$ARCH signed-by=/usr/share/keyrings/aerospike.gpg] https://artifact.aerospike.io/artifactory/database-deb-preview-local $CODENAME main
# STABLE repository
# deb [arch=$ARCH signed-by=/usr/share/keyrings/aerospike.gpg] https://artifact.aerospike.io/artifactory/database-deb-stable-local $CODENAME main
EOF

  echo "Aerospike sources.list file written to $REPO_FILE"
  echo "Updating package lists..."
  apt-get update  
}


function install_test_deps_debian12() {
  apt -y install $UBUNTU_DEPS
  install_test_framework
  install_deb_repo
}

function install_test_deps_debian13() {
  apt -y install $UBUNTU_DEPS
  install_test_framework
  install_deb_repo
}

function install_test_deps_ubuntu20.04() {
  apt -y install $UBUNTU_DEPS
  install_test_framework
  install_deb_repo
}

function install_test_deps_ubuntu22.04() {
  apt -y install $UBUNTU_DEPS
  install_test_framework
  install_deb_repo
}

function install_test_deps_ubuntu24.04() {
  apt -y install $UBUNTU_DEPS
  install_test_framework
  install_deb_repo
}

function install_test_deps_el8() {
  dnf install -y $REDHAT_DEPS
  install_test_framework
  install_yum_repo
}

function install_test_deps_el9() {
  dnf install -y $REDHAT_DEPS
  install_test_framework
  install_yum_repo
}

function install_test_deps_el10() {
  dnf install -y $REDHAT_DEPS
  install_test_framework
  install_yum_repo
}

function install_test_deps_amzn2023() {
  dnf install -y $REDHAT_DEPS
  install_test_framework
  install_yum_repo
}
