# asadm from the working tree on RHEL 9, with cryptography built against the
# host's OpenSSL, so OPENSSL_FORCE_FIPS_MODE=1 reaches every crypto path asadm uses.
FROM redhat/ubi9:9.6

COPY install_rust.sh /tmp/install_rust.sh
RUN dnf -y install python3.12 python3.12-pip python3.12-devel gcc libffi-devel \
      openssl openssl-devel pkgconf-pkg-config openssh-clients findutils \
 && dnf clean all \
 && bash /tmp/install_rust.sh \
 && rm /tmp/install_rust.sh

COPY requirements.txt /tmp/requirements.txt
RUN PATH="/root/.cargo/bin:$PATH" PIP_NO_BINARY=cryptography \
      python3.12 -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt

RUN printf '#!/bin/sh\nexec python3.12 /asadm/asadm.py "$@"\n' > /usr/local/bin/asadm \
 && printf '#!/bin/sh\nexec python3.12 /asadm/asinfo/asinfo.py "$@"\n' > /usr/local/bin/asinfo \
 && chmod 755 /usr/local/bin/asadm /usr/local/bin/asinfo

ENV PYTHONDONTWRITEBYTECODE=1
