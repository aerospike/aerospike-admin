# Copyright 2013-2025 Aerospike, Inc.
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

import os
from os import path
import warnings

from . import ssl_util
from lib.utils import util

try:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)

        from OpenSSL import crypto, SSL

    HAVE_PYOPENSSL = True
except ImportError:
    HAVE_PYOPENSSL = False

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key


class SSLContext(object):
    def __init__(
        self,
        enable_tls=False,
        encrypt_only=False,
        cafile=None,
        capath=None,
        keyfile=None,
        keyfile_password=None,
        certfile=None,
        protocols=None,
        cipher_suite=None,
        crl_check=False,
        crl_check_all=False,
    ):
        self.ctx = None
        if not enable_tls:
            return
        if not HAVE_PYOPENSSL:
            raise ImportError("No module named pyOpenSSL")

        self._create_ssl_context(
            enable_tls=enable_tls,
            encrypt_only=encrypt_only,
            cafile=cafile,
            capath=capath,
            keyfile=keyfile,
            keyfile_password=keyfile_password,
            certfile=certfile,
            protocols=protocols,
            cipher_suite=cipher_suite,
        )

        self._crl_check = crl_check
        self._crl_check_all = crl_check_all
        if enable_tls and not encrypt_only and (crl_check or crl_check_all):
            self._crl_checklist = self._parse_crl_cert(capath)
        else:
            self._crl_checklist = []

    def _parse_crl_cert(self, crl_dir_path):
        if not crl_dir_path:
            raise ValueError("No capath provided to CRL check.")
        try:
            files = [
                path.join(crl_dir_path, f)
                for f in os.listdir(crl_dir_path)
                if path.isfile(path.join(crl_dir_path, f))
            ]
        except OSError:
            raise ValueError("Wrong or empty capath provided to CRL check.")

        crl_checklist = []
        for f in files:
            try:
                with open(f, "rb") as fh:
                    crl = x509.load_pem_x509_crl(fh.read())
                for revoked_cert in crl:
                    try:
                        crl_checklist.append(revoked_cert.serial_number)
                    except (ValueError, AttributeError):
                        pass
            except (OSError, ValueError):
                pass
        if crl_checklist:
            return crl_checklist
        else:
            raise ValueError("No valid CRL found at capath")

    def _verify_none_cb(self, conn, cert, errnum, depth, ok):
        return ok

    @staticmethod
    def _get_cert_short_name(attr):
        """Extract RFC 4514 short name (e.g. CN, O, OU) from an x509.NameAttribute."""
        rfc4514 = attr.rfc4514_string()
        return rfc4514.split("=", 1)[0]

    def _cert_crl_check(self, crypto_cert):
        if not crypto_cert:
            raise ValueError("empty or no Server Certificate chain for CRL check")
        if not self._crl_checklist:
            return

        serial_number = crypto_cert.serial_number
        if serial_number is None:
            raise Exception("Wrong Server Certificate: No Serial Number.")

        if serial_number in self._crl_checklist:
            raise Exception(
                "Server Certificate is in revoked list: (Serial Number: %s)"
                % (str(hex(serial_number)))
            )

    def _get_common_names(self, components):
        common_names = []
        if not components:
            return common_names
        for key, value in components:
            if key == "commonName" or key == "CN":
                common_names.append(value)

        return common_names

    def _get_subject_alt_names(self, crypto_cert):
        """Extract Subject Alternative Names using the cryptography library."""
        alt_names = []
        try:
            san_ext = crypto_cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            for name in san_ext.value:
                if isinstance(
                    name,
                    (x509.DNSName, x509.RFC822Name, x509.UniformResourceIdentifier),
                ):
                    alt_names.append(name.value)
                else:
                    alt_names.append(str(name.value))
        except x509.ExtensionNotFound:
            pass  # SAN is an optional X.509 extension; absence is not an error
        return alt_names

    def _match_tlsname(self, crypto_cert, tls_name):
        if not crypto_cert:
            raise ValueError(
                "empty or no certificate, match_tlsname needs a "
                "SSL socket or SSL context with either "
                "CERT_OPTIONAL or CERT_REQUIRED"
            )

        try:
            components = []
            for attr in crypto_cert.subject:
                short_name = self._get_cert_short_name(attr)
                components.append((short_name, attr.value))
        except (AttributeError, ValueError) as e:
            raise ValueError("Failed to read certificate components: " + str(e))

        cnnames = set()
        for value in self._get_common_names(components):
            try:
                if ssl_util.dnsname_match(value, tls_name):
                    return
            except Exception:
                pass
            cnnames.add(value)

        for value in self._get_subject_alt_names(crypto_cert):
            try:
                if ssl_util.dnsname_match(value, tls_name):
                    return
            except Exception:
                pass
            cnnames.add(value)

        if len(cnnames) > 1:
            raise Exception("Wrong tls_name %r" % tls_name)

        elif len(cnnames) == 1:
            raise Exception("Wrong tls_name %r" % tls_name)

        else:
            raise Exception(
                "no appropriate commonName or subjectAltName fields were found"
            )

    def _verify_cb(self, conn, cert, errnum, depth, ok):
        crypto_cert = cert.to_cryptography()

        if depth == 0:
            tls_name = conn.get_app_data()
            self._match_tlsname(crypto_cert, tls_name)

        if self._crl_check_all or (self._crl_check and depth == 0):
            self._cert_crl_check(crypto_cert)
        return ok

    def _parse_protocols(self, protocols):
        all_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
        protocols_to_enable = set()
        method = None

        if not protocols:
            try:
                method = SSL.TLSv1_2_METHOD
                protocols_to_enable.add("TLSv1.2")
            except AttributeError:
                method = SSL.TLSv1_METHOD
                protocols_to_enable.add("TLSv1")
        else:
            protocols = protocols.split()
            for proto in protocols:
                try:
                    if proto == "TLSv1" or proto == "+TLSv1":
                        protocols_to_enable.add("TLSv1")
                    elif proto == "-TLSv1":
                        protocols_to_enable.remove("TLSv1")

                    elif proto == "TLSv1.1" or proto == "+TLSv1.1":
                        protocols_to_enable.add("TLSv1.1")
                    elif proto == "-TLSv1.1":
                        protocols_to_enable.remove("TLSv1.1")

                    elif proto == "TLSv1.2" or proto == "+TLSv1.2":
                        protocols_to_enable.add("TLSv1.2")
                    elif proto == "-TLSv1.2":
                        protocols_to_enable.remove("TLSv1.2")

                    elif proto == "all" or proto == "+all":
                        protocols_to_enable.update(all_protocols)
                    elif proto == "-all":
                        protocols_to_enable.clear()

                    elif proto == "SSLv2" or proto == "+SSLv2":
                        raise Exception("Protocol SSLv2 not supported (RFC 6176)")
                    elif proto == "-SSLv2":
                        continue

                    elif proto == "SSLv3" or proto == "+SSLv3":
                        raise Exception("Protocol SSLv3 not supported")
                    elif proto == "-SSLv3":
                        continue

                    else:
                        raise Exception("Wrong protocol entry %s" % (str(proto)))

                except KeyError:
                    pass

        if not protocols_to_enable:
            raise Exception("Wrong protocol entries")

        protocols_to_enable = list(protocols_to_enable)

        if len(protocols_to_enable) > 1:
            method = SSL.SSLv23_METHOD
        else:
            if protocols_to_enable[0] == "TLSv1":
                method = SSL.TLSv1_METHOD

            elif protocols_to_enable[0] == "TLSv1.1":
                try:
                    method = SSL.TLSv1_1_METHOD
                except AttributeError:
                    raise Exception(
                        "No support to protocol TLSv1.1. Wrong OpenSSL or Python version. Please use PyOpenSSL >= 0.15."
                    )

            elif protocols_to_enable[0] == "TLSv1.2":
                try:
                    method = SSL.TLSv1_2_METHOD
                except AttributeError:
                    raise Exception(
                        "No support to protocol TLSv1.2. Wrong OpenSSL or Python version. Please use PyOpenSSL >= 0.15."
                    )

        protocols_to_disable = list(set(all_protocols) - set(protocols_to_enable))

        return method, protocols_to_disable

    def _set_context_options(self, ctx, protocols_to_disable):
        try:
            # always disable SSLv2, as per RFC 6176
            ctx.set_options(SSL.OP_NO_SSLv2)

            # aerospike does not support SSLv3
            ctx.set_options(SSL.OP_NO_SSLv3)
        except AttributeError:
            pass

        if not protocols_to_disable:
            return ctx

        for proto in protocols_to_disable:
            try:
                if proto == "TLSv1":
                    ctx.set_options(SSL.OP_NO_TLSv1)
                elif proto == "TLSv1.1":
                    ctx.set_options(SSL.OP_NO_TLSv1_1)
                elif proto == "TLSv1.2":
                    ctx.set_options(SSL.OP_NO_TLSv1_2)
            except AttributeError:
                pass
        return ctx

    def _create_ssl_context(
        self,
        enable_tls=False,
        encrypt_only=False,
        cafile=None,
        capath=None,
        keyfile=None,
        keyfile_password=None,
        certfile=None,
        protocols=None,
        cipher_suite=None,
    ):
        if not enable_tls:
            return
        method, protocols_to_disable = self._parse_protocols(protocols)
        self.ctx = SSL.Context(method)
        self.ctx = self._set_context_options(self.ctx, protocols_to_disable)
        if encrypt_only:
            self.ctx.set_verify(SSL.VERIFY_NONE, self._verify_none_cb)
        else:
            self.ctx.set_verify(
                SSL.VERIFY_PEER | SSL.VERIFY_CLIENT_ONCE, self._verify_cb
            )
            if cafile or capath:
                try:
                    self.ctx.load_verify_locations(cafile, capath)
                except (crypto.Error, OSError) as e:
                    path = ""

                    if cafile:
                        path = "cafile=%s" % (str(cafile))

                    if capath:
                        if path:
                            path += " and "
                        path += "capath=%s" % (str(capath))

                    raise Exception(
                        "Failed to load CA certificate from %s \n %s" % (path, str(e))
                    )

            if certfile:
                try:
                    self.ctx.use_certificate_chain_file(certfile)
                except (crypto.Error, OSError) as e:
                    raise Exception(
                        "Failed to load certificate chain file %s \n %s"
                        % (certfile, str(e))
                    )

            if keyfile:
                pkey = None
                pwd = None

                if keyfile_password:
                    try:
                        pwd = self._read_keyfile_password(keyfile_password)

                        if pwd is not None:
                            pwd = util.str_to_bytes(pwd)
                    except (TypeError, KeyError, OSError) as e:
                        raise Exception(
                            "Invalid keyfile_password {0} \n{1}".format(
                                keyfile_password, e
                            )
                        )

                try:
                    with open(keyfile, "rb") as key_fh:
                        private_key_data = key_fh.read()
                    private_key = load_pem_private_key(
                        private_key_data,
                        password=pwd,
                    )
                    pkey = crypto.PKey.from_cryptography_key(private_key)
                except IOError:
                    raise Exception("Unable to locate key file {}".format(keyfile))
                except (ValueError, TypeError):
                    raise Exception(
                        "Invalid key file or bad passphrase {}".format(keyfile)
                    )
                except crypto.Error as e:
                    raise Exception(
                        "Failed to load private key %s \n %s" % (keyfile, str(e))
                    )

                if pkey is None:
                    raise Exception("Failed to load private key %s" % keyfile)

                try:
                    self.ctx.use_privatekey(pkey)
                except SSL.Error as e:
                    raise Exception(
                        "Failed to load private key %s \n %s" % (keyfile, str(e))
                    )

        if cipher_suite:
            self.ctx.set_cipher_list(cipher_suite)

    def _read_keyfile_password(self, keyfile_password):
        """
        Fetches and returns actual password from input keyfile_password.
        If keyfile_password is "env:<VAR>" then it reads password from environment variable VAR
        If keyfile_password is "file:<PATH>" then it reads password from file
        Else it returns keyfile_password

        :param keyfile_password: input password string
        :return: password to read tls keyfile
        """

        if keyfile_password is None:
            return keyfile_password

        if not util.is_str(keyfile_password):
            raise TypeError("Bad keyfile_password: not string")

        keyfile_password = keyfile_password.strip()

        if keyfile_password.startswith("env:"):
            try:
                return os.environ[keyfile_password[4:]]
            except KeyError as e:
                raise KeyError("Failed to read environment variable: {}".format(e))

        if keyfile_password.startswith("file:"):
            try:
                with open(keyfile_password[5:], "r") as pwd_file:
                    return pwd_file.read().strip()
            except OSError as e:
                raise OSError("Failed to read file: {}".format(e))

        return keyfile_password.strip()
