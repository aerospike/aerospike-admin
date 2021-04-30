# Copyright 2013-2021 Aerospike, Inc.
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
try:
    from pyasn1.type import univ, constraint, char, namedtype, tag
    from pyasn1.codec.der import decoder as der_decoder

    HAVE_PYASN1 = True
except ImportError:
    HAVE_PYASN1 = False

if HAVE_PYASN1:
    # Helper code for ASN.1 decoding
    MAX = 64

    class DirectoryString(univ.Choice):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType(
                "teletexString",
                char.TeletexString().subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
                ),
            ),
            namedtype.NamedType(
                "printableString",
                char.PrintableString().subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
                ),
            ),
            namedtype.NamedType(
                "universalString",
                char.UniversalString().subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
                ),
            ),
            namedtype.NamedType(
                "utf8String",
                char.UTF8String().subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
                ),
            ),
            namedtype.NamedType(
                "bmpString",
                char.BMPString().subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
                ),
            ),
            namedtype.NamedType(
                "ia5String",
                char.IA5String().subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
                ),
            ),
        )

    class AttributeTypeAndValue(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("type", univ.ObjectIdentifier()),
            namedtype.NamedType("value", DirectoryString()),
        )

    class RelativeDistinguishedName(univ.SetOf):
        componentType = AttributeTypeAndValue()

    class RDNSequence(univ.SequenceOf):
        componentType = RelativeDistinguishedName()

    class AnotherName(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("type-id", univ.ObjectIdentifier()),
            namedtype.NamedType(
                "value",
                univ.Any().subtype(
                    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                ),
            ),
        )

    class Name(univ.Choice):
        componentType = namedtype.NamedTypes(namedtype.NamedType("", RDNSequence()),)

    class GeneralName(univ.Choice):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType(
                "otherName",
                AnotherName().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                ),
            ),
            namedtype.NamedType(
                "rfc822Name",
                char.IA5String().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
                ),
            ),
            namedtype.NamedType(
                "dNSName",
                char.IA5String().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
                ),
            ),
            namedtype.NamedType(
                "directoryName",
                Name().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
                ),
            ),
            namedtype.NamedType(
                "uniformResourceIdentifier",
                char.IA5String().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
                ),
            ),
            namedtype.NamedType(
                "iPAddress",
                univ.OctetString().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
                ),
            ),
            namedtype.NamedType(
                "registeredID",
                univ.ObjectIdentifier().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8)
                ),
            ),
        )

    class SubjectAltGeneralNames(univ.SequenceOf):
        componentType = GeneralName()
        sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)


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
        cert_blacklist=None,
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
        if enable_tls and not encrypt_only:
            self._cert_blacklist = self._parse_blacklist_cert(cert_blacklist)
        else:
            self._cert_blacklist = []

    def _parse_crl_cert(self, crl_dir_path):
        if not crl_dir_path:
            raise ValueError("No capath provided to CRL check.")
        try:
            files = [
                path.join(crl_dir_path, f)
                for f in os.listdir(crl_dir_path)
                if path.isfile(path.join(crl_dir_path, f))
            ]
        except Exception:
            raise ValueError("Wrong or empty capath provided to CRL check.")

        crl_checklist = []
        for f in files:
            fs = None
            try:
                fs = open(f, "r").read()
                crl = crypto.load_crl(crypto.FILETYPE_PEM, fs)
                revoked = crl.get_revoked()
                if not revoked:
                    continue
                for r in revoked:
                    try:
                        r_serial = int(r.get_serial(), 16)
                        crl_checklist.append(r_serial)
                    except Exception:
                        pass
            except Exception:
                # Directory can have other files also
                pass
        if crl_checklist:
            return crl_checklist
        else:
            raise ValueError("No valid CRL found at capath")

    def _parse_blacklist_cert(self, file):
        blacklist = []
        try:
            for line in open(file, "r").readlines():
                if not line or not line.strip():
                    continue
                line = line.strip()
                if line.startswith("#"):
                    continue
                tokens = line.split(None, 1)
                serial_number = tokens[0]
                serial_number_int = int(serial_number, 16)
                issuer = None
                if len(tokens) > 1:
                    reminder = tokens[1]
                    if reminder:
                        issuer = self._parse_issuer(reminder.strip())
                blacklist.append((serial_number_int, issuer))
            return blacklist
        except Exception:
            return blacklist

    def _parse_issuer(self, issuer_string):
        components = issuer_string.split("/")
        if not components:
            return None
        comp_list = []
        for c in components:
            if not c or not c.strip():
                continue
            if "=" not in c:
                return None
            key, value = c.split("=")
            try:
                key = key.strip()
                value = value.strip()
            except Exception:
                return None
            comp_list.append((key, value))
        if comp_list:
            comp_list = sorted(comp_list, key=lambda x: x[0])
        else:
            comp_list = None
        return comp_list

    def _verify_none_cb(self, conn, cert, errnum, depth, ok):
        return ok

    def _cert_blacklist_check(self, cert=None):
        if not cert:
            raise ValueError("Empty or no Server Certificate for authentication")
        if not self._cert_blacklist:
            return
        try:
            serial_number = cert.get_serial_number()
            if serial_number is None:
                raise Exception("Wrong Server Certificate: No Serial Number.")
        except Exception:
            raise Exception(
                "Wrong Server Certificate: not able to extract Serial Number."
            )

        try:
            issuer = cert.get_issuer().get_components()
            issuer = sorted(issuer, key=lambda x: x[0])
            if not issuer:
                raise Exception("Wrong Server Certificate: No Issuer Name.")
        except Exception:
            raise Exception("Wrong Server Certificate: not able to extract Issuer.")
        try:
            serial_number_int = int(serial_number)
        except Exception:
            raise Exception(
                "Wrong Server Certificate: not able to extract Serial Number in integer format."
            )
        if (serial_number_int, None) in self._cert_blacklist:
            raise Exception(
                "Server Certificate is in blacklist: (Serial Number: %x)"
                % (serial_number_int)
            )
        if (serial_number_int, issuer) in self._cert_blacklist:
            raise Exception(
                "Server Certificate is in blacklist: (Serial Number: %x, Issuer: %s)"
                % (serial_number_int, str(issuer))
            )

    def _cert_crl_check(self, cert):
        if not cert:
            raise ValueError("empty or no Server Certificate chain for CRL check")
        if not self._crl_checklist:
            return
        try:
            serial_number = cert.get_serial_number()
            if serial_number is None:
                raise Exception("Wrong Server Certificate: No Serial Number.")
        except Exception:
            raise Exception(
                "Wrong Server Certificate: not able to extract Serial Number."
            )

        try:
            serial_number_int = int(serial_number)
        except Exception:
            raise Exception(
                "Wrong Server Certificate: not able to extract Serial Number in integer format."
            )
        if serial_number in self._crl_checklist:
            raise Exception(
                "Server Certificate is in revoked list: (Serial Number: %s)"
                % (str(hex(serial_number_int)))
            )

    def _get_common_names(self, components):
        common_names = []
        if not components:
            return common_names
        for key, value in components:
            if key == "commonName" or key == "CN":
                common_names.append(value)

        return common_names

    def _get_subject_alt_names(self, cert):
        alt_names = []
        for i in range(cert.get_extension_count()):
            e = cert.get_extension(i)
            e_name = util.bytes_to_str(e.get_short_name())
            if e_name == "subjectAltName":
                e_data = e.get_data()
                decoded_data = der_decoder.decode(e_data, SubjectAltGeneralNames())
                for name in decoded_data:
                    if isinstance(name, SubjectAltGeneralNames):
                        for entry in range(len(name)):
                            component = name.getComponentByPosition(entry)
                            alt_names.append(str(component.getComponent()))
        return alt_names

    def _match_tlsname(self, cert, tls_name):
        if not cert:
            raise ValueError(
                "empty or no certificate, match_tlsname needs a "
                "SSL socket or SSL context with either "
                "CERT_OPTIONAL or CERT_REQUIRED"
            )
        try:
            components = []
            for component in cert.get_subject().get_components():
                component_tuple = tuple(util.bytes_to_str(elem) for elem in component)
                components.append(component_tuple)
        except Exception as e:
            raise Exception("Failed to read certificate components: " + str(e))

        cnnames = set()
        for value in self._get_common_names(components):
            try:
                if ssl_util.dnsname_match(value, tls_name):
                    return
            except Exception:
                pass
            cnnames.add(value)

        if HAVE_PYASN1:
            for value in self._get_subject_alt_names(cert):
                try:
                    if ssl_util.dnsname_match(value, tls_name):
                        return
                except Exception:
                    pass
                cnnames.add(value)
        else:
            raise ImportError(
                "No module named pyasn1. It is required for dnsname_match."
            )

        if len(cnnames) > 1:
            raise Exception("Wrong tls_name %r" % tls_name)

        elif len(cnnames) == 1:
            raise Exception("Wrong tls_name %r" % tls_name)

        else:
            raise Exception(
                "no appropriate commonName or subjectAltName fields were found"
            )

    def _verify_cb(self, conn, cert, errnum, depth, ok):
        if depth == 0:
            tls_name = conn.get_app_data()
            self._match_tlsname(cert=cert, tls_name=tls_name)

        self._cert_blacklist_check(cert=cert)
        if self._crl_check_all or (self._crl_check and depth == 0):
            self._cert_crl_check(cert=cert)
        return ok

    def _parse_protocols(self, protocols):
        all_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
        protocols_to_enable = set()
        method = None

        if not protocols:
            try:
                method = SSL.TLSv1_2_METHOD
                protocols_to_enable.add("TLSv1.2")
            except Exception:
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
            # Multiple protocols are enabled
            method = SSL.SSLv23_METHOD
        else:
            if protocols_to_enable[0] == "TLSv1":
                method = SSL.TLSv1_METHOD

            elif protocols_to_enable[0] == "TLSv1.1":
                try:
                    method = SSL.TLSv1_1_METHOD
                except Exception:
                    raise Exception(
                        "No support to protocol TLSv1.1. Wrong OpenSSL or Python version. Please use PyOpenSSL >= 0.15."
                    )

            elif protocols_to_enable[0] == "TLSv1.2":
                try:
                    method = SSL.TLSv1_2_METHOD
                except Exception:
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
        except Exception:
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
            except Exception:
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
                except Exception as e:
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
                except Exception as e:
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
                    except Exception as e:
                        raise Exception(
                            "Invalid keyfile_password {0} \n{1}".format(
                                keyfile_password, e
                            )
                        )

                try:
                    pkey = crypto.load_privatekey(
                        crypto.FILETYPE_PEM,
                        open(keyfile, "rb").read(),
                        util.str_to_bytes(pwd),
                    )
                except IOError:
                    raise Exception("Unable to locate key file {}".format(keyfile))
                except crypto.Error:
                    raise Exception(
                        "Invalid key file or bad passphrase {}".format(keyfile)
                    )
                except Exception as e:
                    raise Exception(
                        "Failed to load private key %s \n %s" % (keyfile, str(e))
                    )

                if pkey is None:
                    raise Exception("Failed to load private key %s" % keyfile)

                try:
                    self.ctx.use_privatekey(pkey)
                except Exception as e:
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
            raise Exception("Bad keyfile_password: not string")

        keyfile_password = keyfile_password.strip()

        if keyfile_password.startswith("env:"):
            # read from environment variable
            try:
                return os.environ[keyfile_password[4:]]
            except Exception as e:
                raise Exception("Failed to read environment variable: {}".format(e))

        if keyfile_password.startswith("file:"):
            # read from file
            file = None

            try:
                file = open(keyfile_password[5:], "r")
                pwd = file.read().strip()
                file.close()
                return pwd

            except Exception as e:
                if file is not None:
                    file.close()
                raise Exception("Failed to read file: {}".format(e))

        return keyfile_password.strip()
