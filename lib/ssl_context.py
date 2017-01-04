#!/usr/bin/env python

# Copyright 2013-2017 Aerospike, Inc.
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
#
# The _dnsname_match function is under the terms and
# conditions of the Python Software Foundation License.  It was taken from
# the Python3 standard library and adapted for use in Python2.  See comments in the
# source for which code precisely is under this License.  PSF License text
# follows:
#
# PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2
# --------------------------------------------
#
# 1. This LICENSE AGREEMENT is between the Python Software Foundation
# ("PSF"), and the Individual or Organization ("Licensee") accessing and
# otherwise using this software ("Python") in source or binary form and
# its associated documentation.
#
# 2. Subject to the terms and conditions of this License Agreement, PSF hereby
# grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
# analyze, test, perform and/or display publicly, prepare derivative works,
# distribute, and otherwise use Python alone or in any derivative version,
# provided, however, that PSF's License Agreement and PSF's notice of copyright,
# i.e., "Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
# 2011, 2012, 2013, 2014 Python Software Foundation; All Rights Reserved" are
# retained in Python alone or in any derivative version prepared by Licensee.
#
# 3. In the event Licensee prepares a derivative work that is based on
# or incorporates Python or any part thereof, and wants to make
# the derivative work available to others as provided herein, then
# Licensee hereby agrees to include in any such work a brief summary of
# the changes made to Python.
#
# 4. PSF is making Python available to Licensee on an "AS IS"
# basis.  PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
# IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND
# DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
# FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON WILL NOT
# INFRINGE ANY THIRD PARTY RIGHTS.
#
# 5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
# FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
# A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON,
# OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.
#
# 6. This License Agreement will automatically terminate upon a material
# breach of its terms and conditions.
#
# 7. Nothing in this License Agreement shall be deemed to create any
# relationship of agency, partnership, or joint venture between PSF and
# Licensee.  This License Agreement does not grant permission to use PSF
# trademarks or trade name in a trademark sense to endorse or promote
# products or services of Licensee, or any third party.
#
# 8. By copying, installing or otherwise using Python, Licensee
# agrees to be bound by the terms and conditions of this License
# Agreement.

import re
import warnings
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    from OpenSSL import crypto, SSL
from os import listdir
from os.path import isfile, join

class SSLContext(object):

    def __init__(self, enable_tls=False, encrypt_only=False, cafile=None, capath=None,
                 keyfile=None, certfile=None, protocols=None, cipher_suite=None, cert_blacklist=None,
                 crl_check=False, crl_check_all=False):
        self._create_ssl_context(enable_tls=enable_tls, encrypt_only=encrypt_only, cafile=cafile, capath=capath,
                                 keyfile=keyfile, certfile=certfile, protocols=protocols, cipher_suite=cipher_suite)
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
            files = [join(crl_dir_path, f) for f in listdir(crl_dir_path) if isfile(join(crl_dir_path, f))]
        except Exception:
            raise ValueError("Wrong or empty capath provided to CRL check.")

        crl_checklist = []
        for f in files:
            fs = None
            try:
                fs = open(f, "r").read()
                crl = crypto.load_crl(crypto.FILETYPE_PEM,fs)
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
            for line in open(file, 'r').readlines():
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
                blacklist.append((serial_number_int,issuer))
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
            if not "=" in c:
                return None
            key, value = c.split("=")
            try:
                key = key.strip()
                value = value.strip()
            except Exception:
                return None
            comp_list.append((key,value))
        if comp_list:
            comp_list = sorted(comp_list, key=lambda x : x[0])
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
            raise Exception("Wrong Server Certificate: not able to extract Serial Number.")

        try:
            issuer = cert.get_issuer().get_components()
            issuer = sorted(issuer, key=lambda x : x[0])
            if not issuer:
                raise Exception("Wrong Server Certificate: No Issuer Name.")
        except Exception:
            raise Exception("Wrong Server Certificate: not able to extract Issuer.")
        try:
            serial_number_int = int(serial_number)
        except Exception:
            raise Exception("Wrong Server Certificate: not able to extract Serial Number in integer format.")
        if (serial_number_int,None) in self._cert_blacklist:
            raise Exception("Server Certificate is in blacklist: (Serial Number: %x)"%(serial_number_int))
        if (serial_number_int,issuer) in self._cert_blacklist:
            raise Exception("Server Certificate is in blacklist: (Serial Number: %x, Issuer: %s)"%(serial_number_int, str(issuer)))

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
            raise Exception("Wrong Server Certificate: not able to extract Serial Number.")

        try:
            serial_number_int = int(serial_number)
        except Exception:
            raise Exception("Wrong Server Certificate: not able to extract Serial Number in integer format.")
        if serial_number in self._crl_checklist:
            raise Exception("Server Certificate is in revoked list: (Serial Number: %s)"%(str(hex(serial_number_int))))

    ###
    ### The following block of code is under the terms and conditions of the
    ### Python Software Foundation License
    ###

    def _dnsname_match(self, dn, hostname, max_wildcards=1):
        """Matching according to RFC 6125, section 6.4.3

        http://tools.ietf.org/html/rfc6125#section-6.4.3
        """
        pats = []
        if not dn:
            return False

        p = dn.split(r'.')
        leftmost = p[0]
        remainder = p[1:]
        wildcards = leftmost.count('*')
        if wildcards > max_wildcards:
            # Issue #17980: avoid denials of service by refusing more
            # than one wildcard per fragment.  A survery of established
            # policy among SSL implementations showed it to be a
            # reasonable choice.
            raise Exception("too many wildcards in certificate Subject: " + repr(dn))

        # speed up common case w/o wildcards
        if not wildcards:
            return dn.lower() == hostname.lower()

        # RFC 6125, section 6.4.3, subitem 1.
        # The client SHOULD NOT attempt to match a presented identifier in which
        # the wildcard character comprises a label other than the left-most label.
        if leftmost == '*':
            # When '*' is a fragment by itself, it matches a non-empty dotless
            # fragment.
            pats.append('[^.]+')
        elif leftmost.startswith('xn--') or hostname.startswith('xn--'):
            # RFC 6125, section 6.4.3, subitem 3.
            # The client SHOULD NOT attempt to match a presented identifier
            # where the wildcard character is embedded within an A-label or
            # U-label of an internationalized domain name.
            pats.append(re.escape(leftmost))
        else:
            # Otherwise, '*' matches any dotless string, e.g. www*
            pats.append(re.escape(leftmost).replace(r'\*', '[^.]*'))

        # add the remaining fragments, ignore any wildcards
        for frag in remainder:
            pats.append(re.escape(frag))

        pat = re.compile(r'\A' + r'\.'.join(pats) + r'\Z', re.IGNORECASE)
        return pat.match(hostname)

    ###
    ### End of Python Software Foundation Licensed code
    ###

    def _get_common_names(self, components):
        common_names = []
        if not components:
            return common_names
        for key, value in components:
            if key == 'commonName' or key == 'CN':
                common_names.append(value)

        return common_names

    def _match_tlsname(self, cert, tls_name):
        if not cert:
            raise ValueError("empty or no certificate, match_tlsname needs a "
                             "SSL socket or SSL context with either "
                             "CERT_OPTIONAL or CERT_REQUIRED")
        try:
            components = cert.get_subject().get_components()
        except Exception:
            raise ("Wrong peer certificate for match_tlsname.")
        cnnames = []
        for value in self._get_common_names(components):
            try:
                if self._dnsname_match(value, tls_name):
                    return
            except Exception:
                pass
            cnnames.append(value)
        if len(cnnames) > 1:
            raise Exception("tls_name %r doesn't match either of %s"% (tls_name, ', '.join(map(repr, cnnames))))
        elif len(cnnames) == 1:
            raise Exception("tls_name %r  doesn't match %r"% (tls_name, cnnames[0]))
        else:
            raise Exception("no appropriate commonName or subjectAltName fields were found")

    def _verify_cb(self, conn, cert, errnum, depth, ok):
        if depth == 0:
            tls_name = conn.get_app_data()
            self._match_tlsname(cert=cert, tls_name=tls_name)
        self._cert_blacklist_check(cert=cert)
        if self._crl_check_all or (self._crl_check and depth == 0):
            self._cert_crl_check(cert=cert)
        return ok

    def _parse_protocols(self, protocols):
        protocols_to_disable = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"]
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
                    if proto == "SSLv3" or proto == "+SSLv3":
                        protocols_to_enable.add("SSLv3")
                    elif proto == "-SSLv3":
                        protocols_to_enable.remove("SSLv3")
                    elif proto == "TLSv1" or proto == "+TLSv1":
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
                        protocols_to_enable.add("SSLv3")
                        protocols_to_enable.add("TLSv1")
                        protocols_to_enable.add("TLSv1.1")
                        protocols_to_enable.add("TLSv1.2")
                    elif proto == "-all":
                        protocols_to_enable.clear()
                    elif proto == "SSLv2" or proto == "+SSLv2":
                        raise Exception("Protocol SSLv2 not supported (RFC 6176)")
                    elif proto == "-SSLv2":
                        continue
                    else:
                        raise Exception("Wrong protocol entry %s"%(str(proto)))
                except KeyError:
                    pass
        if not protocols_to_enable:
            raise Exception("Wrong protocol entries")
        protocols_to_enable = list(protocols_to_enable)
        if len(protocols_to_enable)>1:
            # Multiple protocols are enabled
            method = SSL.SSLv23_METHOD
        else:
            if protocols_to_enable[0] == "SSLv3":
                method = SSL.SSLv3_METHOD
            elif protocols_to_enable[0] == "TLSv1":
                method = SSL.TLSv1_METHOD
            elif protocols_to_enable[0] == "TLSv1.1":
                try:
                    method = SSL.TLSv1_1_METHOD
                except Exception:
                    raise Exception("No support to protocol %s. Wrong OpenSSL or Python version. Please use Python-2.7.13."%("TLSv1.1"))
            elif protocols_to_enable[0] == "TLSv1.2":
                try:
                    method = SSL.TLSv1_2_METHOD
                except Exception:
                    raise Exception("No support to protocol %s. Wrong OpenSSL or Python version. Please use Python-2.7.13."%("TLSv1.2"))
        protocols_to_disable = list(set(protocols_to_disable) - set(protocols_to_enable))
        return method, protocols_to_disable

    def _set_context_options(self, ctx, protocols_to_disable):
        if not protocols_to_disable:
            return ctx
        for proto in protocols_to_disable:
            try:
                if proto == "SSLv2":
                    ctx.set_options(SSL.OP_NO_SSLv2)
                elif proto == "SSLv3":
                    ctx.set_options(SSL.OP_NO_SSLv3)
                elif proto == "TLSv1":
                    ctx.set_options(SSL.OP_NO_TLSv1)
                elif proto == "TLSv1.1":
                    ctx.set_options(SSL.OP_NO_TLSv1_1)
                elif proto == "TLSv1.2":
                    ctx.set_options(SSL.OP_NO_TLSv1_2)
            except Exception:
                pass
        return ctx

    def _create_ssl_context(self, enable_tls=False, encrypt_only=False, cafile=None, capath=None,
                           keyfile=None, certfile=None, protocols=None, cipher_suite=None):
        self.ctx = None
        if not enable_tls:
            return
        method, protocols_to_disable = self._parse_protocols(protocols)
        self.ctx = SSL.Context(method)
        self.ctx = self._set_context_options(self.ctx, protocols_to_disable)
        if encrypt_only:
            self.ctx.set_verify(SSL.VERIFY_NONE, self._verify_none_cb)
        else:
            self.ctx.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_CLIENT_ONCE, self._verify_cb)
            if cafile or capath:
                self.ctx.load_verify_locations(cafile, capath)
            if certfile:
                self.ctx.use_certificate_chain_file(certfile)
            if keyfile:
                self.ctx.use_privatekey_file(keyfile)
        if cipher_suite:
            self.ctx.set_cipher_list(cipher_suite)