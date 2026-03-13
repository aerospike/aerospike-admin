# Copyright 2025 Aerospike, Inc.
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

import datetime
import ipaddress
import os
import tempfile
import unittest

UTC = datetime.timezone.utc

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from lib.live_cluster.client.ssl_context import SSLContext


def _generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _generate_ca(cn="Test CA", extra_issuer_attrs=None):
    key = _generate_key()
    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if extra_issuer_attrs:
        name_attrs.extend(extra_issuer_attrs)
    name = x509.Name(name_attrs)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(UTC))
        .not_valid_after(datetime.datetime.now(UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _generate_cert(
    ca_key,
    ca_cert,
    cn="test.example.com",
    san_names=None,
    serial_number=None,
    extra_subject_attrs=None,
):
    key = _generate_key()
    subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if extra_subject_attrs:
        subject_attrs.extend(extra_subject_attrs)
    subject = x509.Name(subject_attrs)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial_number or x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(UTC))
        .not_valid_after(datetime.datetime.now(UTC) + datetime.timedelta(days=365))
    )
    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names), critical=False
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _generate_crl(ca_key, ca_cert, revoked_serials=None):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.issuer)
        .last_update(datetime.datetime.now(UTC))
        .next_update(datetime.datetime.now(UTC) + datetime.timedelta(days=30))
    )
    for serial in revoked_serials or []:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(datetime.datetime.now(UTC))
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    return builder.sign(ca_key, hashes.SHA256())


class TestGetSubjectAltNames(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)
        self.ca_key, self.ca_cert = _generate_ca()

    def test_dns_names(self):
        _, cert = _generate_cert(
            self.ca_key,
            self.ca_cert,
            san_names=[
                x509.DNSName("test.example.com"),
                x509.DNSName("*.example.com"),
                x509.DNSName("other.example.org"),
            ],
        )
        alt_names = self.ssl_ctx._get_subject_alt_names(cert)
        self.assertEqual(
            alt_names, ["test.example.com", "*.example.com", "other.example.org"]
        )

    def test_ip_addresses(self):
        _, cert = _generate_cert(
            self.ca_key,
            self.ca_cert,
            san_names=[
                x509.IPAddress(ipaddress.IPv4Address("192.168.1.1")),
                x509.IPAddress(ipaddress.IPv6Address("::1")),
            ],
        )
        alt_names = self.ssl_ctx._get_subject_alt_names(cert)
        self.assertEqual(alt_names, ["192.168.1.1", "::1"])

    def test_mixed_san_types(self):
        _, cert = _generate_cert(
            self.ca_key,
            self.ca_cert,
            san_names=[
                x509.DNSName("test.example.com"),
                x509.IPAddress(ipaddress.IPv4Address("10.0.0.1")),
                x509.RFC822Name("admin@example.com"),
                x509.UniformResourceIdentifier("https://example.com"),
            ],
        )
        alt_names = self.ssl_ctx._get_subject_alt_names(cert)
        self.assertEqual(
            alt_names,
            [
                "test.example.com",
                "10.0.0.1",
                "admin@example.com",
                "https://example.com",
            ],
        )

    def test_no_san_extension(self):
        _, cert = _generate_cert(self.ca_key, self.ca_cert, san_names=None)
        alt_names = self.ssl_ctx._get_subject_alt_names(cert)
        self.assertEqual(alt_names, [])


class TestGetIssuerComponents(unittest.TestCase):
    def test_single_cn(self):
        _, ca_cert = _generate_ca(cn="My CA")
        components = SSLContext._get_issuer_components(ca_cert.issuer)
        self.assertEqual(components, [("CN", "My CA")])

    def test_multiple_attributes_sorted(self):
        _, ca_cert = _generate_ca(
            cn="My CA",
            extra_issuer_attrs=[
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Org"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ],
        )
        components = SSLContext._get_issuer_components(ca_cert.issuer)
        keys = [c[0] for c in components]
        self.assertEqual(sorted(keys), keys)
        self.assertIn(("CN", "My CA"), components)
        self.assertIn(("O", "My Org"), components)
        self.assertIn(("C", "US"), components)


class TestGetCommonNames(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)

    def test_returns_cn_values(self):
        components = [("CN", "test.example.com"), ("O", "My Org")]
        result = self.ssl_ctx._get_common_names(components)
        self.assertEqual(result, ["test.example.com"])

    def test_multiple_cns(self):
        components = [("CN", "first.example.com"), ("CN", "second.example.com")]
        result = self.ssl_ctx._get_common_names(components)
        self.assertEqual(result, ["first.example.com", "second.example.com"])

    def test_no_cn(self):
        components = [("O", "My Org"), ("C", "US")]
        result = self.ssl_ctx._get_common_names(components)
        self.assertEqual(result, [])

    def test_empty_components(self):
        result = self.ssl_ctx._get_common_names([])
        self.assertEqual(result, [])

    def test_none_components(self):
        result = self.ssl_ctx._get_common_names(None)
        self.assertEqual(result, [])


class TestCertBlacklistCheck(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)
        self.ca_key, self.ca_cert = _generate_ca(
            cn="Test CA",
            extra_issuer_attrs=[
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            ],
        )

    def test_no_blacklist(self):
        self.ssl_ctx._cert_blacklist = []
        _, cert = _generate_cert(self.ca_key, self.ca_cert, serial_number=12345)
        self.ssl_ctx._cert_blacklist_check(cert)

    def test_serial_only_match(self):
        _, cert = _generate_cert(self.ca_key, self.ca_cert, serial_number=0xDEAD)
        self.ssl_ctx._cert_blacklist = [(0xDEAD, None)]
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._cert_blacklist_check(cert)
        self.assertIn("blacklist", str(ctx.exception))
        self.assertIn("dead", str(ctx.exception).lower())

    def test_serial_and_issuer_match(self):
        _, cert = _generate_cert(self.ca_key, self.ca_cert, serial_number=0xBEEF)
        issuer_components = SSLContext._get_issuer_components(cert.issuer)
        self.ssl_ctx._cert_blacklist = [(0xBEEF, issuer_components)]
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._cert_blacklist_check(cert)
        self.assertIn("blacklist", str(ctx.exception))

    def test_serial_match_wrong_issuer_passes(self):
        _, cert = _generate_cert(self.ca_key, self.ca_cert, serial_number=0xCAFE)
        self.ssl_ctx._cert_blacklist = [
            (0xCAFE, [("CN", "Different CA"), ("O", "Different Org")])
        ]
        self.ssl_ctx._cert_blacklist_check(cert)

    def test_no_match(self):
        _, cert = _generate_cert(self.ca_key, self.ca_cert, serial_number=0x1234)
        self.ssl_ctx._cert_blacklist = [(0x5678, None)]
        self.ssl_ctx._cert_blacklist_check(cert)

    def test_none_cert_raises(self):
        self.ssl_ctx._cert_blacklist = [(0x1234, None)]
        with self.assertRaises(ValueError):
            self.ssl_ctx._cert_blacklist_check(None)


class TestCertCrlCheck(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)
        self.ca_key, self.ca_cert = _generate_ca()

    def test_revoked_cert(self):
        _, cert = _generate_cert(self.ca_key, self.ca_cert, serial_number=0xABCD)
        self.ssl_ctx._crl_checklist = [0xABCD]
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._cert_crl_check(cert)
        self.assertIn("revoked", str(ctx.exception))

    def test_non_revoked_cert(self):
        _, cert = _generate_cert(self.ca_key, self.ca_cert, serial_number=0x1111)
        self.ssl_ctx._crl_checklist = [0x2222, 0x3333]
        self.ssl_ctx._cert_crl_check(cert)

    def test_empty_crl(self):
        _, cert = _generate_cert(self.ca_key, self.ca_cert, serial_number=0x1234)
        self.ssl_ctx._crl_checklist = []
        self.ssl_ctx._cert_crl_check(cert)

    def test_none_cert_raises(self):
        self.ssl_ctx._crl_checklist = [0x1234]
        with self.assertRaises(ValueError):
            self.ssl_ctx._cert_crl_check(None)


class TestMatchTlsName(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)
        self.ca_key, self.ca_cert = _generate_ca()

    def test_cn_exact_match(self):
        _, cert = _generate_cert(self.ca_key, self.ca_cert, cn="server.example.com")
        self.ssl_ctx._match_tlsname(cert, "server.example.com")

    def test_san_dns_match(self):
        _, cert = _generate_cert(
            self.ca_key,
            self.ca_cert,
            cn="other.example.com",
            san_names=[x509.DNSName("server.example.com")],
        )
        self.ssl_ctx._match_tlsname(cert, "server.example.com")

    def test_san_wildcard_match(self):
        _, cert = _generate_cert(
            self.ca_key,
            self.ca_cert,
            cn="other.example.com",
            san_names=[x509.DNSName("*.example.com")],
        )
        self.ssl_ctx._match_tlsname(cert, "server.example.com")

    def test_no_match_raises(self):
        _, cert = _generate_cert(
            self.ca_key,
            self.ca_cert,
            cn="other.example.com",
            san_names=[x509.DNSName("wrong.example.com")],
        )
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._match_tlsname(cert, "server.example.com")
        self.assertIn("tls_name", str(ctx.exception))

    def test_no_cn_no_san_raises(self):
        key = _generate_key()
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "No CN Org")])
            )
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(UTC))
            .not_valid_after(
                datetime.datetime.now(UTC) + datetime.timedelta(days=365)
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._match_tlsname(cert, "server.example.com")
        self.assertIn("no appropriate commonName", str(ctx.exception))

    def test_none_cert_raises(self):
        with self.assertRaises(ValueError):
            self.ssl_ctx._match_tlsname(None, "server.example.com")


class TestParseCrlCert(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)
        self.ca_key, self.ca_cert = _generate_ca()

    def test_valid_crl_dir(self):
        crl = _generate_crl(self.ca_key, self.ca_cert, revoked_serials=[0x1234, 0x5678])
        crl_pem = crl.public_bytes(serialization.Encoding.PEM)

        with tempfile.TemporaryDirectory() as tmpdir:
            crl_path = os.path.join(tmpdir, "test.crl")
            with open(crl_path, "wb") as f:
                f.write(crl_pem)
            result = self.ssl_ctx._parse_crl_cert(tmpdir)

        self.assertIn(0x1234, result)
        self.assertIn(0x5678, result)

    def test_empty_crl_raises(self):
        crl = _generate_crl(self.ca_key, self.ca_cert, revoked_serials=[])
        crl_pem = crl.public_bytes(serialization.Encoding.PEM)

        with tempfile.TemporaryDirectory() as tmpdir:
            crl_path = os.path.join(tmpdir, "test.crl")
            with open(crl_path, "wb") as f:
                f.write(crl_pem)
            with self.assertRaises(ValueError) as ctx:
                self.ssl_ctx._parse_crl_cert(tmpdir)
            self.assertIn("No valid CRL", str(ctx.exception))

    def test_no_capath_raises(self):
        with self.assertRaises(ValueError):
            self.ssl_ctx._parse_crl_cert(None)

    def test_invalid_dir_raises(self):
        with self.assertRaises(ValueError):
            self.ssl_ctx._parse_crl_cert("/nonexistent/path/12345")

    def test_non_crl_files_skipped(self):
        crl = _generate_crl(self.ca_key, self.ca_cert, revoked_serials=[0xABCD])
        crl_pem = crl.public_bytes(serialization.Encoding.PEM)

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "not_a_crl.txt"), "w") as f:
                f.write("this is not a CRL")
            crl_path = os.path.join(tmpdir, "valid.crl")
            with open(crl_path, "wb") as f:
                f.write(crl_pem)
            result = self.ssl_ctx._parse_crl_cert(tmpdir)

        self.assertIn(0xABCD, result)


class TestParseBlacklistCert(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)

    def test_serial_only(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("DEAD\n")
            f.write("BEEF\n")
            f.flush()
            path = f.name
        try:
            result = self.ssl_ctx._parse_blacklist_cert(path)
            self.assertEqual(result, [(0xDEAD, None), (0xBEEF, None)])
        finally:
            os.unlink(path)

    def test_serial_with_issuer(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("DEAD /CN=Test CA/O=Test Org\n")
            f.flush()
            path = f.name
        try:
            result = self.ssl_ctx._parse_blacklist_cert(path)
            self.assertEqual(len(result), 1)
            serial, issuer = result[0]
            self.assertEqual(serial, 0xDEAD)
            self.assertIsNotNone(issuer)
            self.assertIn(("CN", "Test CA"), issuer)
            self.assertIn(("O", "Test Org"), issuer)
        finally:
            os.unlink(path)

    def test_comments_and_blank_lines_skipped(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# This is a comment\n")
            f.write("\n")
            f.write("ABCD\n")
            f.write("  \n")
            f.flush()
            path = f.name
        try:
            result = self.ssl_ctx._parse_blacklist_cert(path)
            self.assertEqual(result, [(0xABCD, None)])
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        result = self.ssl_ctx._parse_blacklist_cert("/nonexistent/file.txt")
        self.assertEqual(result, [])


class TestParseIssuer(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)

    def test_single_component(self):
        result = self.ssl_ctx._parse_issuer("/CN=Test CA")
        self.assertEqual(result, [("CN", "Test CA")])

    def test_multiple_components_sorted(self):
        result = self.ssl_ctx._parse_issuer("/O=Test Org/CN=Test CA/C=US")
        keys = [c[0] for c in result]
        self.assertEqual(keys, sorted(keys))
        self.assertIn(("CN", "Test CA"), result)
        self.assertIn(("O", "Test Org"), result)
        self.assertIn(("C", "US"), result)

    def test_empty_string(self):
        result = self.ssl_ctx._parse_issuer("")
        self.assertIsNone(result)

    def test_invalid_component_no_equals(self):
        result = self.ssl_ctx._parse_issuer("/invalid")
        self.assertIsNone(result)


class TestReadKeyfilePassword(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)

    def test_none_password(self):
        result = self.ssl_ctx._read_keyfile_password(None)
        self.assertIsNone(result)

    def test_plain_password(self):
        result = self.ssl_ctx._read_keyfile_password("my-password")
        self.assertEqual(result, "my-password")

    def test_password_with_whitespace(self):
        result = self.ssl_ctx._read_keyfile_password("  my-password  ")
        self.assertEqual(result, "my-password")

    def test_env_password(self):
        os.environ["TEST_SSL_PASSWORD"] = "env-password"
        try:
            result = self.ssl_ctx._read_keyfile_password("env:TEST_SSL_PASSWORD")
            self.assertEqual(result, "env-password")
        finally:
            del os.environ["TEST_SSL_PASSWORD"]

    def test_env_password_missing_raises(self):
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._read_keyfile_password("env:NONEXISTENT_VAR_12345")
        self.assertIn("Failed to read environment variable", str(ctx.exception))

    def test_file_password(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("file-password\n")
            f.flush()
            path = f.name
        try:
            result = self.ssl_ctx._read_keyfile_password("file:" + path)
            self.assertEqual(result, "file-password")
        finally:
            os.unlink(path)

    def test_file_password_missing_raises(self):
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._read_keyfile_password("file:/nonexistent/path.txt")
        self.assertIn("Failed to read file", str(ctx.exception))

    def test_non_string_raises(self):
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._read_keyfile_password(12345)
        self.assertIn("not string", str(ctx.exception))


class TestGetCertShortName(unittest.TestCase):
    def test_common_name(self):
        attr = x509.NameAttribute(NameOID.COMMON_NAME, "test")
        self.assertEqual(SSLContext._get_cert_short_name(attr), "CN")

    def test_organization(self):
        attr = x509.NameAttribute(NameOID.ORGANIZATION_NAME, "test")
        self.assertEqual(SSLContext._get_cert_short_name(attr), "O")

    def test_country(self):
        attr = x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
        self.assertEqual(SSLContext._get_cert_short_name(attr), "C")

    def test_locality(self):
        attr = x509.NameAttribute(NameOID.LOCALITY_NAME, "test")
        self.assertEqual(SSLContext._get_cert_short_name(attr), "L")

    def test_state(self):
        attr = x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "test")
        self.assertEqual(SSLContext._get_cert_short_name(attr), "ST")

    def test_org_unit(self):
        attr = x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "test")
        self.assertEqual(SSLContext._get_cert_short_name(attr), "OU")
