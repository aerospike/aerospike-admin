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
import types
import unittest
import unittest.mock
from unittest.mock import patch

UTC = datetime.timezone.utc

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto, SSL

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
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
            .not_valid_after(datetime.datetime.now(UTC) + datetime.timedelta(days=365))
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
        with self.assertRaises(KeyError) as ctx:
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
        with self.assertRaises(OSError) as ctx:
            self.ssl_ctx._read_keyfile_password("file:/nonexistent/path.txt")
        self.assertIn("Failed to read file", str(ctx.exception))

    def test_non_string_raises(self):
        with self.assertRaises(TypeError) as ctx:
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


class TestParseProtocols(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_default_none_uses_tlsv1_2(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols(None)
        self.assertEqual(method, "TLSv1_2_METHOD")
        self.assertNotIn("TLSv1.2", disabled)

    def test_default_fallback_to_tlsv1(self):
        fake_ssl = types.SimpleNamespace(TLSv1_METHOD="TLSv1_METHOD")
        with patch("lib.live_cluster.client.ssl_context.SSL", new=fake_ssl):
            method, disabled = self.ssl_ctx._parse_protocols(None)
        self.assertEqual(method, "TLSv1_METHOD")
        self.assertNotIn("TLSv1", disabled)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_single_tlsv1(self, mock_ssl):
        mock_ssl.TLSv1_METHOD = "TLSv1_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols("TLSv1")
        self.assertEqual(method, "TLSv1_METHOD")
        self.assertIn("TLSv1.1", disabled)
        self.assertIn("TLSv1.2", disabled)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_single_tlsv1_1(self, mock_ssl):
        mock_ssl.TLSv1_1_METHOD = "TLSv1_1_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols("TLSv1.1")
        self.assertEqual(method, "TLSv1_1_METHOD")
        self.assertIn("TLSv1", disabled)
        self.assertIn("TLSv1.2", disabled)

    def test_single_tlsv1_1_no_support_raises(self):
        fake_ssl = types.SimpleNamespace()
        with patch("lib.live_cluster.client.ssl_context.SSL", new=fake_ssl):
            with self.assertRaises(Exception) as ctx:
                self.ssl_ctx._parse_protocols("TLSv1.1")
        self.assertIn("No support to protocol TLSv1.1", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_single_tlsv1_2(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols("TLSv1.2")
        self.assertEqual(method, "TLSv1_2_METHOD")
        self.assertIn("TLSv1", disabled)
        self.assertIn("TLSv1.1", disabled)

    def test_single_tlsv1_2_no_support_raises(self):
        fake_ssl = types.SimpleNamespace()
        with patch("lib.live_cluster.client.ssl_context.SSL", new=fake_ssl):
            with self.assertRaises(Exception) as ctx:
                self.ssl_ctx._parse_protocols("TLSv1.2")
        self.assertIn("No support to protocol TLSv1.2", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_plus_prefix(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols("+TLSv1.2")
        self.assertEqual(method, "TLSv1_2_METHOD")

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_multiple_protocols_uses_sslv23(self, mock_ssl):
        mock_ssl.SSLv23_METHOD = "SSLv23_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols("TLSv1 TLSv1.2")
        self.assertEqual(method, "SSLv23_METHOD")
        self.assertIn("TLSv1.1", disabled)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_all_keyword(self, mock_ssl):
        mock_ssl.SSLv23_METHOD = "SSLv23_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols("all")
        self.assertEqual(method, "SSLv23_METHOD")
        self.assertEqual(disabled, [])

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_minus_all_then_add(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols("-all TLSv1.2")
        self.assertEqual(method, "TLSv1_2_METHOD")

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_minus_all_alone_raises(self, mock_ssl):
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._parse_protocols("-all")
        self.assertIn("Wrong protocol entries", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_sslv2_raises(self, mock_ssl):
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._parse_protocols("SSLv2")
        self.assertIn("SSLv2 not supported", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_minus_sslv2_ignored(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols("-SSLv2 TLSv1.2")
        self.assertEqual(method, "TLSv1_2_METHOD")

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_sslv3_raises(self, mock_ssl):
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._parse_protocols("SSLv3")
        self.assertIn("SSLv3 not supported", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_minus_sslv3_ignored(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols("-SSLv3 TLSv1.2")
        self.assertEqual(method, "TLSv1_2_METHOD")

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_invalid_protocol_raises(self, mock_ssl):
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._parse_protocols("INVALID")
        self.assertIn("Wrong protocol entry", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_remove_before_add_silently_ignored(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols("-TLSv1 TLSv1.2")
        self.assertEqual(method, "TLSv1_2_METHOD")

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_add_then_remove(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        method, disabled = self.ssl_ctx._parse_protocols("TLSv1 TLSv1.2 -TLSv1")
        self.assertEqual(method, "TLSv1_2_METHOD")
        self.assertIn("TLSv1", disabled)


class TestSetContextOptions(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_always_disables_sslv2_and_sslv3(self, mock_ssl):
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        result = self.ssl_ctx._set_context_options(mock_ctx, [])
        mock_ctx.set_options.assert_any_call(0x01000000)
        mock_ctx.set_options.assert_any_call(0x02000000)
        self.assertEqual(result, mock_ctx)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_disables_tlsv1(self, mock_ssl):
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ssl.OP_NO_TLSv1 = 0x04000000
        mock_ctx = unittest.mock.MagicMock()
        result = self.ssl_ctx._set_context_options(mock_ctx, ["TLSv1"])
        mock_ctx.set_options.assert_any_call(0x04000000)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_disables_multiple_protocols(self, mock_ssl):
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ssl.OP_NO_TLSv1 = 0x04000000
        mock_ssl.OP_NO_TLSv1_1 = 0x10000000
        mock_ctx = unittest.mock.MagicMock()
        self.ssl_ctx._set_context_options(mock_ctx, ["TLSv1", "TLSv1.1"])
        mock_ctx.set_options.assert_any_call(0x04000000)
        mock_ctx.set_options.assert_any_call(0x10000000)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_empty_disable_list_returns_ctx(self, mock_ssl):
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        result = self.ssl_ctx._set_context_options(mock_ctx, [])
        self.assertEqual(result, mock_ctx)


class TestVerifyCb(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)
        self.ca_key, self.ca_cert = _generate_ca(
            cn="Test CA",
            extra_issuer_attrs=[
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            ],
        )
        self.ssl_ctx._crl_checklist = []
        self.ssl_ctx._crl_check = False
        self.ssl_ctx._crl_check_all = False

    def _make_mock_conn_and_cert(self, tls_name="test.example.com", serial=0x1234):
        _, cert = _generate_cert(
            self.ca_key,
            self.ca_cert,
            cn=tls_name,
            serial_number=serial,
        )
        mock_pyopenssl_cert = unittest.mock.MagicMock()
        mock_pyopenssl_cert.to_cryptography.return_value = cert
        mock_conn = unittest.mock.MagicMock()
        mock_conn.get_app_data.return_value = tls_name
        return mock_conn, mock_pyopenssl_cert

    def test_depth_zero_calls_match_tlsname(self):
        conn, cert = self._make_mock_conn_and_cert()
        result = self.ssl_ctx._verify_cb(conn, cert, 0, 0, True)
        self.assertTrue(result)
        conn.get_app_data.assert_called_once()

    def test_depth_nonzero_skips_match_tlsname(self):
        conn, cert = self._make_mock_conn_and_cert()
        result = self.ssl_ctx._verify_cb(conn, cert, 0, 1, True)
        self.assertTrue(result)
        conn.get_app_data.assert_not_called()

    def test_crl_check_at_depth_zero(self):
        conn, cert = self._make_mock_conn_and_cert(serial=0xABCD)
        self.ssl_ctx._crl_check = True
        self.ssl_ctx._crl_checklist = [0xABCD]
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._verify_cb(conn, cert, 0, 0, True)
        self.assertIn("revoked", str(ctx.exception))

    def test_crl_check_skipped_at_nonzero_depth(self):
        conn, cert = self._make_mock_conn_and_cert(serial=0xABCD)
        self.ssl_ctx._crl_check = True
        self.ssl_ctx._crl_checklist = [0xABCD]
        result = self.ssl_ctx._verify_cb(conn, cert, 0, 2, True)
        self.assertTrue(result)

    def test_crl_check_all_checks_at_any_depth(self):
        conn, cert = self._make_mock_conn_and_cert(serial=0xABCD)
        self.ssl_ctx._crl_check_all = True
        self.ssl_ctx._crl_checklist = [0xABCD]
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._verify_cb(conn, cert, 0, 5, True)
        self.assertIn("revoked", str(ctx.exception))

    def test_returns_ok_parameter(self):
        conn, cert = self._make_mock_conn_and_cert()
        self.assertTrue(self.ssl_ctx._verify_cb(conn, cert, 0, 1, True))
        self.assertFalse(self.ssl_ctx._verify_cb(conn, cert, 0, 1, False))


class TestCreateSSLContext(unittest.TestCase):
    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_disabled_tls_returns_early(self, mock_ssl):
        ssl_ctx = SSLContext.__new__(SSLContext)
        ssl_ctx._create_ssl_context(enable_tls=False)
        mock_ssl.Context.assert_not_called()

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_encrypt_only_sets_verify_none(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_NONE = 0
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        ssl_ctx = SSLContext.__new__(SSLContext)
        ssl_ctx._create_ssl_context(enable_tls=True, encrypt_only=True)
        mock_ctx.set_verify.assert_called_once()
        args = mock_ctx.set_verify.call_args[0]
        self.assertEqual(args[0], 0)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_full_auth_sets_verify_peer(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        ssl_ctx = SSLContext.__new__(SSLContext)
        ssl_ctx._create_ssl_context(enable_tls=True, encrypt_only=False)
        mock_ctx.set_verify.assert_called_once()
        args = mock_ctx.set_verify.call_args[0]
        self.assertEqual(args[0], 1 | 2)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_loads_ca_file(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        ssl_ctx = SSLContext.__new__(SSLContext)
        ssl_ctx._create_ssl_context(
            enable_tls=True, encrypt_only=False, cafile="/tmp/ca.pem"
        )
        mock_ctx.load_verify_locations.assert_called_once_with("/tmp/ca.pem", None)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_loads_ca_path(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        ssl_ctx = SSLContext.__new__(SSLContext)
        ssl_ctx._create_ssl_context(
            enable_tls=True, encrypt_only=False, capath="/tmp/ca_dir"
        )
        mock_ctx.load_verify_locations.assert_called_once_with(None, "/tmp/ca_dir")

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_bad_ca_file_raises(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ctx.load_verify_locations.side_effect = crypto.Error([("", "", "bad cert")])
        mock_ssl.Context.return_value = mock_ctx
        ssl_ctx = SSLContext.__new__(SSLContext)
        with self.assertRaises(Exception) as ctx:
            ssl_ctx._create_ssl_context(
                enable_tls=True, encrypt_only=False, cafile="/bad/ca.pem"
            )
        self.assertIn("Failed to load CA certificate", str(ctx.exception))
        self.assertIn("cafile=/bad/ca.pem", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_bad_ca_path_raises_with_capath(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ctx.load_verify_locations.side_effect = crypto.Error([("", "", "bad path")])
        mock_ssl.Context.return_value = mock_ctx
        ssl_ctx = SSLContext.__new__(SSLContext)
        with self.assertRaises(Exception) as ctx:
            ssl_ctx._create_ssl_context(
                enable_tls=True, encrypt_only=False, capath="/bad/dir"
            )
        self.assertIn("capath=/bad/dir", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_bad_ca_with_both_cafile_and_capath(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ctx.load_verify_locations.side_effect = crypto.Error([("", "", "bad")])
        mock_ssl.Context.return_value = mock_ctx
        ssl_ctx = SSLContext.__new__(SSLContext)
        with self.assertRaises(Exception) as ctx:
            ssl_ctx._create_ssl_context(
                enable_tls=True,
                encrypt_only=False,
                cafile="/ca.pem",
                capath="/ca_dir",
            )
        msg = str(ctx.exception)
        self.assertIn("cafile=/ca.pem", msg)
        self.assertIn("capath=/ca_dir", msg)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_loads_certfile(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        ssl_ctx = SSLContext.__new__(SSLContext)
        ssl_ctx._create_ssl_context(
            enable_tls=True, encrypt_only=False, certfile="/tmp/cert.pem"
        )
        mock_ctx.use_certificate_chain_file.assert_called_once_with("/tmp/cert.pem")

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_bad_certfile_raises(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ctx.use_certificate_chain_file.side_effect = crypto.Error(
            [("", "", "bad cert")]
        )
        mock_ssl.Context.return_value = mock_ctx
        ssl_ctx = SSLContext.__new__(SSLContext)
        with self.assertRaises(Exception) as ctx:
            ssl_ctx._create_ssl_context(
                enable_tls=True, encrypt_only=False, certfile="/bad/cert.pem"
            )
        self.assertIn("Failed to load certificate chain file", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.SSL")
    @patch("lib.live_cluster.client.ssl_context.load_pem_private_key")
    @patch("lib.live_cluster.client.ssl_context.crypto")
    def test_loads_keyfile(self, mock_crypto, mock_load_key, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        mock_pkey = unittest.mock.MagicMock()
        mock_crypto.PKey.from_cryptography_key.return_value = mock_pkey
        key = _generate_key()
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(key_pem)
            keypath = f.name
        try:
            ssl_ctx = SSLContext.__new__(SSLContext)
            ssl_ctx._create_ssl_context(
                enable_tls=True, encrypt_only=False, keyfile=keypath
            )
            mock_ctx.use_privatekey.assert_called_once_with(mock_pkey)
        finally:
            os.unlink(keypath)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    @patch("lib.live_cluster.client.ssl_context.load_pem_private_key")
    @patch("lib.live_cluster.client.ssl_context.crypto")
    def test_keyfile_with_password(self, mock_crypto, mock_load_key, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        mock_pkey = unittest.mock.MagicMock()
        mock_crypto.PKey.from_cryptography_key.return_value = mock_pkey
        key = _generate_key()
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(key_pem)
            keypath = f.name
        try:
            ssl_ctx = SSLContext.__new__(SSLContext)
            ssl_ctx._create_ssl_context(
                enable_tls=True,
                encrypt_only=False,
                keyfile=keypath,
                keyfile_password="secret",
            )
            _, kwargs = mock_load_key.call_args
            self.assertEqual(kwargs["password"], b"secret")
        finally:
            os.unlink(keypath)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    @patch(
        "lib.live_cluster.client.ssl_context.load_pem_private_key",
        side_effect=IOError("not found"),
    )
    def test_keyfile_not_found_raises(self, mock_load_key, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        ssl_ctx = SSLContext.__new__(SSLContext)
        with self.assertRaises(Exception) as ctx:
            ssl_ctx._create_ssl_context(
                enable_tls=True, encrypt_only=False, keyfile="/missing/key.pem"
            )
        self.assertIn("Unable to locate key file", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.SSL")
    @patch(
        "lib.live_cluster.client.ssl_context.load_pem_private_key",
        side_effect=ValueError("bad key"),
    )
    def test_invalid_keyfile_raises(self, mock_load_key, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(b"not a real key")
            keypath = f.name
        try:
            ssl_ctx = SSLContext.__new__(SSLContext)
            with self.assertRaises(Exception) as ctx:
                ssl_ctx._create_ssl_context(
                    enable_tls=True, encrypt_only=False, keyfile=keypath
                )
            self.assertIn("Invalid key file or bad passphrase", str(ctx.exception))
        finally:
            os.unlink(keypath)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    @patch(
        "lib.live_cluster.client.ssl_context.load_pem_private_key",
        side_effect=TypeError("bad type"),
    )
    def test_bad_passphrase_type_error_raises(self, mock_load_key, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(b"dummy")
            keypath = f.name
        try:
            ssl_ctx = SSLContext.__new__(SSLContext)
            with self.assertRaises(Exception) as ctx:
                ssl_ctx._create_ssl_context(
                    enable_tls=True, encrypt_only=False, keyfile=keypath
                )
            self.assertIn("Invalid key file or bad passphrase", str(ctx.exception))
        finally:
            os.unlink(keypath)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    @patch("lib.live_cluster.client.ssl_context.load_pem_private_key")
    @patch("lib.live_cluster.client.ssl_context.crypto")
    def test_use_privatekey_failure_raises(self, mock_crypto, mock_load_key, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ssl.Error = SSL.Error
        mock_ctx = unittest.mock.MagicMock()
        mock_ctx.use_privatekey.side_effect = SSL.Error([("", "", "ctx reject")])
        mock_ssl.Context.return_value = mock_ctx
        mock_crypto.PKey.from_cryptography_key.return_value = unittest.mock.MagicMock()
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(b"dummy")
            keypath = f.name
        try:
            ssl_ctx = SSLContext.__new__(SSLContext)
            with self.assertRaises(Exception) as ctx:
                ssl_ctx._create_ssl_context(
                    enable_tls=True, encrypt_only=False, keyfile=keypath
                )
            self.assertIn("Failed to load private key", str(ctx.exception))
        finally:
            os.unlink(keypath)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    @patch("lib.live_cluster.client.ssl_context.load_pem_private_key")
    @patch("lib.live_cluster.client.ssl_context.crypto")
    def test_null_pkey_raises(self, mock_crypto, mock_load_key, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        mock_crypto.PKey.from_cryptography_key.return_value = None
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(b"dummy")
            keypath = f.name
        try:
            ssl_ctx = SSLContext.__new__(SSLContext)
            with self.assertRaises(Exception) as ctx:
                ssl_ctx._create_ssl_context(
                    enable_tls=True, encrypt_only=False, keyfile=keypath
                )
            self.assertIn("Failed to load private key", str(ctx.exception))
        finally:
            os.unlink(keypath)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_cipher_suite_set(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        ssl_ctx = SSLContext.__new__(SSLContext)
        ssl_ctx._create_ssl_context(
            enable_tls=True, encrypt_only=True, cipher_suite="AES256-SHA"
        )
        mock_ctx.set_cipher_list.assert_called_once_with("AES256-SHA")

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_invalid_keyfile_password_raises(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(b"dummy")
            keypath = f.name
        try:
            ssl_ctx = SSLContext.__new__(SSLContext)
            with self.assertRaises(Exception) as ctx:
                ssl_ctx._create_ssl_context(
                    enable_tls=True,
                    encrypt_only=False,
                    keyfile=keypath,
                    keyfile_password=12345,
                )
            self.assertIn("Invalid keyfile_password", str(ctx.exception))
        finally:
            os.unlink(keypath)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    @patch("lib.live_cluster.client.ssl_context.load_pem_private_key")
    @patch("lib.live_cluster.client.ssl_context.crypto")
    def test_keyfile_password_from_env(self, mock_crypto, mock_load_key, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        mock_crypto.PKey.from_cryptography_key.return_value = unittest.mock.MagicMock()
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(b"dummy")
            keypath = f.name
        os.environ["_TEST_SSL_KEY_PWD"] = "env-secret"
        try:
            ssl_ctx = SSLContext.__new__(SSLContext)
            ssl_ctx._create_ssl_context(
                enable_tls=True,
                encrypt_only=False,
                keyfile=keypath,
                keyfile_password="env:_TEST_SSL_KEY_PWD",
            )
            _, kwargs = mock_load_key.call_args
            self.assertEqual(kwargs["password"], b"env-secret")
        finally:
            del os.environ["_TEST_SSL_KEY_PWD"]
            os.unlink(keypath)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    @patch("lib.live_cluster.client.ssl_context.load_pem_private_key")
    @patch("lib.live_cluster.client.ssl_context.crypto")
    def test_generic_load_key_exception_raises(
        self, mock_crypto, mock_load_key, mock_ssl
    ):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ssl.Context.return_value = mock_ctx
        mock_crypto.Error = crypto.Error
        mock_load_key.side_effect = crypto.Error([("", "", "unexpected")])
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(b"dummy")
            keypath = f.name
        try:
            ssl_ctx = SSLContext.__new__(SSLContext)
            with self.assertRaises(Exception) as ctx:
                ssl_ctx._create_ssl_context(
                    enable_tls=True, encrypt_only=False, keyfile=keypath
                )
            self.assertIn("Failed to load private key", str(ctx.exception))
        finally:
            os.unlink(keypath)


class TestSSLContextInit(unittest.TestCase):
    def test_tls_disabled_ctx_is_none(self):
        ctx = SSLContext(enable_tls=False)
        self.assertIsNone(ctx.ctx)

    @patch("lib.live_cluster.client.ssl_context.HAVE_PYOPENSSL", False)
    def test_no_pyopenssl_raises(self):
        with self.assertRaises(ImportError) as ctx:
            SSLContext(enable_tls=True)
        self.assertIn("pyOpenSSL", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_encrypt_only_skips_crl(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_NONE = 0
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ssl.Context.return_value = unittest.mock.MagicMock()
        ctx = SSLContext(
            enable_tls=True,
            encrypt_only=True,
            crl_check=True,
        )
        self.assertEqual(ctx._crl_checklist, [])

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_full_auth_no_crl(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ssl.Context.return_value = unittest.mock.MagicMock()
        ctx = SSLContext(enable_tls=True, encrypt_only=False)
        self.assertEqual(ctx._crl_checklist, [])

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_full_auth_with_crl_check(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ssl.Context.return_value = unittest.mock.MagicMock()
        ca_key, ca_cert = _generate_ca()
        crl = _generate_crl(ca_key, ca_cert, revoked_serials=[0x1111, 0x2222])
        crl_pem = crl.public_bytes(serialization.Encoding.PEM)
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "crl.pem"), "wb") as f:
                f.write(crl_pem)
            ctx = SSLContext(
                enable_tls=True,
                encrypt_only=False,
                capath=tmpdir,
                crl_check=True,
            )
            self.assertIn(0x1111, ctx._crl_checklist)
            self.assertIn(0x2222, ctx._crl_checklist)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_full_auth_with_crl_check_all(self, mock_ssl):
        mock_ssl.TLSv1_2_METHOD = "TLSv1_2_METHOD"
        mock_ssl.VERIFY_PEER = 1
        mock_ssl.VERIFY_CLIENT_ONCE = 2
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ssl.Context.return_value = unittest.mock.MagicMock()
        ca_key, ca_cert = _generate_ca()
        crl = _generate_crl(ca_key, ca_cert, revoked_serials=[0x3333])
        crl_pem = crl.public_bytes(serialization.Encoding.PEM)
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "crl.pem"), "wb") as f:
                f.write(crl_pem)
            ctx = SSLContext(
                enable_tls=True,
                encrypt_only=False,
                capath=tmpdir,
                crl_check_all=True,
            )
            self.assertIn(0x3333, ctx._crl_checklist)


class TestMatchTlsNameEdgeCases(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)
        self.ca_key, self.ca_cert = _generate_ca()

    def test_cn_mismatch_single_name_raises(self):
        _, cert = _generate_cert(self.ca_key, self.ca_cert, cn="other.example.com")
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._match_tlsname(cert, "wrong.example.com")
        self.assertIn("tls_name", str(ctx.exception))

    def test_multiple_names_no_match_raises(self):
        _, cert = _generate_cert(
            self.ca_key,
            self.ca_cert,
            cn="first.example.com",
            san_names=[x509.DNSName("second.example.com")],
        )
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._match_tlsname(cert, "third.example.com")
        self.assertIn("tls_name", str(ctx.exception))

    def test_san_ip_no_dns_match_raises(self):
        _, cert = _generate_cert(
            self.ca_key,
            self.ca_cert,
            cn="nomatch.example.com",
            san_names=[x509.IPAddress(ipaddress.IPv4Address("10.0.0.1"))],
        )
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._match_tlsname(cert, "wrong.example.com")
        self.assertIn("tls_name", str(ctx.exception))

    def test_subject_read_failure_raises(self):
        fake_cert = types.SimpleNamespace()
        with self.assertRaises(ValueError) as ctx:
            self.ssl_ctx._match_tlsname(fake_cert, "test.example.com")
        self.assertIn("Failed to read certificate components", str(ctx.exception))


class TestParseCrlCertEdgeCases(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)
        self.ca_key, self.ca_cert = _generate_ca()

    def test_multiple_crl_files(self):
        crl1 = _generate_crl(self.ca_key, self.ca_cert, revoked_serials=[0x1111])
        crl2 = _generate_crl(self.ca_key, self.ca_cert, revoked_serials=[0x2222])
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "crl1.pem"), "wb") as f:
                f.write(crl1.public_bytes(serialization.Encoding.PEM))
            with open(os.path.join(tmpdir, "crl2.pem"), "wb") as f:
                f.write(crl2.public_bytes(serialization.Encoding.PEM))
            result = self.ssl_ctx._parse_crl_cert(tmpdir)
        self.assertIn(0x1111, result)
        self.assertIn(0x2222, result)

    def test_dir_with_only_invalid_files_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "garbage.txt"), "w") as f:
                f.write("not a CRL at all")
            with self.assertRaises(ValueError) as ctx:
                self.ssl_ctx._parse_crl_cert(tmpdir)
            self.assertIn("No valid CRL", str(ctx.exception))

    def test_empty_dir_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ValueError) as ctx:
                self.ssl_ctx._parse_crl_cert(tmpdir)
            self.assertIn("No valid CRL", str(ctx.exception))

    def test_crl_with_many_revoked_certs(self):
        serials = list(range(100, 200))
        crl = _generate_crl(self.ca_key, self.ca_cert, revoked_serials=serials)
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "big_crl.pem"), "wb") as f:
                f.write(crl.public_bytes(serialization.Encoding.PEM))
            result = self.ssl_ctx._parse_crl_cert(tmpdir)
        for s in serials:
            self.assertIn(s, result)


class TestCertCrlCheckEdgeCases(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)

    def test_none_serial_number_raises(self):
        mock_cert = unittest.mock.MagicMock()
        mock_cert.serial_number = None
        self.ssl_ctx._crl_checklist = [0x1234]
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._cert_crl_check(mock_cert)
        self.assertIn("No Serial Number", str(ctx.exception))


class TestSetContextOptionsEdgeCases(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)

    @patch("lib.live_cluster.client.ssl_context.SSL")
    def test_sslv2_sslv3_disable_exception_swallowed(self, mock_ssl):
        mock_ssl.OP_NO_SSLv2 = 0x01000000
        mock_ssl.OP_NO_SSLv3 = 0x02000000
        mock_ctx = unittest.mock.MagicMock()
        mock_ctx.set_options.side_effect = AttributeError("no SSLv2 support")
        result = self.ssl_ctx._set_context_options(mock_ctx, [])
        self.assertEqual(result, mock_ctx)


class TestGetSubjectAltNamesEdgeCases(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)
        self.ca_key, self.ca_cert = _generate_ca()

    def test_directory_name_san(self):
        _, cert = _generate_cert(
            self.ca_key,
            self.ca_cert,
            san_names=[
                x509.DirectoryName(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dir-test")])
                ),
            ],
        )
        alt_names = self.ssl_ctx._get_subject_alt_names(cert)
        self.assertEqual(len(alt_names), 1)


class TestMatchTlsNameDnsMatchExceptions(unittest.TestCase):
    def setUp(self):
        self.ssl_ctx = SSLContext.__new__(SSLContext)
        self.ca_key, self.ca_cert = _generate_ca()

    @patch("lib.live_cluster.client.ssl_context.ssl_util")
    def test_cn_dnsname_match_exception_swallowed(self, mock_ssl_util):
        mock_ssl_util.dnsname_match.side_effect = Exception("too many wildcards")
        _, cert = _generate_cert(self.ca_key, self.ca_cert, cn="*.*.example.com")
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._match_tlsname(cert, "a.b.example.com")
        self.assertIn("tls_name", str(ctx.exception))

    @patch("lib.live_cluster.client.ssl_context.ssl_util")
    def test_san_dnsname_match_exception_swallowed(self, mock_ssl_util):
        mock_ssl_util.dnsname_match.side_effect = Exception("too many wildcards")
        _, cert = _generate_cert(
            self.ca_key,
            self.ca_cert,
            cn="no-cn-match.example.com",
            san_names=[x509.DNSName("*.*.example.com")],
        )
        with self.assertRaises(Exception) as ctx:
            self.ssl_ctx._match_tlsname(cert, "a.b.example.com")
        self.assertIn("tls_name", str(ctx.exception))
