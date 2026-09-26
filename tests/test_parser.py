"""Unit tests for the parser and helper functions."""

from datetime import datetime, timezone

import pytest


class TestParseOpensslTime:
    def test_utctime(self, mod):
        result = mod.parse_openssl_time("310827234024Z")
        assert result == datetime(2031, 8, 27, 23, 40, 24, tzinfo=timezone.utc)

    def test_utctime_century_boundary(self, mod):
        result = mod.parse_openssl_time("491231235959Z")
        assert result == datetime(2049, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    def test_utctime_20th_century(self, mod):
        result = mod.parse_openssl_time("500101000000Z")
        assert result == datetime(1950, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_generalizedtime(self, mod):
        result = mod.parse_openssl_time("20310827234024Z")
        assert result == datetime(2031, 8, 27, 23, 40, 24, tzinfo=timezone.utc)

    def test_empty_returns_none(self, mod):
        assert mod.parse_openssl_time("") is None

    def test_invalid_raises(self, mod):
        with pytest.raises(ValueError, match="invalid OpenSSL timestamp"):
            mod.parse_openssl_time("not-a-time")


class TestParseSubject:
    def test_slash_dn(self, mod):
        attrs = mod.parse_subject("/C=AU/O=Example/CN=alice")
        assert attrs["CN"] == ["alice"]
        assert attrs["O"] == ["Example"]
        assert attrs["C"] == ["AU"]

    def test_no_cn(self, mod):
        attrs = mod.parse_subject("/C=AU/O=Example")
        assert "CN" not in attrs

    def test_escaped_slash(self, mod):
        attrs = mod.parse_subject("/CN=name\\/with\\/slash")
        assert attrs["CN"] == ["name/with/slash"]

    def test_comma_separated(self, mod):
        attrs = mod.parse_subject("C=AU, O=Example, CN=alice")
        assert attrs["CN"] == ["alice"]

    def test_empty(self, mod):
        attrs = mod.parse_subject("")
        assert attrs == {}


class TestCertificateName:
    def test_cn(self, mod):
        assert mod.certificate_name("/C=AU/O=Example/CN=alice") == "alice"

    def test_no_cn_returns_none(self, mod):
        assert mod.certificate_name("/C=AU/O=Example") is None

    def test_uid_fallback(self, mod):
        assert mod.certificate_name("/UID=user123") == "user123"

    def test_multiple_cn_takes_last(self, mod):
        result = mod.certificate_name("/CN=old/CN=new")
        assert result == "new"


class TestReadIndex:
    def test_mixed(self, mod, fx):
        certs = mod.read_index(fx / "mixed_index.txt")
        assert len(certs) == 8

        alice = certs[0]
        assert alice.name == "alice"
        assert alice.status == "V"
        assert alice.serial == "01"

        edward = certs[4]
        assert edward.name == "edward"
        assert edward.status == "R"
        assert edward.revoked is not None

        harriet = certs[7]
        assert harriet.name == "harriet"
        assert harriet.status == "E"

    def test_empty_file(self, mod, fx):
        certs = mod.read_index(fx / "empty_index.txt")
        assert certs == []

    def test_file_not_found(self, mod, fx):
        with pytest.raises(RuntimeError, match="does not exist"):
            mod.read_index(fx / "nonexistent.txt")

    def test_malformed_line(self, mod, fx):
        with pytest.raises(RuntimeError, match="expected 6 tab-separated"):
            mod.read_index(fx / "malformed_index.txt")

    def test_skips_blank_lines(self, mod, fx):
        import tempfile
        import os
        from pathlib import Path

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n")
            f.write(
                "V\t310827234024Z\t\t01\tunknown\t/C=AU/O=Example/CN=alice\n"
            )
            f.write("   \n")
            f.write(
                "V\t330225085227Z\t\t02\tunknown\t/C=AU/O=Example/CN=bob\n"
            )
            f.write("\n")
            path = f.name

        try:
            certs = mod.read_index(Path(path))
            assert len(certs) == 2
        finally:
            os.unlink(path)


class TestLoadExpected:
    def test_normal(self, mod, fx):
        expected = mod.load_expected(fx / "expected.txt")
        assert expected == {"alice", "bob", "cora", "dan"}

    def test_comments_skipped(self, mod, fx):
        expected = mod.load_expected(fx / "expected.txt")
        assert "#" not in expected

    def test_none_path_raises(self, mod):
        with pytest.raises(RuntimeError, match="no expected certificate file"):
            mod.load_expected(None)

    def test_empty_file_raises(self, mod, fx):
        with pytest.raises(RuntimeError, match="is empty"):
            mod.load_expected(fx / "empty_index.txt")


class TestEffectiveStatus:
    NOW = datetime(2026, 9, 26, 0, 0, 0, tzinfo=timezone.utc)

    def _make_cert(self, mod, status="V", expires=None):
        return mod.Certificate(
            line=1,
            status=status,
            expires=expires,
            revoked=None,
            serial="01",
            filename="unknown",
            subject="/CN=test",
            name="test",
        )

    def test_valid(self, mod):
        cert = self._make_cert(
            mod,
            status="V",
            expires=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )
        assert mod.effective_status(cert, self.NOW) == "valid"

    def test_revoked(self, mod):
        cert = self._make_cert(
            mod,
            status="R",
            expires=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )
        assert mod.effective_status(cert, self.NOW) == "revoked"

    def test_expired_status(self, mod):
        cert = self._make_cert(
            mod,
            status="E",
            expires=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        assert mod.effective_status(cert, self.NOW) == "expired"

    def test_v_but_past_expiry_date(self, mod):
        """A V-status cert whose expiry has passed is treated as expired.

        This tests the 'do not rely on ca -updatedb' behaviour.
        """
        cert = self._make_cert(
            mod,
            status="V",
            expires=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        assert mod.effective_status(cert, self.NOW) == "expired"

    def test_unknown_status(self, mod):
        cert = self._make_cert(mod, status="X")
        assert mod.effective_status(cert, self.NOW) == "unknown"


class TestTimeVerb:
    NOW = datetime(2026, 9, 26, 0, 0, 0, tzinfo=timezone.utc)

    def test_future(self, mod):
        future = datetime(2030, 1, 1, tzinfo=timezone.utc)
        assert mod.time_verb(future, self.NOW) == "expires"

    def test_past(self, mod):
        past = datetime(2020, 1, 1, tzinfo=timezone.utc)
        assert mod.time_verb(past, self.NOW) == "expired"

    def test_none(self, mod):
        assert mod.time_verb(None, self.NOW) == "expires"
