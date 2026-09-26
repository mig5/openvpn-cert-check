"""Integration tests running the script as a subprocess."""

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "openvpn-cert-check"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def run(index, expected_file, *extra, expect_fail=False):
    cmd = [
        sys.executable,
        str(SCRIPT),
        "-i",
        str(index),
        "-e",
        str(expected_file),
    ]
    cmd.extend(extra)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if not expect_fail and result.returncode not in (0, 1, 3):
        msg = f"unexpected exit {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        raise AssertionError(msg)

    return result


class TestHumanOutput:
    def test_mixed_all_expected(self):
        r = run(FIXTURES / "mixed_index.txt", FIXTURES / "expected.txt")
        assert r.returncode == 0
        assert "OK: all valid certificates are expected." in r.stdout
        assert "Valid       : 4" in r.stdout
        assert "Revoked     : 3" in r.stdout
        assert "Expired     : 1" in r.stdout

    def test_expired_uses_past_tense(self):
        r = run(FIXTURES / "mixed_index.txt", FIXTURES / "expected.txt")
        assert "harriet  expired 2026-05-07" in r.stdout
        assert "harriet  expires 2026-05-07" not in r.stdout

    def test_revoked_uses_future_tense(self):
        r = run(FIXTURES / "mixed_index.txt", FIXTURES / "expected.txt")
        assert "edward    expires 2032-05-09" in r.stdout

    def test_unexpected_cert_exit_1(self):
        r = run(
            FIXTURES / "unexpected_index.txt",
            FIXTURES / "expected.txt",
        )
        assert r.returncode == 1
        assert "FAILED: 1 unexpected valid certificate" in r.stdout
        assert "UNEXPECTED" in r.stdout

    def test_missing_cert_shown(self):
        r = run(
            FIXTURES / "missing_index.txt",
            FIXTURES / "expected.txt",
        )
        assert r.returncode == 0
        assert "Expected but not currently valid" in r.stdout
        assert "dan" in r.stdout

    def test_duplicate_shown(self):
        r = run(
            FIXTURES / "duplicate_index.txt",
            FIXTURES / "expected.txt",
        )
        assert "Multiple valid certificates with the same name" in r.stdout
        assert "alice: 2" in r.stdout

    def test_unparseable_exit_1(self):
        r = run(
            FIXTURES / "unparseable_index.txt",
            FIXTURES / "expected.txt",
        )
        assert r.returncode == 1
        assert "UNPARSEABLE" in r.stdout
        assert "FAILED" in r.stdout

    def test_empty_index(self):
        r = run(FIXTURES / "empty_index.txt", FIXTURES / "expected.txt")
        assert r.returncode == 0
        assert "Valid       : 0" in r.stdout

    def test_malformed_exit_2(self):
        r = run(
            FIXTURES / "malformed_index.txt",
            FIXTURES / "expected.txt",
            expect_fail=True,
        )
        assert r.returncode == 2
        assert "expected 6 tab-separated" in r.stderr

    def test_missing_expected_file_exit_2(self):
        cmd = [
            sys.executable,
            str(SCRIPT),
            "-i",
            str(FIXTURES / "good_index.txt"),
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        assert r.returncode == 2


class TestJsonOutput:
    def test_mixed_json(self):
        r = run(
            FIXTURES / "mixed_index.txt",
            FIXTURES / "expected.txt",
            "--json",
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)

        assert data["expected_count"] == 4
        assert data["valid_count"] == 4
        assert data["revoked_count"] == 3
        assert data["expired_count"] == 1
        assert data["unexpected"] == []
        assert data["missing"] == []
        assert data["metric_value"] == 0
        assert data["expiring"] == []
        assert data["expiring_count"] == 0
        assert data["warn_days"] is None

    def test_unexpected_json(self):
        r = run(
            FIXTURES / "unexpected_index.txt",
            FIXTURES / "expected.txt",
            "--json",
        )
        assert r.returncode == 1
        data = json.loads(r.stdout)
        assert data["unexpected"] == ["eve"]
        assert data["metric_value"] == 1

    def test_missing_json(self):
        r = run(
            FIXTURES / "missing_index.txt",
            FIXTURES / "expected.txt",
            "--json",
        )
        data = json.loads(r.stdout)
        assert data["missing"] == ["dan"]

    def test_duplicate_json(self):
        r = run(
            FIXTURES / "duplicate_index.txt",
            FIXTURES / "expected.txt",
            "--json",
        )
        data = json.loads(r.stdout)
        assert data["duplicate_valid_names"] == {"alice": 2}

    def test_expected_count_matches_human(self):
        """The mock output had expected_count: 8 but Expected: 4 — these must match."""
        r_human = run(FIXTURES / "mixed_index.txt", FIXTURES / "expected.txt")
        r_json = run(
            FIXTURES / "mixed_index.txt",
            FIXTURES / "expected.txt",
            "--json",
        )
        data = json.loads(r_json.stdout)

        # Extract "Expected    : N" from human output
        for line in r_human.stdout.splitlines():
            if line.strip().startswith("Expected"):
                human_expected = int(line.split(":")[1].strip())
                break

        assert data["expected_count"] == human_expected


class TestWarnDays:
    def test_expiring_exit_3(self):
        r = run(
            FIXTURES / "mixed_index.txt",
            FIXTURES / "expected.txt",
            "--warn-days",
            "999999",
        )
        assert r.returncode == 3
        assert "WARNING: 4 valid certificates expiring" in r.stdout
        assert "Expiring soon" in r.stdout

    def test_expiring_json(self):
        r = run(
            FIXTURES / "mixed_index.txt",
            FIXTURES / "expected.txt",
            "--warn-days",
            "999999",
            "--json",
        )
        assert r.returncode == 3
        data = json.loads(r.stdout)
        assert data["expiring_count"] == 4
        assert data["warn_days"] == 999999
        assert all("days" in item for item in data["expiring"])
        # Sorted by expiry date (soonest first)
        names = [item["name"] for item in data["expiring"]]
        assert names == sorted(names, key=lambda n: {
            "dan": 0, "cora": 1, "alice": 2, "bob": 3
        }.get(n, 99))

    def test_no_warn_days_no_expiring(self):
        r = run(
            FIXTURES / "mixed_index.txt",
            FIXTURES / "expected.txt",
            "--json",
        )
        data = json.loads(r.stdout)
        assert data["expiring"] == []
        assert data["expiring_count"] == 0

    def test_warn_days_zero_no_expiring(self):
        """--warn-days 0 flags nothing since valid certs haven't expired yet."""
        r = run(
            FIXTURES / "mixed_index.txt",
            FIXTURES / "expected.txt",
            "--warn-days",
            "0",
            "--json",
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert data["expiring_count"] == 0

    def test_negative_warn_days_exit_2(self):
        r = run(
            FIXTURES / "mixed_index.txt",
            FIXTURES / "expected.txt",
            "--warn-days",
            "-1",
            expect_fail=True,
        )
        assert r.returncode == 2

    def test_unexpected_takes_precedence_over_expiring(self):
        r = run(
            FIXTURES / "unexpected_index.txt",
            FIXTURES / "expected.txt",
            "--warn-days",
            "999999",
            "--json",
        )
        assert r.returncode == 1
        data = json.loads(r.stdout)
        assert data["unexpected"] == ["eve"]
        assert data["expiring_count"] == 5  # 4 expected + 1 unexpected


class TestExitCodePrecedence:
    def test_config_error_beats_everything(self):
        cmd = [
            sys.executable,
            str(SCRIPT),
            "-i",
            str(FIXTURES / "malformed_index.txt"),
            "-e",
            str(FIXTURES / "expected.txt"),
            "--warn-days",
            "30",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        assert r.returncode == 2
