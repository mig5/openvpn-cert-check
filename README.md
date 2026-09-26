# openvpn-cert-check

Audit an OpenSSL/OpenVPN certificate authority's `index.txt` against a
known list of expected valid certificates.

## Why

OpenVPN's PKI is just an OpenSSL CA. The `index.txt` file is the
authoritative record of every certificate ever issued: valid, revoked,
and expired. But there is no built-in tool that answers a simple
operational question:

> Which certificates are currently valid, and are they exactly the ones
> we expect?

1. **Drift detection.** Someone issues a certificate and forgets to tell
   anyone. Months later the employee leaves, the cert is still valid,
   and nobody knows it exists.

2. **Expiry monitoring.** Certificates silently expire. OpenVPN clients
   stop connecting with cryptic TLS errors. A CI check that runs daily
   and warns 30 days before expiry prevents this.

## What it does

Reads a tab-separated OpenSSL `index.txt` and compares the set of
currently-valid certificates against a file of expected certificate
names (CNs), one per line.

Reports:

- Valid certificates that are **not** in the expected list (unexpected)
- Expected certificates that are **not** currently valid (missing)
- Valid certificates whose CN cannot be parsed (unparseable)
- Multiple valid certificates sharing the same CN (duplicates)
- Certificates expiring within a warning window (`--warn-days`)
- Revoked and expired certificates (informational)

## Usage

```
openvpn-cert-check -i <index.txt> -e <expected.txt> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-i, --index PATH` | OpenSSL index file (default: `/root/openvpn-ca/keys/index.txt`) |
| `-e, --expected-file PATH` | File of expected certificate names, one per line (required) |
| `-w, --warn-days N` | Warn about valid certificates expiring within N days |
| `--json` | Machine-readable JSON output |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No unexpected valid certificates, no expiring warnings |
| 1 | Unexpected or unparseable valid certificates found |
| 2 | Configuration or input error |
| 3 | Valid certificate(s) expiring within `--warn-days` (warning only) |

When both exit 1 and exit 3 conditions apply, exit 1 takes precedence:
unexpected certificates are a failure, expiry warnings are not.

## CI integration

The `--warn-days` flag with `--json` is designed for CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Check certificate expiry
  run: |
    ./openvpn-cert-check \
      -i index.txt \
      -e expected.txt \
      --warn-days 30 \
      --json > result.json
```

A non-zero exit code fails the pipeline. Use exit code 3 (warning) with
`continue-on-error: true` if you want to be notified but not blocked.

## Works with any OpenSSL CA

Despite the name, this tool reads a standard OpenSSL `index.txt`. It
works with any CA that uses `openssl ca`, be it OpenVPN, custom PKIs, etc.

## Testing

```
pytest tests/
```
