# php2shell-scanner

Passive version scanner for CVE-2026-109618 / CVE-2026-109619 (PHP2Shell).

Detects vulnerable PHP instances by reading the `X-Powered-By` response header and comparing the reported version against the fixed versions from the 2026-10-21 security advisory. No exploit code is sent — this is detection only.

## How it works

PHP exposes its version in the `X-Powered-By: PHP/x.x.x` response header when `expose_php = On` is set in `php.ini` (this is the default). The scanner reads that header and compares it against the known fixed versions:

| Branch | Fixed version |
|--------|--------------|
| 8.5    | 8.5.12       |
| 8.4    | 8.4.27       |
| 8.3    | 8.3.36       |
| 8.2    | 8.2.35       |
| 5.x / 7.x / 8.0 / 8.1 | EOL — no official patch |

If the header is absent, the target is reported as `no header` — this does **not** mean it is safe, only that the version cannot be passively determined.

## Requirements

```bash
pip install requests packaging
```

## Usage

```bash
# Single target
python3 php2shell-scanner.py -t http://example.com

# List of targets (one URL per line)
python3 php2shell-scanner.py -l targets.txt

# Only print vulnerable results
python3 php2shell-scanner.py -l targets.txt --only-vulnerable

# Export results as JSON
python3 php2shell-scanner.py -l targets.txt --output json > results.json

# Export results as CSV
python3 php2shell-scanner.py -l targets.txt --output csv > results.csv

# Adjust threads and timeout
python3 php2shell-scanner.py -l targets.txt --threads 50 --timeout 10
```

## All flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t`, `--target` | — | Single target URL or hostname |
| `-l`, `--list` | — | Path to file with one target per line |
| `--threads` | 20 | Number of concurrent threads |
| `--timeout` | 5 | Request timeout in seconds |
| `--output` | text | Output format: `text`, `json`, or `csv` |
| `--only-vulnerable` | off | Only print targets flagged as vulnerable |

## targets.txt format

One URL per line, blank lines are ignored:

```
http://example.com
http://192.168.1.10
https://another-target.com
```

## Output

```
🔴  http://target.com      PHP 8.2.34    Below fixed version 8.2.35
🟢  http://target2.com     PHP 8.2.35    >= 8.2.35
⚪  http://target3.com     PHP n/a       X-Powered-By absent or not PHP — version undetectable passively
❌  http://target4.com     PHP n/a       Connection refused / unreachable

Scanned 4 targets — 🔴 1 vulnerable  🟢 1 patched  ⚪ 1 no header  ❌ 1 errors
```

| Icon | Meaning |
|------|---------|
| 🔴 | Version detected and below the fixed version |
| 🟢 | Version detected and at or above the fixed version |
| ⚪ | No `X-Powered-By` header or header does not contain PHP |
| 🟡 | PHP version detected but branch not in advisory — check manually |
| ❌ | Connection error, timeout, or SSL failure |

## Server-side requirement

The target server must have `expose_php = On` in `php.ini` for the `X-Powered-By` header to appear. This is the PHP default but many hardened servers disable it. A `no header` result should be treated as unknown, not safe.

```ini
; php.ini
expose_php = On
```

## Disclaimer

For use only on systems you own or have explicit written permission to test.

## CVE references

- CVE-2026-109618 — Session filename injection via `session.upload_progress`
- CVE-2026-109619 — Handler mismatch leading to object deserialization and RCE
