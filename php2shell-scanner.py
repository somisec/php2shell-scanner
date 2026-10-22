import argparse
import csv
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from packaging import version
import requests
import urllib3

urllib3.disable_warnings()

# Fixed versions per PHP security advisory 2026-10-21
FIXED_VERSIONS = {
    "8.5": "8.5.12",
    "8.4": "8.4.27",
    "8.3": "8.3.36",
    "8.2": "8.2.35",
}
EOL_BRANCHES = {"5", "7", "8.0", "8.1"}


def check_target(target: str, timeout: int = 5) -> dict:
    if not target.startswith("http"):
        target = "https://" + target

    result = {
        "target": target,
        "status": "unknown",
        "php_version": None,
        "header_value": None,
        "note": "",
        "timestamp": datetime.utcnow().isoformat(),
    }

    try:
        resp = requests.head(
            target,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (security-scanner/research)"},
        )

        powered_by = resp.headers.get("X-Powered-By", "")
        result["header_value"] = powered_by or None

        if not powered_by or "php" not in powered_by.lower():
            result["status"] = "no_header"
            result["note"] = "X-Powered-By absent or not PHP — version undetectable passively"
            return result

        # Parse version string e.g. "PHP/8.2.34" or "PHP/8.2.34-1"
        raw = powered_by.split("/")[-1].split("-")[0].strip()
        result["php_version"] = raw

        try:
            detected = version.parse(raw)
        except version.InvalidVersion:
            result["status"] = "parse_error"
            result["note"] = f"Could not parse version string: {raw}"
            return result

        major_minor = f"{detected.major}.{detected.minor}"

        if major_minor in EOL_BRANCHES or detected.major < 8:
            result["status"] = "vulnerable"
            result["note"] = f"EOL branch {major_minor} — no official patch available"
            return result

        fixed = FIXED_VERSIONS.get(major_minor)
        if not fixed:
            result["status"] = "unknown"
            result["note"] = f"Branch {major_minor} not in advisory — check manually"
            return result

        if detected < version.parse(fixed):
            result["status"] = "vulnerable"
            result["note"] = f"Below fixed version {fixed}"
        else:
            result["status"] = "patched"
            result["note"] = f">= {fixed}"

    except requests.exceptions.SSLError:
        result["status"] = "error"
        result["note"] = "SSL error"
    except requests.exceptions.ConnectionError:
        result["status"] = "error"
        result["note"] = "Connection refused / unreachable"
    except requests.exceptions.Timeout:
        result["status"] = "error"
        result["note"] = "Timeout"
    except Exception as e:
        result["status"] = "error"
        result["note"] = str(e)

    return result


def print_result(r: dict):
    icons = {
        "vulnerable": "🔴",
        "patched":    "🟢",
        "no_header":  "⚪",
        "unknown":    "🟡",
        "error":      "❌",
        "parse_error":"⚠️ ",
    }
    icon = icons.get(r["status"], "?")
    ver = r["php_version"] or "n/a"
    print(f"{icon}  {r['target']:<45} PHP {ver:<12} {r['note']}")


def main():
    parser = argparse.ArgumentParser(
        description="php2shell CVE-2026-109618/109619 passive version scanner"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="Single target URL or host")
    group.add_argument("-l", "--list", help="File with one target per line")

    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--output", choices=["text", "json", "csv"], default="text")
    parser.add_argument("--only-vulnerable", action="store_true",
                        help="Only print vulnerable results")
    args = parser.parse_args()

    if args.target:
        targets = [args.target]
    else:
        with open(args.list) as f:
            targets = [line.strip() for line in f if line.strip()]

    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_target, t, args.timeout): t for t in targets}
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            if args.output == "text":
                if not args.only_vulnerable or r["status"] == "vulnerable":
                    print_result(r)

    if args.output == "json":
        json.dump(results, sys.stdout, indent=2)
    elif args.output == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    # Summary
    if args.output == "text":
        vuln = sum(1 for r in results if r["status"] == "vulnerable")
        patched = sum(1 for r in results if r["status"] == "patched")
        no_header = sum(1 for r in results if r["status"] == "no_header")
        errors = sum(1 for r in results if r["status"] == "error")
        print(f"\nScanned {len(results)} targets — "
              f"🔴 {vuln} vulnerable  🟢 {patched} patched  "
              f"⚪ {no_header} no header  ❌ {errors} errors")


if __name__ == "__main__":
    main()
