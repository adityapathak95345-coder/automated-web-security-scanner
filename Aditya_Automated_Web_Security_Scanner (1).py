"""
Automated Web Security Scanner (Defensive, passive checks)
Author: Aditya Pathak

Checks a target URL for common HTTP security headers, HTTPS usage, and
basic CORS response behavior. Use only on websites you own or are authorized
to assess. This tool does not exploit vulnerabilities or perform intrusive tests.
"""
from urllib.parse import urlparse
import argparse
import json
from datetime import datetime, timezone

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS in supported browsers.",
    "Content-Security-Policy": "Helps reduce risks from injected content.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing when set to nosniff.",
    "X-Frame-Options": "Helps reduce clickjacking risk (CSP frame-ancestors is a modern alternative).",
    "Referrer-Policy": "Controls how much referrer information browsers send.",
    "Permissions-Policy": "Restricts access to selected browser features.",
}

def normalize_url(url: str) -> str:
    """Add https:// when a scheme is omitted and validate the URL shape."""
    url = url.strip()
    if not url:
        raise ValueError("Please provide a target URL.")
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must be an http:// or https:// URL with a hostname.")
    if parsed.username or parsed.password:
        raise ValueError("Do not include credentials in the URL.")
    return url

def scan_url(url: str, timeout: int = 8) -> dict:
    """Perform a single ordinary GET request and report passive observations."""
    target = normalize_url(url)
    result = {
        "target": target,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status_code": None,
        "final_url": None,
        "https_used": target.lower().startswith("https://"),
        "redirected": False,
        "server_header_present": False,
        "headers": {},
        "cors": {},
        "errors": [],
    }
    try:
        response = requests.get(
            target,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "PassiveWebSecurityScanner/1.0"},
        )
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["redirected"] = len(response.history) > 0
        result["https_used"] = response.url.lower().startswith("https://")
        result["server_header_present"] = "Server" in response.headers

        for header, explanation in SECURITY_HEADERS.items():
            value = response.headers.get(header)
            result["headers"][header] = {
                "present": value is not None,
                "value": value if value is not None else "",
                "note": explanation,
            }

        acao = response.headers.get("Access-Control-Allow-Origin")
        acac = response.headers.get("Access-Control-Allow-Credentials")
        result["cors"] = {
            "allow_origin_present": acao is not None,
            "allow_origin": acao or "",
            "allow_credentials": acac or "",
            "wildcard_with_credentials": acao == "*" and str(acac).lower() == "true",
            "note": "CORS findings depend on request context; a header alone does not prove an exploitable flaw."
        }
    except requests.RequestException as exc:
        result["errors"].append(f"Request failed: {exc.__class__.__name__}: {exc}")
    return result

def print_report(report: dict) -> None:
    print("\n=== PASSIVE WEB SECURITY SCAN ===")
    print(f"Target: {report['target']}")
    print(f"Checked (UTC): {report['checked_at_utc']}")
    print(f"HTTP status: {report['status_code']}")
    print(f"Final URL: {report['final_url']}")
    print(f"HTTPS at final URL: {'Yes' if report['https_used'] else 'No'}")
    print(f"Redirected: {'Yes' if report['redirected'] else 'No'}")
    print("\nSecurity headers:")
    for name, item in report["headers"].items():
        state = "PRESENT" if item["present"] else "MISSING"
        print(f"- {name}: {state}")
        if item["present"]:
            print(f"    Value: {item['value']}")
    cors = report["cors"]
    print("\nCORS observations:")
    print(f"- Access-Control-Allow-Origin present: {cors.get('allow_origin_present')}")
    print(f"- Allow-Origin value: {cors.get('allow_origin') or '(not set)'}")
    print(f"- Allow-Credentials: {cors.get('allow_credentials') or '(not set)'}")
    if cors.get("wildcard_with_credentials"):
        print("  WARNING: wildcard origin and credentials were both observed; verify browser behavior and configuration.")
    print("\nNotes:")
    print("- Missing headers are hardening opportunities, not proof of a vulnerability.")
    print("- This is a passive, single-request check, not a comprehensive penetration test.")
    for error in report["errors"]:
        print(f"- ERROR: {error}")

def main():
    parser = argparse.ArgumentParser(description="Passive web security header and CORS checker.")
    parser.add_argument("url", help="Website URL you own or have permission to assess")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--json", dest="json_path", help="Optional path to save the JSON report")
    args = parser.parse_args()

    if args.timeout < 1 or args.timeout > 60:
        parser.error("--timeout must be between 1 and 60 seconds")

    report = scan_url(args.url, args.timeout)
    print_report(report)
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2, ensure_ascii=False)
        print(f"\nJSON report saved to: {args.json_path}")

if __name__ == "__main__":
    main()
