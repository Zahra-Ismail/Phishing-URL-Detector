"""
Phishing URL Detector
=====================
Detects potentially malicious or phishing URLs using heuristics,
blocklist matching, and structural analysis.

DISCLAIMER: For educational and ethical use only.
"""

import re
import sys
import json
import math
import argparse
import urllib.parse
from pathlib import Path
from datetime import datetime


# ── Blocklist ──────────────────────────────────────────────────────────────────
BLOCKLIST_FILE = Path(__file__).parent / "data" / "blocklist.txt"

def load_blocklist() -> set:
    if BLOCKLIST_FILE.exists():
        return set(BLOCKLIST_FILE.read_text().splitlines())
    return set()

BLOCKLIST = load_blocklist()


# ── Heuristic Checks ───────────────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "paypal", "amazon", "apple", "microsoft", "google",
    "netflix", "password", "credential", "confirm", "wallet",
    "ebay", "support", "helpdesk", "suspended", "unusual",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Free TLDs often abused
    ".xyz", ".top", ".click", ".link",
    ".pw", ".cc", ".su",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st",
]

IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (higher = more random/suspicious)."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def check_url(url: str) -> dict:
    """
    Analyse a single URL and return a result dict with:
      - score       : int  (risk points accumulated)
      - risk_level  : str  ('Low' | 'Medium' | 'High' | 'Critical')
      - flags       : list of human-readable warning strings
      - url         : the original URL
    """
    flags   = []
    score   = 0

    # Normalise
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return {"url": url, "score": 100, "risk_level": "Critical",
                "flags": ["Cannot parse URL"]}

    hostname = parsed.hostname or ""
    path     = parsed.path or ""
    full     = url.lower()

    # ── 1. Blocklist ──────────────────────────────────────────────────────────
    if hostname in BLOCKLIST:
        flags.append("🚫 Domain is on the blocklist")
        score += 100

    # ── 2. IP address instead of domain ──────────────────────────────────────
    if IP_PATTERN.match(hostname):
        flags.append("🔢 URL uses a raw IP address instead of a domain name")
        score += 30

    # ── 3. HTTP (no TLS) ─────────────────────────────────────────────────────
    if parsed.scheme == "http":
        flags.append("🔓 No HTTPS – connection is unencrypted")
        score += 10

    # ── 4. Suspicious TLD ────────────────────────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            flags.append(f"⚠️  Suspicious TLD: {tld}")
            score += 20
            break

    # ── 5. URL shortener ─────────────────────────────────────────────────────
    for shortener in URL_SHORTENERS:
        if hostname == shortener or hostname.endswith("." + shortener):
            flags.append(f"🔗 URL shortener detected: {shortener}")
            score += 15
            break

    # ── 6. Suspicious keywords in domain / path ───────────────────────────────
    keyword_hits = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in hostname or kw in path.lower():
            keyword_hits.append(kw)
    if keyword_hits:
        flags.append(f"🎣 Phishing keywords found: {', '.join(keyword_hits)}")
        score += min(len(keyword_hits) * 8, 40)

    # ── 7. Excessive subdomains ───────────────────────────────────────────────
    subdomain_count = hostname.count(".")
    if subdomain_count >= 3:
        flags.append(f"🌐 Excessive subdomains ({subdomain_count} dots) – may spoof legitimate domains")
        score += 15

    # ── 8. Long URL ───────────────────────────────────────────────────────────
    if len(url) > 100:
        flags.append(f"📏 Unusually long URL ({len(url)} chars)")
        score += 10

    # ── 9. @ symbol in URL (user-info trick) ─────────────────────────────────
    if "@" in url:
        flags.append("@ symbol in URL – browser ignores everything before it (classic trick)")
        score += 25

    # ── 10. Punycode / homograph ──────────────────────────────────────────────
    if "xn--" in hostname:
        flags.append("🔡 Punycode detected – possible homograph/look-alike domain")
        score += 25

    # ── 11. Double slash in path (redirect trick) ─────────────────────────────
    if "//" in path:
        flags.append("↪️  Double slash in path – possible open redirect")
        score += 10

    # ── 12. High entropy hostname (randomised / DGA domain) ───────────────────
    domain_label = hostname.split(".")[0]
    entropy = shannon_entropy(domain_label)
    if entropy > 3.8 and len(domain_label) > 8:
        flags.append(f"🎲 High-entropy domain label (entropy={entropy:.2f}) – may be DGA-generated")
        score += 20

    # ── 13. Port number in URL ────────────────────────────────────────────────
    if parsed.port and parsed.port not in (80, 443):
        flags.append(f"🔌 Non-standard port: {parsed.port}")
        score += 15

    # ── Risk Level ────────────────────────────────────────────────────────────
    if score == 0:
        risk_level = "Low"
    elif score < 30:
        risk_level = "Low"
    elif score < 60:
        risk_level = "Medium"
    elif score < 90:
        risk_level = "High"
    else:
        risk_level = "Critical"

    if not flags:
        flags.append("✅ No suspicious indicators detected")

    return {
        "url":        url,
        "score":      score,
        "risk_level": risk_level,
        "flags":      flags,
    }


# ── Pretty Printer ─────────────────────────────────────────────────────────────
RISK_COLORS = {
    "Low":      "\033[92m",   # green
    "Medium":   "\033[93m",   # yellow
    "High":     "\033[91m",   # red
    "Critical": "\033[95m",   # magenta
}
RESET = "\033[0m"
BOLD  = "\033[1m"

def print_result(result: dict, use_color: bool = True) -> None:
    rl    = result["risk_level"]
    color = RISK_COLORS.get(rl, "") if use_color else ""
    reset = RESET if use_color else ""
    bold  = BOLD  if use_color else ""

    print(f"\n{'─'*60}")
    print(f"{bold}URL   :{reset} {result['url']}")
    print(f"{bold}Score :{reset} {result['score']}")
    print(f"{bold}Risk  :{reset} {color}{rl}{reset}")
    print(f"{bold}Flags :{reset}")
    for flag in result["flags"]:
        print(f"  • {flag}")
    print(f"{'─'*60}")


# ── CLI ────────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="detector",
        description="Phishing URL Detector – heuristic & blocklist analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detector.py -u https://paypa1-secure.tk/login
  python detector.py -f urls.txt
  python detector.py -u http://192.168.1.1/verify --json
  python detector.py -f urls.txt --output results.json

DISCLAIMER: Use only on URLs you own or have explicit permission to test.
        """,
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url",  help="Single URL to analyse")
    group.add_argument("-f", "--file", help="File with one URL per line")
    p.add_argument("--json",   action="store_true", help="Output results as JSON")
    p.add_argument("--output", metavar="FILE",      help="Save JSON results to a file")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colour output")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    urls = []
    if args.url:
        urls = [args.url.strip()]
    elif args.file:
        try:
            urls = [
            l.strip()
            for l in Path(args.file).read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    results = [check_url(u) for u in urls]

    if args.json or args.output:
        payload = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total":        len(results),
            "results":      results,
        }
        json_str = json.dumps(payload, indent=2)
        if args.output:
            Path(args.output).write_text(json_str)
            print(f"[+] Results saved to {args.output}")
        if args.json:
            print(json_str)
    else:
        use_color = not args.no_color
        for r in results:
            print_result(r, use_color=use_color)

        # Summary
        summary = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for r in results:
            summary[r["risk_level"]] += 1
        print(f"\n📊 Summary  |  Total: {len(results)}  |  "
              + "  ".join(f"{k}: {v}" for k, v in summary.items()))


if __name__ == "__main__":
    main()
