# ============================================================
#  COMP2152 — Term Project: Silent Breach
#  Author: Mukhtar Ali
#  Vulnerability: Missing Security Headers
#  Target: api.0x10.cloud
# ============================================================
#
#  This script checks whether important HTTP security headers
#  are missing from the response. Missing headers can allow
#  clickjacking, content injection, weaker HTTPS protection,
#  and MIME-type confusion attacks.
# ============================================================

import urllib.request
import time

target = "http://api.0x10.cloud"

print("=" * 60)
print("  Missing Security Headers Check")
print("=" * 60)

try:
    # Respect the project rate limit
    time.sleep(0.15)

    response = urllib.request.urlopen(target, timeout=5)
    headers = dict(response.headers)

    # Security headers to inspect
    required_headers = {
        "Content-Security-Policy": "Helps reduce XSS and content injection risks",
        "X-Frame-Options": "Helps prevent clickjacking attacks",
        "Strict-Transport-Security": "Forces HTTPS in supporting browsers",
        "X-Content-Type-Options": "Helps prevent MIME-type sniffing",
        "Referrer-Policy": "Controls referrer data leakage",
    }

    print(f"\nTarget: {target}")
    print("Checking required security headers...\n")

    missing = []

    for header, purpose in required_headers.items():
        value = headers.get(header)
        if value:
            print(f"[FOUND] {header}: {value}")
        else:
            print(f"[MISSING] {header} -> {purpose}")
            missing.append(header)

    if missing:
        print("\n[!] VULNERABILITY FOUND")
        print("The server is missing important security headers:")
        for h in missing:
            print(f" - {h}")
        print("Missing security headers can weaken browser-side protection.")
    else:
        print("\n[OK] No missing security headers detected from this checklist.")

except Exception as e:
    print(f"\n[ERROR] Could not inspect headers: {e}")

print("\n" + "=" * 60)
