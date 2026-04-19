# ============================================================
#  COMP2152 — Term Project: Silent Breach
#  Author: Mukhtar Ali
#  Vulnerability: Open CORS Misconfiguration
#  Target: api.0x10.cloud
# ============================================================
#
#  This script checks whether the server allows overly broad
#  cross-origin access. If Access-Control-Allow-Origin is set
#  to *, other websites may be able to interact with the API
#  from a victim's browser, depending on the endpoint design.
# ============================================================

import urllib.request
import time

target = "http://api.0x10.cloud"

print("=" * 60)
print("  Open CORS Policy Check")
print("=" * 60)

try:
    time.sleep(0.15)

    request = urllib.request.Request(target)
    response = urllib.request.urlopen(request, timeout=5)
    headers = dict(response.headers)

    cors_origin = headers.get("Access-Control-Allow-Origin")
    cors_methods = headers.get("Access-Control-Allow-Methods", "Not disclosed")
    cors_headers = headers.get("Access-Control-Allow-Headers", "Not disclosed")
    allow_credentials = headers.get("Access-Control-Allow-Credentials", "Not disclosed")

    print(f"\nTarget: {target}")
    print(f"Access-Control-Allow-Origin: {cors_origin}")
    print(f"Access-Control-Allow-Methods: {cors_methods}")
    print(f"Access-Control-Allow-Headers: {cors_headers}")
    print(f"Access-Control-Allow-Credentials: {allow_credentials}")

    if cors_origin == "*":
        print("\n[!] VULNERABILITY FOUND")
        print(
            "The server allows requests from any origin using Access-Control-Allow-Origin: *"
        )
        print("This may expose API resources to unauthorized cross-origin access.")
    elif cors_origin:
        print("\n[INFO] CORS is enabled, but not fully open with '*'.")
    else:
        print("\n[OK] No permissive CORS policy detected in the response.")

except Exception as e:
    print(f"\n[ERROR] Could not inspect CORS headers: {e}")

print("\n" + "=" * 60)
