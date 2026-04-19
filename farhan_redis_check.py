# ============================================================
#  COMP2152 — Term Project: Silent Breach
#  Author: Muhammad-Amin Farhan Ali
#  Vulnerability: Open Redis Port / Unauthenticated Redis Check
#  Target: redis.0x10.cloud (edit if needed)
# ============================================================
#
#  This script checks whether Redis is exposed on port 6379.
#  If the port is open, it then sends a simple Redis PING
#  command. A PONG response strongly suggests the service is
#  reachable and may lack authentication.
#
#  NOTE:
#  - If redis.0x10.cloud does not exist, try another allowed
#    0x10.cloud subdomain that you discover in scope.
# ============================================================

import socket
import time

target = "redis.0x10.cloud"   # Change only to another 0x10.cloud subdomain if needed
port = 6379

print("=" * 60)
print("  Redis Exposure Check")
print("=" * 60)

sock = None

try:
    time.sleep(0.15)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)

    print(f"\nTarget: {target}")
    print(f"Port:   {port}")
    print("Scanning Redis service...")

    result = sock.connect_ex((target, port))

    if result == 0:
        print(f"\n[INFO] Port {port} is OPEN on {target}")
        print("Attempting basic Redis PING command...")

        # Redis protocol message for PING
        ping_payload = b"*1\r\n$4\r\nPING\r\n"
        sock.sendall(ping_payload)

        reply = sock.recv(1024).decode(errors="ignore")
        print(f"Response: {reply.strip()}")

        if "PONG" in reply:
            print("\n[!] VULNERABILITY FOUND")
            print("Redis responded to an unauthenticated PING request.")
            print("This suggests the Redis service may be exposed without authentication.")
        else:
            print("\n[INFO] Port is open, but no clear unauthenticated Redis response was confirmed.")
    else:
        print(f"\n[OK] Port {port} is closed or unreachable on {target}")

except socket.gaierror:
    print(f"\n[ERROR] Hostname could not be resolved: {target}")
except socket.timeout:
    print("\n[ERROR] Connection timed out.")
except Exception as e:
    print(f"\n[ERROR] Redis check failed: {e}")
finally:
    if sock:
        sock.close()

print("\n" + "=" * 60)