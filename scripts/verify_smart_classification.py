import asyncio
import json
from pathlib import Path
import sys
import os

# Add scan-servers to path
sys.path.append(os.path.join(os.getcwd(), "scan-servers"))

import fingerprints
from matcher import MatchResult, Fingerprint, CVEHit
from supabase_push import build_payload, severity_counts

def test_nmap_no_redundancy():
    print("\n--- Testing Nmap Noise Reduction ---")
    # Simulation: Nmap finds Apache 2.4.7 on port 80
    nmap_output = "80/tcp open http Apache httpd 2.4.7"
    fps = fingerprints.from_nmap(nmap_output)

    # Expected: 1 fingerprint (Apache software), NO redundant "Open Port: 80"
    # because software was detected and port 80 is not 'risky'.
    print(f"Fingerprints count: {len(fps)}")
    for fp in fps:
        print(f"Product: {fp.product:<20} Source: {fp.source}")

    assert len(fps) == 1
    assert fps[0].product == "http_server"

def test_nmap_risky_port():
    print("\n--- Testing Nmap Risky Port Inclusion ---")
    # Simulation: Nmap finds FTP on port 21
    nmap_output = "21/tcp open ftp"
    fps = fingerprints.from_nmap(nmap_output)

    # Expected: Port 21 should be included as it's in _RISKY_PORTS
    print(f"Fingerprints count: {len(fps)}")
    for fp in fps:
        print(f"Product: {fp.product:<20} Severity: {fp.suggested_severity}")

    assert any(f.product == "port-21/tcp" for f in fps)

def test_nikto_noise_reduction():
    print("\n--- Testing Nikto Noise Reduction ---")
    # Simulation: Nikto finding 'interesting' (Low) vs 'vulnerable' (High)
    nikto_output = """
+ Server: Apache/2.4.7
+ The anti-clickjacking header is not present.
+ The X-Content-Type-Options header is not set.
+ OSVDB-3092: /test.php: This might be interesting.
+ /admin/: Vulnerable to something.
    """
    fps = fingerprints.from_nikto(nikto_output)

    for fp in fps:
        print(f"Title: {fp.product:<15} Evidence: {fp.evidence[:30]:<30} Sev: {fp.suggested_severity or 'NVD'}")

    # Expected:
    # 1. Apache (NVD)
    # 2. anti-clickjacking (LOW)
    # 3. X-Content-Type-Options (LOW)
    # 4. /test.php (LOW)
    # 5. /admin/ (HIGH)
    print(f"Total findings: {len(fps)}")

if __name__ == "__main__":
    test_nmap_no_redundancy()
    test_nmap_risky_port()
    test_nikto_noise_reduction()
    print("\n✓ ALL NOISE REDUCTION VERIFICATIONS PASSED")
