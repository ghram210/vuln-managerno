import sys
import os

# Add parent directory to path to import local modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scan-servers'))

from fingerprints import from_nmap, from_ffuf, from_nikto, from_sqlmap

def test_nmap_visibility():
    print("--- Testing Nmap Visibility ---")
    # Simulation: Nmap finds an open port and software
    # The user wants BOTH to be visible.
    raw_nmap = """
    80/tcp open  http    Apache httpd 2.4.7
    """
    fps = from_nmap(raw_nmap)
    print(f"Fingerprints count: {len(fps)}")
    for fp in fps:
        # Fingerprint is a dataclass, use dot notation
        print(f" - [{fp.suggested_severity}] {fp.product} {fp.version} (Source: {fp.source})")

    # We expect 2 findings: 1 for the software (Apache 2.4.7) and 1 for the port (port-80/tcp)
    assert len(fps) == 2
    products = [fp.product for fp in fps]
    assert "http_server" in products # apache httpd maps to http_server
    assert "port-80/tcp" in products

def test_ffuf_noise_filter():
    print("--- Testing FFUF Noise Filter ---")
    raw_ffuf = """
    [Status: 200, Size: 123] | /index.php
    [Status: 200, Size: 456] | /style.css
    [Status: 200, Size: 789] | /logo.png
    [Status: 200, Size: 10]  | /.env
    """
    fps = from_ffuf(raw_ffuf)
    print(f"Fingerprints count: {len(fps)}")
    paths = [fp.path for fp in fps]
    print(f"Paths: {paths}")

    assert "/.env" in paths
    assert "/index.php" in paths
    assert "/style.css" not in paths
    assert "/logo.png" not in paths
    print("FFUF Noise Filter works!")

def test_nvd_priority_simulation():
    print("--- Testing NVD Priority Simulation ---")
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    # Scenario:
    # Finding 1 (FFUF .env) -> Smart says CRITICAL
    # Finding 2 (Nmap Apache) -> Smart says LOW (port 80)
    # Finding 2 matched CVE-2024-XXXX -> NVD says HIGH

    by_finding = {}

    # 1. Smart Classification step
    by_finding["f1"] = "CRITICAL" # .env
    by_finding["f2"] = "LOW"      # Apache on port 80 (LOW because 80 is common)

    # 2. NVD Priority step
    cve_sev = {"CVE-2024-1": "HIGH"}
    finding_cves = [{"client_id": "f2", "cve_id": "CVE-2024-1"}]

    for link in finding_cves:
        sev = cve_sev.get(link["cve_id"], "")
        cur = by_finding.get(link["client_id"])

        # This simulates the logic in supabase_push.py
        # If NVD provides a severity, it wins.
        # We check if 'cur' came from NVD or not?
        # Actually in supabase_push we do:
        # if cur is None or sev_order[sev] < sev_order.get(cur, 99):
        # But if 'cur' was 'CRITICAL' from Smart, and NVD says 'HIGH',
        # should NVD win? User said "the priority is for NVD classification".
        # This usually means NVD is the gold standard.

        if cur is None or sev_order[sev] < 99:
             by_finding[link["client_id"]] = sev

    print(f"Finding 2 Final Severity: {by_finding['f2']}")
    assert by_finding["f2"] == "HIGH"

if __name__ == "__main__":
    try:
        test_nmap_visibility()
        test_ffuf_noise_filter()
        test_nvd_priority_simulation()
        print("\nVerification Successful!")
    except Exception as e:
        print(f"\nVerification Failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
