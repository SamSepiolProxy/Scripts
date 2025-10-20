#!/usr/bin/env python3
"""
iker v2.1 - IPsec VPN Security Scanner
A Python-based tool to discover and assess the security of IPsec VPN servers.
All development was done by https://github.com/nullenc0de/iker/tree/patch-1
"""

import argparse
import json
import logging
import re
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List

# --- Global Constants ---

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Vulnerability descriptions
FLAWS = {
    "IKEV1": "Weak IKE version 1 supported (deprecated in favor of IKEv2)",
    "DISC": "The IKE service is discoverable, which should be restricted to authorized parties",
    "ENC_DES": "DES encryption detected - CRITICAL vulnerability (easily broken)",
    "ENC_3DES": "3DES encryption detected - deprecated and should be replaced with AES",
    "HASH_MD5": "MD5 hash algorithm detected - CRITICAL vulnerability (collision attacks possible)",
    "HASH_SHA1": "SHA1 hash algorithm detected - deprecated due to collision vulnerabilities",
    "DHG_1": "DH Group 1 (MODP-768) detected - CRITICAL vulnerability (insufficient key length)",
    "DHG_2": "DH Group 2 (MODP-1024) detected - weak DH group, should use Group 14+ (2048-bit+)",
    "AUTH_PSK": "Pre-shared key authentication - consider certificate-based authentication",
    "AGG_MODE": "Aggressive Mode supported - reveals identity and is vulnerable to offline attacks",
    "FING_VID": "Vendor ID fingerprinting possible via VID payload",
    "FING_BACKOFF": "Implementation fingerprinting possible via backoff pattern"
}

# IKEv1 Transform Payloads for testing
MAIN_MODE_TRANSFORMS = [
    "1,1,1,1",      # DES-CBC, MD5, DH Group 1
    "1,2,1,1",      # DES-CBC, SHA1, DH Group 1
    "5,1,1,1",      # 3DES-CBC, MD5, DH Group 1
    "5,2,1,1",      # 3DES-CBC, SHA1, DH Group 1
    "5,1,2,1",      # 3DES-CBC, MD5, DH Group 2
    "5,2,2,1",      # 3DES-CBC, SHA1, DH Group 2
    "7/128,1,2,1",  # AES-128, MD5, DH Group 2
    "7/128,2,2,1",  # AES-128, SHA1, DH Group 2
    "7/256,2,14,1", # AES-256, SHA1, DH Group 14
    "7/256,5,14,1", # AES-256, SHA256, DH Group 14
]

AGGRESSIVE_MODE_TRANSFORMS = [
    "1,1,1,1",      # DES-CBC, MD5, DH Group 1
    "5,2,2,1",      # 3DES-CBC, SHA1, DH Group 2
    "7/128,2,14,1", # AES-128, SHA1, DH Group 14
    "7/256,5,14,1", # AES-256, SHA256, DH Group 14
]

# --- Core Functions ---

def run_command(cmd: List[str], timeout: int = 30) -> str:
    """Runs a shell command with a specified timeout and captures the output."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {' '.join(cmd)}")
        return ""
    except Exception as e:
        logger.error(f"Command failed: {' '.join(cmd)} - {e}")
        return ""

def check_ike_dependency():
    """Checks if ike-scan is installed and executable."""
    try:
        result = subprocess.run(["which", "ike-scan"], capture_output=True, text=True, check=False)
        if result.returncode == 0:
            logger.info(f"ike-scan found: {result.stdout.strip()}")
            return True
        else:
            logger.error("ike-scan not found. Please install ike-scan to continue.")
            return False
    except FileNotFoundError:
        logger.error("Error checking for ike-scan. The 'which' command may not be available.")
        return False


# --- Scanning and Fingerprinting Functions ---

def check_ikev1(vpns: Dict, ip: str):
    """Checks for IKEv1 support and attempts to fingerprint Vendor IDs."""
    logger.info(f"Discovering IKEv1 services for {ip}")
    command = ["ike-scan", ip, "--vendor", "f4ed19e0c114eb516faaac0ee37daf2807b4381f", "--vendor", "1f07f70eaa6514d3b0fa96542a500300"]
    output = run_command(command, timeout=10)
    
    if output and "Handshake returned" in output:
        logger.info(f"IKEv1 supported by {ip}")
        vpns[ip]["v1"] = True
        vpns[ip]["handshake"] = output
        fingerprint_vid(vpns, ip, output)

def check_ikev2(vpns: Dict, ip: str):
    """Checks for IKEv2 support."""
    logger.info(f"Checking IKEv2 support for {ip}")
    output = run_command(["ike-scan", "--ikev2", ip], timeout=10)
    
    logger.info(f"DEBUG: IKEv2 scan output for {ip}: {repr(output[:200])}")
    
    ikev2_patterns = ["IKE_SA_INIT", "IKEv2", "Handshake returned", "returned notify"]
    if output and any(p in output for p in ikev2_patterns):
        pattern = next((p for p in ikev2_patterns if p in output), "Unknown")
        logger.info(f"IKEv2 supported by {ip} (detected via: {pattern})")
        vpns[ip]["v2"] = True
        vpns[ip]["ikev2_handshake"] = output

def fingerprint_vid(vpns: Dict, ip: str, handshake: str):
    """Extracts and analyzes Vendor ID payloads from a handshake string."""
    if "vid" not in vpns[ip]:
        vpns[ip]["vid"] = []

    vid_matches = re.findall(r"VID=([a-fA-F0-9]+)(?:\s+\(([^)]+)\))?", handshake)
    transform_match = re.search(r"SA=(\([^)]+\))", handshake)
    transform = transform_match.group(1) if transform_match else "N/A"

    for hex_vid, description in vid_matches:
        description = description if description else hex_vid
        if "draft-ietf" in description:
            continue
            
        if description and description not in [v[0] for v in vpns[ip]["vid"]]:
            vpns[ip]["vid"].append((description, handshake))
            logger.info(f"Vendor ID for {ip}: {description} (Transform: {transform})")

def fingerprint_implementation(vpns: Dict, ip: str):
    """Performs implementation fingerprinting via backoff analysis."""
    logger.info(f"Fingerprinting {ip} via backoff analysis")
    output = run_command(["ike-scan", "--showbackoff", ip], timeout=10)
    vpns[ip]["showbackoff"] = output if output else "Unknown"

def test_transforms(vpns: Dict, ip: str):
    """Tests supported IKEv1 Main Mode encryption/hash algorithms."""
    logger.info(f"Testing encryption algorithms for {ip}")
    results = []
    for i, transform in enumerate(MAIN_MODE_TRANSFORMS, 1):
        progress = (i / len(MAIN_MODE_TRANSFORMS)) * 100
        print(f"\r[{'█' * int(progress / 100 * 30):30}] {progress:.1f}% - Main Mode Transform: {transform}", end="", flush=True)
        
        output = run_command(["ike-scan", "--trans", transform, ip], timeout=5)
        if output and "Handshake returned" in output:
            results.append((transform, output))
            fingerprint_vid(vpns, ip, output)
    
    print()
    vpns[ip]["transforms"] = results

def test_aggressive_mode(vpns: Dict, ip: str):
    """Tests for IKEv1 Aggressive Mode support and attempts to extract hashes."""
    logger.info(f"Testing Aggressive Mode for {ip}")
    results = []
    extracted_hashes = []
    
    for i, transform in enumerate(AGGRESSIVE_MODE_TRANSFORMS, 1):
        progress = (i / len(AGGRESSIVE_MODE_TRANSFORMS)) * 100
        print(f"\r[{'█' * int(progress / 100 * 30):30}] {progress:.1f}% - Aggressive Mode Transform: {transform}", end="", flush=True)
        
        output = run_command(["ike-scan", "--aggressive", "--trans", transform, "--id", "testuser", ip], timeout=5)
        
        if output and "Handshake returned" in output:
            logger.info(f"DEBUG: Aggressive mode handshake detected for {ip}")
            results.append((transform, output))
            fingerprint_vid(vpns, ip, output)
            
            hash_data = extract_aggressive_hash(output, transform, "testuser")
            if hash_data:
                extracted_hashes.append(hash_data)
                logger.warning(f"HASH EXTRACTED from {ip} using {transform}: {hash_data['hash']}")
    
    print()
    vpns[ip]["aggressive"] = results
    vpns[ip]["extracted_hashes"] = extracted_hashes

def extract_aggressive_hash(output: str, transform: str, identity: str) -> Dict:
    """Extracts a hash from an IKEv1 Aggressive Mode response."""
    hash_match = re.search(r"Hash=\(([a-fA-F0-9]{32,})\)", output)
    if not hash_match:
        return None
        
    hash_value = hash_match.group(1)
    hash_len = len(hash_value)
    hash_type = "unknown"
    if hash_len == 32: hash_type = "MD5"
    elif hash_len == 40: hash_type = "SHA1"
    elif hash_len == 64: hash_type = "SHA256"

    if hash_type != "unknown" and not hash_value.startswith("0000"):
        logger.info(f"DEBUG: Valid hash found: {hash_type} - {hash_value}")
        return {
            "hash": hash_value, "hash_type": hash_type, "transform": transform,
            "identity": identity, "full_output": output,
            "crackable": hash_type in ["MD5", "SHA1"]
        }
    return None

def test_ikev2_features(vpns: Dict, ip: str):
    """Tests for IKEv2-specific features like certificate requests."""
    logger.info(f"Testing IKEv2-specific features for {ip}")
    output = run_command(["ike-scan", "--ikev2", "--certreq", ip], timeout=5)
    if output:
        vpns[ip]["ikev2_certreq"] = True


# --- Analysis and Reporting ---

def analyze_security_flaws(vpns: Dict) -> Dict:
    """Analyzes discovered configurations for security flaws, avoiding duplicates."""
    logger.info("Analyzing security flaws")
    results = {"services": {}, "summary": {}}
    
    for ip, data in vpns.items():
        results["services"][ip] = {"flaws": [], "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
        added_flaws = set()

        def add_unique_flaw(description: str, severity: str, payload: str = ""):
            """Adds a flaw to the results if it hasn't been added for the current IP."""
            if description not in added_flaws:
                results["services"][ip]["flaws"].append({"description": description, "severity": severity, "data": payload})
                results["services"][ip]["severity_counts"][severity] += 1
                added_flaws.add(description)

        # --- Flaw Identification ---

        # Basic service-level flaws
        if data.get("v1") or data.get("v2"): add_unique_flaw(FLAWS["DISC"], "medium")
        if data.get("v1"): add_unique_flaw(FLAWS["IKEV1"], "high")
        if data.get("aggressive"): add_unique_flaw(FLAWS["AGG_MODE"], "high")

        # Aggregate all successful handshakes for cipher analysis
        all_handshakes_text = " ".join(
            [data.get("handshake", "")] +
            [data.get("ikev2_handshake", "")] +
            [h for _, h in data.get("transforms", [])] +
            [h for _, h in data.get("aggressive", [])]
        )

        # Analyze aggregated handshakes for weak crypto
        if "Enc=DES" in all_handshakes_text and "Enc=3DES" not in all_handshakes_text: add_unique_flaw(FLAWS["ENC_DES"], "critical", all_handshakes_text)
        if "Enc=3DES" in all_handshakes_text: add_unique_flaw(FLAWS["ENC_3DES"], "high", all_handshakes_text)
        if "Hash=MD5" in all_handshakes_text: add_unique_flaw(FLAWS["HASH_MD5"], "critical", all_handshakes_text)
        if "Hash=SHA1" in all_handshakes_text: add_unique_flaw(FLAWS["HASH_SHA1"], "high", all_handshakes_text)
        if "Group=1:modp768" in all_handshakes_text: add_unique_flaw(FLAWS["DHG_1"], "critical", all_handshakes_text)
        if "Group=2:modp1024" in all_handshakes_text: add_unique_flaw(FLAWS["DHG_2"], "high", all_handshakes_text)
        if "Auth=PSK" in all_handshakes_text: add_unique_flaw(FLAWS["AUTH_PSK"], "medium", all_handshakes_text)

        # Hash extraction flaws
        for hash_data in data.get("extracted_hashes", []):
            desc = f"HASH EXTRACTED: {hash_data.get('hash_type')} hash from Aggressive Mode ({hash_data.get('hash')[:16]}...)"
            add_unique_flaw(desc, "critical", hash_data)
            
        # Fingerprinting flaws
        for vid, handshake in data.get("vid", []):
            add_unique_flaw(f"{FLAWS['FING_VID']}: {vid}", "low", handshake)
        if data.get("showbackoff", "Unknown") != "Unknown":
            add_unique_flaw(f"{FLAWS['FING_BACKOFF']}: {data['showbackoff']}", "low")

    # --- Final Summary Calculation ---
    summary = {"total_hosts": len(vpns), "critical": 0, "high": 0, "medium": 0, "low": 0}
    for service_data in results["services"].values():
        for severity, count in service_data["severity_counts"].items():
            summary[severity] += count
    results["summary"] = summary
    return results

def generate_xml_report(results: Dict, filename: str):
    """Generates an XML report from the scan results."""
    root = ET.Element("iker_scan")
    ET.SubElement(root, "scan_info", **results["scan_info"])
    summary = ET.SubElement(root, "summary")
    for severity, count in results["summary"].items():
        ET.SubElement(summary, severity).text = str(count)
    
    services = ET.SubElement(root, "services")
    for ip, service_data in results["services"].items():
        service = ET.SubElement(services, "service", ip=ip)
        flaws_elem = ET.SubElement(service, "flaws")
        for flaw in service_data["flaws"]:
            ET.SubElement(flaws_elem, "flaw", severity=flaw["severity"]).text = flaw["description"]
    
    tree = ET.ElementTree(root)
    ET.indent(tree, space="\t", level=0)
    tree.write(filename, encoding="utf-8", xml_declaration=True)

def print_console_report(results: Dict, vpns: Dict):
    """Prints a summary and detailed results to the console."""
    summary = results["summary"]
    logger.info("\n" + "="*60 + "\nSCAN RESULTS SUMMARY\n" + "="*60)
    logger.info(f"Total hosts scanned: {summary['total_hosts']}")
    logger.info(f"Critical issues: {summary['critical']}")
    logger.info(f"High severity issues: {summary['high']}")
    logger.info(f"Medium severity issues: {summary['medium']}")
    logger.info(f"Low severity issues: {summary['low']}")
    logger.info("="*60 + "\n")

    for ip, service_data in results["services"].items():
        logger.info(f"Host: {ip}")
        versions = []
        if vpns[ip].get("v1"): versions.append("IKEv1")
        if vpns[ip].get("v2"): versions.append("IKEv2")
        logger.info(f"  Supported versions: {', '.join(versions) or 'None'}")
        logger.info(f"  Total issues: {len(service_data['flaws'])}")
        
        for severity in ["critical", "high", "medium", "low"]:
            flaws = [f["description"] for f in service_data["flaws"] if f["severity"] == severity]
            if flaws:
                logger.info(f"    {severity.upper()}: {len(flaws)}")
                for desc in flaws:
                    logger.info(f"      - {desc}")
        logger.info("")

def generate_reports(vpns: Dict, start_time: str, end_time: str):
    """Generates all reports (JSON, XML, Console)."""
    logger.info("Generating reports...")
    results = analyze_security_flaws(vpns)
    results["scan_info"] = {
        "start_time": start_time,
        "end_time": end_time,
        "targets": list(vpns.keys())
    }
    
    xml_file = "iker_output.xml"
    json_file = "iker_output.json"
    
    # Generate file reports
    generate_xml_report(results, xml_file)
    with open(json_file, "w") as f:
        json.dump(results, f, indent=2)
    
    # Print console report
    print_console_report(results, vpns)
    
    logger.info("Detailed reports saved to:")
    logger.info(f"  XML: {xml_file}")
    logger.info(f"  JSON: {json_file}")

# --- Main Execution ---

def scan_target(ip: str) -> Dict:
    """Performs a comprehensive scan of a single target IP."""
    logger.info(f"Starting comprehensive scan of {ip}")
    vpn_data = {ip: {"v1": False, "v2": False, "vid": [], "transforms": [], "aggressive": [], "extracted_hashes": []}}
    
    check_ikev1(vpn_data, ip)
    check_ikev2(vpn_data, ip)
    
    if not vpn_data[ip].get("v1") and not vpn_data[ip].get("v2"):
        logger.warning(f"No IKE services found on {ip}")
        return vpn_data
    
    logger.info(f"Analyzing discovered service at {ip}")
    fingerprint_implementation(vpn_data, ip)
    test_transforms(vpn_data, ip)
    test_aggressive_mode(vpn_data, ip)
    
    if vpn_data[ip].get("v2"):
        test_ikev2_features(vpn_data, ip)
    
    logger.info(f"Completed analysis of {ip}")
    return vpn_data

def main():
    """Main function to parse arguments and orchestrate the scan."""
    parser = argparse.ArgumentParser(
        description="iker v2.1 - IPsec VPN Security Scanner",
        epilog="Scans for IKE/IPsec VPNs and assesses their security posture."
    )
    parser.add_argument("targets", nargs="+", help="One or more target IP addresses or hostnames")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of concurrent threads (default: 1)")
    
    args = parser.parse_args()
    
    logger.info("iker v2.1 - IPsec VPN Security Scanner")
    logger.info("Original by Julio Gomez, refactored and enhanced by nullenc0de.")
    
    if not check_ike_dependency():
        return 1
        
    start_time = datetime.now()
    logger.info(f"Scan started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Targets: {', '.join(args.targets)} | Threads: {args.threads}")
    
    all_vpns = {}
    if args.threads > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_ip = {executor.submit(scan_target, ip): ip for ip in args.targets}
            for future in as_completed(future_to_ip):
                try:
                    all_vpns.update(future.result())
                except Exception as e:
                    logger.error(f"Scan failed for {future_to_ip[future]}: {e}")
    else:
        for target in args.targets:
            all_vpns.update(scan_target(target))

    end_time = datetime.now()
    logger.info(f"Scan completed at {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Total scan duration: {end_time - start_time}")

    if all_vpns:
        generate_reports(all_vpns, start_time.strftime('%Y-%m-%d %H:%M:%S'), end_time.strftime('%Y-%m-%d %H:%M:%S'))
    else:
        logger.warning("No responsive IKE hosts found. No report generated.")
    
    logger.info("Scan finished.")
    return 0

if __name__ == "__main__":
    exit(main())
