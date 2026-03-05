#!/usr/bin/env python3
"""
NVD to VulnDB Converter

Fetches CVE data from the NVD API and generates a CPE-to-CVE mapping file
for use with NetIntel.

Usage:
    python nvd-to-vulndb.py --output vuln-db.json
    python nvd-to-vulndb.py --output vuln-db.json --days 30
    python nvd-to-vulndb.py --output vuln-db.json --cpe "cpe:2.3:a:apache:*"

Requirements:
    pip install requests

NVD API: https://nvd.nist.gov/developers/vulnerabilities
Rate limit: 5 requests per 30 seconds (without API key)
           50 requests per 30 seconds (with API key)
"""

import argparse
import json
import sys
import time
from datetime import datetime, timedelta
from typing import Optional

try:
    import requests
except ImportError:
    print("Error: requests library required. Install with: pip install requests")
    sys.exit(1)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
REQUEST_DELAY = 6  # seconds between requests (respect rate limit)


def fetch_cves(
    api_key: Optional[str] = None,
    days_back: Optional[int] = None,
    cpe_match: Optional[str] = None,
    start_index: int = 0
) -> dict:
    """Fetch CVEs from NVD API."""
    params = {
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": start_index,
    }

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    if days_back:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        params["pubStartDate"] = start_date.strftime("%Y-%m-%dT00:00:00.000")
        params["pubEndDate"] = end_date.strftime("%Y-%m-%dT23:59:59.999")

    if cpe_match:
        params["cpeName"] = cpe_match

    response = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=60)
    response.raise_for_status()
    return response.json()


def extract_cpe_cve_mapping(cve_item: dict) -> list:
    """Extract CPE to CVE mappings from a CVE item."""
    mappings = []

    cve_id = cve_item.get("id", "")

    # Get CVSS score (prefer v3.1, fallback to v3.0, then v2.0)
    metrics = cve_item.get("metrics", {})
    cvss = None

    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV30" in metrics:
        cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV2" in metrics:
        cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

    # Get description
    descriptions = cve_item.get("descriptions", [])
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value", "")[:200]  # Truncate for size
            break

    # Extract CPEs from configurations
    configurations = cve_item.get("configurations", [])
    cpes = set()

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable", False):
                    cpe = cpe_match.get("criteria", "")
                    if cpe:
                        cpes.add(cpe)

    for cpe in cpes:
        mappings.append({
            "cpe": cpe,
            "cve": cve_id,
            "cvss": cvss,
            "desc": desc
        })

    return mappings


def build_vulndb(
    api_key: Optional[str] = None,
    days_back: Optional[int] = None,
    cpe_match: Optional[str] = None,
    verbose: bool = False
) -> dict:
    """Build the vulnerability database."""
    vulndb = {}
    start_index = 0
    total_results = None
    processed = 0

    print("Fetching CVE data from NVD API...")

    while True:
        if verbose:
            print(f"  Fetching from index {start_index}...")

        try:
            data = fetch_cves(
                api_key=api_key,
                days_back=days_back,
                cpe_match=cpe_match,
                start_index=start_index
            )
        except requests.exceptions.RequestException as e:
            print(f"Error fetching data: {e}")
            break

        if total_results is None:
            total_results = data.get("totalResults", 0)
            print(f"Total CVEs to process: {total_results}")

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for vuln in vulnerabilities:
            cve_item = vuln.get("cve", {})
            mappings = extract_cpe_cve_mapping(cve_item)

            for mapping in mappings:
                cpe = mapping["cpe"]
                if cpe not in vulndb:
                    vulndb[cpe] = []

                vulndb[cpe].append({
                    "cve": mapping["cve"],
                    "cvss": mapping["cvss"],
                    "desc": mapping["desc"]
                })

            processed += 1

        if verbose:
            print(f"  Processed {processed}/{total_results} CVEs, {len(vulndb)} CPEs")

        start_index += RESULTS_PER_PAGE
        if start_index >= total_results:
            break

        # Rate limiting
        delay = 0.6 if api_key else REQUEST_DELAY
        time.sleep(delay)

    return vulndb


def main():
    parser = argparse.ArgumentParser(
        description="Generate CPE-to-CVE mapping from NVD API for NetIntel"
    )
    parser.add_argument(
        "--output", "-o",
        default="vuln-db.json",
        help="Output file path (default: vuln-db.json)"
    )
    parser.add_argument(
        "--api-key", "-k",
        help="NVD API key (optional, increases rate limit)"
    )
    parser.add_argument(
        "--days", "-d",
        type=int,
        help="Only fetch CVEs published in the last N days"
    )
    parser.add_argument(
        "--cpe", "-c",
        help="Filter by CPE pattern (e.g., cpe:2.3:a:apache:*)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    vulndb = build_vulndb(
        api_key=args.api_key,
        days_back=args.days,
        cpe_match=args.cpe,
        verbose=args.verbose
    )

    # Statistics
    total_cpes = len(vulndb)
    total_cves = sum(len(cves) for cves in vulndb.values())
    unique_cves = len(set(
        cve["cve"]
        for cves in vulndb.values()
        for cve in cves
    ))

    print(f"\nVulnerability database built:")
    print(f"  CPEs: {total_cpes}")
    print(f"  CVE mappings: {total_cves}")
    print(f"  Unique CVEs: {unique_cves}")

    # Write output
    with open(args.output, "w") as f:
        json.dump(vulndb, f, indent=2)

    print(f"\nOutput written to: {args.output}")

    # Show file size
    import os
    size_mb = os.path.getsize(args.output) / (1024 * 1024)
    print(f"File size: {size_mb:.2f} MB")


if __name__ == "__main__":
    main()
