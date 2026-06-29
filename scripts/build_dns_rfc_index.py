#!/usr/bin/env python3
"""
build_dns_rfc_index.py
Fetches and indexes DNS-related RFCs using the existing add_rfc_to_db() function.
No new parsing logic - reuses tools/db RFC functions.
"""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import internal function to avoid MCP dependency
from tools.db import add_rfc_to_db

# DNS RFC seed list
DNS_RFC_LIST = [
    1034,  # Domain Names - Concepts and Facilities
    1035,  # Domain Names - Implementation and Specification
    2181,  # Clarifications to the DNS Specification
    2308,  # Negative Caching of DNS Queries (NXDOMAIN)
    5452,  # Measures for Making DNS More Resilient against Forged Answers
    5936,  # DNS Zone Transfer Protocol (AXFR)
    1995,  # Incremental Zone Transfer in DNS (IXFR)
    1996,  # A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
    6672,  # DNAME Redirection in the DNS
    6891,  # Extension Mechanisms for DNS (EDNS(0))
    4033,  # DNS Security Introduction and Requirements
    4034,  # Resource Records for the DNS Security Extensions
    4035,  # Protocol Modifications for the DNS Security Extensions
    7766,  # DNS Transport over TCP
    7858,  # DNS over Transport Layer Security (DoT)
    8484,  # DNS Queries over HTTPS (DoH)
    7208,  # Sender Policy Framework (SPF)
    6376,  # DomainKeys Identified Mail (DKIM) Signatures
    7489,  # Domain-based Message Authentication, Reporting & Conformance (DMARC)
    7873,  # Domain Name System (DNS) Cookies
]


def build_dns_index():
    """Build DNS RFC index using existing add_rfc infrastructure."""
    success_count = 0
    error_count = 0
    errors = []

    for rfc_number in DNS_RFC_LIST:
        print(f"[INFO] Fetching RFC {rfc_number}...")
        result = add_rfc_to_db(rfc_number, topic_tag="DNS")

        if result.get("success"):
            success_count += 1
            print(f"[OK] RFC {rfc_number}: {result.get('title', 'OK')[:50]}...")
        else:
            error_count += 1
            errors.append(rfc_number)
            print(f"[WARN] RFC {rfc_number}: {result.get('error', 'failed')}")

        # Delay 1 second between requests (polite)
        time.sleep(1)

    print(f"\n[SUMMARY] DNS RFCs indexed: {success_count}")
    if errors:
        print(f"[WARN] Failed: {errors}")


if __name__ == "__main__":
    build_dns_index()