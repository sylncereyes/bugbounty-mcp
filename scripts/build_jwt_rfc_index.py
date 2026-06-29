#!/usr/bin/env python3
"""
build_jwt_rfc_index.py
Fetches and indexes JWT/JOSE-related RFCs using the existing add_rfc_to_db() function.
No new parsing logic - reuses tools/db RFC functions.
"""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import internal function to avoid MCP dependency
from tools.db import add_rfc_to_db

# JWT/JOSE RFC seed list
JWT_RFC_LIST = [
    7515,  # JSON Web Signature (JWS)
    7516,  # JSON Web Encryption (JWE)
    7517,  # JSON Web Key (JWK)
    7518,  # JSON Web Algorithms (JWA)
    7519,  # JSON Web Token (JWT)
    7520,  # Examples of Protecting Content Using JOSE
    7521,  # Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants
    7523,  # JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants
    8037,  # CFRG Elliptic Curve ECDH and Signatures in JOSE
    8725,  # JSON Web Token Best Current Practices
    9068,  # JWT Profile for OAuth 2.0 Access Tokens
    9278,  # JWK Thumbprint URI
]


def build_jwt_index():
    """Build JWT RFC index using existing add_rfc infrastructure."""
    success_count = 0
    error_count = 0
    errors = []

    for rfc_number in JWT_RFC_LIST:
        print(f"[INFO] Fetching RFC {rfc_number}...")
        result = add_rfc_to_db(rfc_number, topic_tag="JWT")

        if result.get("success"):
            success_count += 1
            print(f"[OK] RFC {rfc_number}: {result.get('title', 'OK')[:50]}...")
        else:
            error_count += 1
            errors.append(rfc_number)
            print(f"[WARN] RFC {rfc_number}: {result.get('error', 'failed')}")

        # Delay 1 second between requests (polite)
        time.sleep(1)

    print(f"\n[SUMMARY] JWT RFCs indexed: {success_count}")
    if errors:
        print(f"[WARN] Failed: {errors}")


if __name__ == "__main__":
    build_jwt_index()