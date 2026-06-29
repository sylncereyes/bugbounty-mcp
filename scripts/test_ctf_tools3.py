#!/usr/bin/env python3
"""Test get_ctf_writeup_content for both CTFtime and external."""

import sys
sys.path.insert(0, '/home/kali/bugbounty-mcp')
from tools.ctf_writeups_kb import get_ctf_writeup_content
import json

# Test 1: Writeup 40840 - has external content (already tested, external)
print("=== TEST 1: Writeup 40840 (external content) ===")
content1 = get_ctf_writeup_content(40840)
print(json.dumps({k: v[:200] if k == "content" else v for k, v in content1.items()}, indent=2))

# Test 2: Find one with content directly on CTFtime
# Let's test a few to find one with local content
print("\n=== TEST 2: Search for writeups with local content ===")
# We need to test manually - let's check a few recent ones
for wpid in [40890, 40889, 40888, 40887, 40886]:
    content = get_ctf_writeup_content(wpid)
    stype = content.get("source_type", "unknown")
    clen = len(content.get("content", ""))
    print(f"  Writeup {wpid}: source_type={stype}, content_len={clen}")
    if stype == "ctftime" and clen > 200:
        print(f"  *** Found CTFtime-local content! ***")
        print(json.dumps({k: v[:300] if k == "content" else v for k, v in content.items()}, indent=2))
        break