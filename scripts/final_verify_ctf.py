#!/usr/bin/env python3
"""Final verification of CTF writeup tools."""

import sys
sys.path.insert(0, '/home/kali/bugbounty-mcp')
from tools.ctf_writeups_kb import search_ctf_writeups, get_ctf_writeup_content, list_ctf_writeup_tags
import json

print("=== SEARCH 'forensics' ===")
results = search_ctf_writeups('forensics', limit=3)
print(json.dumps(results, indent=2))

print("\n=== SEARCH 'web' with tag filter ===")
results = search_ctf_writeups('web', tag='crypto', limit=3)
print(json.dumps(results, indent=2))

print("\n=== LIST TAGS ===")
tags = list_ctf_writeup_tags()
print(json.dumps(tags[:10], indent=2))

print("\n=== GET CONTENT 40891 (youtube link) ===")
content = get_ctf_writeup_content(40891)
print(f"source_type: {content.get('source_type')}")
print(f"cached: {content.get('cached')}")
print(f"content_len: {len(content.get('content', ''))}")
print(f"source_url: {content.get('source_url')[:80]}...")
print(f"disclaimer present: {'disclaimer' in content}")

print("\n=== GET CONTENT 40840 (cached external) ===")
content = get_ctf_writeup_content(40840)
print(f"source_type: {content.get('source_type')}")
print(f"cached: {content.get('cached')}")
print(f"content_len: {len(content.get('content', ''))}")
print(f"source_url: {content.get('source_url')[:80]}...")