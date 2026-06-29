#!/usr/bin/env python3
"""Test CTF writeup tools - more tests."""

import sys
sys.path.insert(0, '/home/kali/bugbounty-mcp')
from tools.ctf_writeups_kb import search_ctf_writeups, get_ctf_writeup_content, list_ctf_writeup_tags
import json

# Test get content for a writeup that has content directly on CTFtime (not external)
print('=== GET CONTENT TEST - CTFTIME CONTENT ===')
# Writeup 40891 was the RIFFHACK one - let's test it
content = get_ctf_writeup_content(40891)
print(json.dumps({k: v[:300] if k == "content" else v for k, v in content.items()}, indent=2))

# Test search with tag filter
print('\n=== SEARCH WITH TAG FILTER ===')
results = search_ctf_writeups('web', tag='web', limit=3)
print(json.dumps(results, indent=2))

# Test list tags
print('\n=== ALL TAGS ===')
tags = list_ctf_writeup_tags()
print(json.dumps(tags, indent=2))