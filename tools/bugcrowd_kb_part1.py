"""Bugcrowd Knowledge‑Base MCP tool
Implements sync, search, get and stats for public CrowdStream disclosures.
Uses the incremental scraper defined in `scripts/sync_bugcrowd.py`.
"""
import json
from pathlib import Path

# FastMCP instance is available globally via the imported `mcp` in other tools.
# We'll import the sync function lazily to avoid heavy imports at module load.

def _load_sync():
    from importlib import import_module
    mod = import_module('scripts.sync_bugcrowd')
    return mod.sync_bugcrowd

def _load_db():
    from tools import db
    return db
