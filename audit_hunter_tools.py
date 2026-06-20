"""
QA AUDIT SCRIPT — hunter.py tools verification
Tests semua 5 tools, edge cases, error handling, dan DB persistence.
"""
import asyncio
import json
import sqlite3
import sys
import time
import os

# Setup path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load env dulu
from dotenv import load_dotenv
load_dotenv()

# Import DB path
from tools.db import DB_PATH, db_connection

print("=" * 70)
print("QA AUDIT: hunter.py tools")
print("=" * 70)
print()

# Import tools (ini juga trigger _init_hunter_tables)
from tools import hunter  # noqa: F401 — triggers registration
from tools.hunter import (
    define_hunt_goal,
    osint_recon,
    logic_flow_mapper,
    escalation_advisor,
    hidden_endpoint_discovery,
)

# ─────────────────────────────────────────────────────────────
# TOOL 1: define_hunt_goal
# ─────────────────────────────────────────────────────────────
print("=" * 70)
print("TOOL 1: define_hunt_goal")
print("=" * 70)

async def test_define_hunt_goal():
    print("\n[TEST 1a] Normal call: fintech + account_takeover")
    result = await define_hunt_goal(
        target="test.com",
        industry="fintech",
        objective="account_takeover"
    )
    print(f"  Return type: {type(result).__name__}")
    print(f"  Keys: {list(result.keys())}")
    
    # Cek field wajib
    for field in ["session_id", "priority_assets", "likely_logic_flaws"]:
        found = field in result or (field in result.get("plan", {}))
        print(f"  Field '{field}': {'✅ ADA' if found else '❌ TIDAK ADA'}")
    
    session_id = result.get("session_id")
    print(f"  session_id value: {session_id}")
    
    # Verify DB persistence
    print("\n  [DB CHECK] Verify session tersimpan di SQLite...")
    with db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM hunt_sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if row:
            row_dict = dict(row)
            print(f"  ✅ Row ditemukan di DB: id={row_dict['id']}, target={row_dict['target']}, industry={row_dict['industry']}, objective={row_dict['objective']}")
        else:
            print(f"  ❌ Row TIDAK ditemukan di DB untuk session_id={session_id}")
    
    print("\n[TEST 1b] Unknown industry → fallback ke 'general'")
    r2 = await define_hunt_goal(target="x.com", industry="unknown_xyz", objective="rce")
    print(f"  industry returned: {r2.get('industry')} (expected: general)")
    assert r2.get("industry") == "general", f"FAIL: got {r2.get('industry')}"
    print("  ✅ Graceful fallback confirmed")
    
    print("\n[TEST 1c] Unknown objective → fallback ke 'business_logic'")
    r3 = await define_hunt_goal(target="y.com", industry="saas", objective="blah_blah")
    print(f"  objective returned: {r3.get('objective')} (expected: business_logic)")
    assert r3.get("objective") == "business_logic", f"FAIL: got {r3.get('objective')}"
    print("  ✅ Graceful fallback confirmed")
    
    print("\n[TEST 1d] Empty string target → error atau graceful?")
    r4 = await define_hunt_goal(target="", industry="fintech", objective="rce")
    print(f"  Result: {r4}")
    if "error" in r4:
        print("  ⚠️ Returned error dict (graceful)")
    else:
        print("  ℹ️ Saved empty target to DB (no crash)")
    
    return session_id

session_id = asyncio.run(test_define_hunt_goal())

# ─────────────────────────────────────────────────────────────
# TOOL 2: osint_recon
# ─────────────────────────────────────────────────────────────
print()
print("=" * 70)
print("TOOL 2: osint_recon")
print("=" * 70)

async def test_osint_recon():
    print("\n[TEST 2a] Normal call: example.com (real HTTP ke web.archive.org)")
    t_start = time.time()
    result = await osint_recon(target="example.com")
    t_elapsed = time.time() - t_start
    
    print(f"  Elapsed: {t_elapsed:.2f}s")
    print(f"  Keys returned: {list(result.keys())}")
    print(f"  wayback_total_archived: {result.get('wayback_total_archived')}")
    print(f"  wayback_interesting_urls count: {len(result.get('wayback_interesting_urls', []))}")
    print(f"  js_files_scanned: {result.get('js_files_scanned')}")
    print(f"  js_endpoints count: {len(result.get('js_endpoints', []))}")
    print(f"  github_leaks count: {len(result.get('github_leaks', []))}")
    print(f"  errors: {result.get('errors', {})}")
    print(f"  total_attack_surface: {result.get('total_attack_surface')}")
    
    # Cek apakah async paralel benar jalan
    # Jika total < 6s (3 sumber x2s masing-masing) berarti paralel
    if t_elapsed < 15:
        print(f"  ⏱️ Timing: {t_elapsed:.2f}s — konsisten dengan async parallel")
    else:
        print(f"  ⚠️ Timing: {t_elapsed:.2f}s — mungkin sequential")
    
    # Cek apakah github dorking handle GITHUB_TOKEN kosong
    github_note = result.get("errors", {}).get("github")
    from config import GITHUB_TOKEN
    if not GITHUB_TOKEN:
        print(f"\n[TEST 2b] GITHUB_TOKEN kosong — apakah graceful?")
        if github_note:
            print(f"  ✅ Graceful: errors.github = '{github_note}'")
        else:
            # Bisa juga tidak ada error key sama sekali (skip)
            github_leaks = result.get("github_leaks", [])
            print(f"  ℹ️ github_leaks: {github_leaks}")
            # Cek langsung _github_dork
            from tools.hunter import _github_dork
            r = await _github_dork("test.com")
            print(f"  _github_dork result: {r}")
            if "note" in r:
                print(f"  ✅ Graceful skip: '{r['note']}'")
    else:
        print(f"\n[TEST 2b] GITHUB_TOKEN tersedia — skip test ini")
    
    print("\n[TEST 2c] Session linking ke DB")
    if session_id:
        r2 = await osint_recon(target="example.com", session_id=session_id)
        with db_connection() as conn:
            row = conn.execute(
                "SELECT * FROM osint_results WHERE session_id = ?", (session_id,)
            ).fetchone()
        if row:
            row_dict = dict(row)
            print(f"  ✅ osint_results row saved: target={row_dict['target']}, result_type={row_dict['result_type']}")
        else:
            print(f"  ❌ osint_results row NOT saved for session_id={session_id}")

asyncio.run(test_osint_recon())

# ─────────────────────────────────────────────────────────────
# TOOL 3: logic_flow_mapper
# ─────────────────────────────────────────────────────────────
print()
print("=" * 70)
print("TOOL 3: logic_flow_mapper")
print("=" * 70)

async def test_logic_flow_mapper():
    print("\n[TEST 3a] flow_type='payment'")
    r = await logic_flow_mapper(base_url="https://test.com/checkout", flow_type="payment")
    print(f"  Keys: {list(r.keys())}")
    print(f"  flow_type: {r.get('flow_type')}")
    print(f"  total_test_cases: {r.get('total_test_cases')}")
    
    # Verifikasi test cases yang dispesifikasikan di spec
    required_desc_fragments = [
        "Negative amount",
        "Currency confusion",
        "Race condition",
        "Coupon",
        "Refund",
    ]
    print("\n  Checking required test cases:")
    test_cases = r.get("test_cases", [])
    descriptions = [tc.get("description", "") for tc in test_cases]
    for frag in required_desc_fragments:
        found = any(frag.lower() in d.lower() for d in descriptions)
        print(f"    [{('✅' if found else '❌')}] '{frag}'")
    
    print(f"\n  Sample test case #1: {json.dumps(test_cases[0], indent=4) if test_cases else 'NONE'}")
    
    print("\n[TEST 3b] Unknown flow_type='random_type' — graceful atau crash?")
    r2 = await logic_flow_mapper(base_url="https://test.com", flow_type="random_type")
    print(f"  Result: {r2}")
    if "error" in r2:
        print("  ✅ Graceful error dict returned (tidak crash)")
        print(f"  Error message: {r2['error']}")
    else:
        print("  ❌ Tidak return error, tapi juga tidak crash — check output")
    
    print("\n[TEST 3c] Semua flow_type yang tersedia")
    from tools.hunter import _FLOW_TEST_CASES
    available = sorted(_FLOW_TEST_CASES.keys())
    print(f"  Available flow types: {available}")
    for ft in available:
        r3 = await logic_flow_mapper(base_url="https://test.com", flow_type=ft)
        tc_count = r3.get("total_test_cases", 0)
        print(f"    [{('✅' if tc_count > 0 else '❌')}] {ft}: {tc_count} test cases")

asyncio.run(test_logic_flow_mapper())

# ─────────────────────────────────────────────────────────────
# TOOL 4: escalation_advisor
# ─────────────────────────────────────────────────────────────
print()
print("=" * 70)
print("TOOL 4: escalation_advisor")
print("=" * 70)

async def test_escalation_advisor():
    print("\n[TEST 4a] finding_type='xss'")
    r = await escalation_advisor(
        finding_type="xss",
        current_impact="reflected XSS di search param"
    )
    print(f"  Keys: {list(r.keys())}")
    print(f"  finding_type: {r.get('finding_type')}")
    print(f"  total_escalation_paths: {r.get('total_escalation_paths')}")
    print(f"  escalation_paths count: {len(r.get('escalation_paths', []))}")
    
    # Sample first path
    paths = r.get("escalation_paths", [])
    if paths:
        print(f"\n  Sample path #1: {json.dumps(paths[0], indent=4)}")
    
    print("\n[TEST 4b] Test SEMUA 10 finding_type dari spec:")
    all_types = ["xss", "sqli", "idor", "ssrf", "open_redirect", 
                 "info_disclosure", "csrf", "xxe", "rce", "lfi"]
    
    from tools.hunter import _ESCALATION_KB
    
    for ft in all_types:
        r2 = await escalation_advisor(finding_type=ft, current_impact=f"test {ft}")
        paths_count = r2.get("total_escalation_paths", 0)
        in_kb = ft in _ESCALATION_KB
        has_error = "error" in r2
        status = "✅" if (in_kb and paths_count > 0 and not has_error) else "❌"
        print(f"  [{status}] {ft}: in_KB={in_kb}, paths={paths_count}, error={has_error}")
    
    print("\n[TEST 4c] Unknown finding_type='unknown_vuln'")
    r3 = await escalation_advisor(finding_type="unknown_vuln", current_impact="test")
    print(f"  Result: {r3}")
    if "error" in r3:
        print("  ✅ Graceful error returned")
    
    print("\n[TEST 4d] Context hints — fintech context")
    r4 = await escalation_advisor(
        finding_type="idor", 
        current_impact="IDOR on /api/accounts", 
        target_context="fintech"
    )
    hints = r4.get("context_hints", [])
    print(f"  context_hints ({len(hints)} hints): {hints}")
    if hints:
        print("  ✅ Context hints tersedia")
    else:
        print("  ❌ Context hints kosong untuk fintech")

asyncio.run(test_escalation_advisor())

# ─────────────────────────────────────────────────────────────
# TOOL 5: hidden_endpoint_discovery
# ─────────────────────────────────────────────────────────────
print()
print("=" * 70)
print("TOOL 5: hidden_endpoint_discovery")
print("=" * 70)

async def test_hidden_endpoint_discovery():
    print("\n[TEST 5a] context='laravel' — apakah laravel paths termasuk?")
    from tools.hunter import _UNIVERSAL_PATHS, _FRAMEWORK_PATHS
    
    universal_count = len(_UNIVERSAL_PATHS)
    laravel_paths = _FRAMEWORK_PATHS.get("laravel", [])
    print(f"  Universal paths count: {universal_count}")
    print(f"  Laravel-specific paths: {laravel_paths}")
    
    # Verifikasi path list yang akan dicek
    paths_to_check = list(_UNIVERSAL_PATHS)
    for p in laravel_paths:
        if p not in paths_to_check:
            paths_to_check.append(p)
    print(f"  Total paths with 'laravel' context: {len(paths_to_check)}")
    print(f"  Laravel-specific additions: {[p for p in laravel_paths if p not in _UNIVERSAL_PATHS]}")
    
    # Actual HTTP call ke test.com (might fail, that's OK — test error handling)
    print("\n  [ACTUAL HTTP CALL] hidden_endpoint_discovery('https://test.com', 'laravel')")
    print("  (This makes real HTTP requests — expect timeouts/connection errors)")
    t_start = time.time()
    r = await hidden_endpoint_discovery(base_url="https://test.com", context="laravel")
    t_elapsed = time.time() - t_start
    print(f"  Elapsed: {t_elapsed:.2f}s")
    print(f"  Keys: {list(r.keys())}")
    print(f"  total_checked: {r.get('total_checked')}")
    print(f"  total_interesting: {r.get('total_interesting')}")
    print(f"  errors: {r.get('errors')}")
    print(f"  context field: {r.get('context')}")
    
    print("\n[TEST 5b] context='' (kosong) — hanya universal paths")
    r2 = await hidden_endpoint_discovery(base_url="https://example.com", context="")
    print(f"  total_checked: {r2.get('total_checked')} (expected ~{universal_count})")
    print(f"  context field: '{r2.get('context')}'")
    expected_ctx = "none (universal paths only)"
    if r2.get("context") == expected_ctx:
        print(f"  ✅ Context field correct: '{expected_ctx}'")
    else:
        print(f"  ❌ Context field mismatch: got '{r2.get('context')}'")
    
    print("\n[TEST 5c] Verify HTTP requests dibuat (cek dengan real URL)")
    print("  [INFO] Memeriksa apakah interesting endpoints ditemukan di example.com")
    interesting = r2.get("interesting", [])
    for item in interesting[:3]:
        print(f"    - {item.get('url')} [status={item.get('status')}, reason={item.get('reason')}]")
    if not interesting:
        print("    (Tidak ada interesting endpoint — normal untuk test domain)")

asyncio.run(test_hidden_endpoint_discovery())

# ─────────────────────────────────────────────────────────────
# SECTION 4: Database Schema Verification
# ─────────────────────────────────────────────────────────────
print()
print("=" * 70)
print("DATABASE SCHEMA VERIFICATION")
print("=" * 70)

print(f"\n[DB PATH] {DB_PATH}")
print("\n[SCHEMA: hunt_sessions]")
with db_connection() as conn:
    schema = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='hunt_sessions'"
    ).fetchone()
    print(f"  {schema[0] if schema else '❌ TABLE NOT FOUND'}")

print("\n[SCHEMA: osint_results]")
with db_connection() as conn:
    schema = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='osint_results'"
    ).fetchone()
    print(f"  {schema[0] if schema else '❌ TABLE NOT FOUND'}")

print("\n[ROW COUNT CHECK]")
with db_connection() as conn:
    hs_count = conn.execute("SELECT COUNT(*) FROM hunt_sessions").fetchone()[0]
    os_count = conn.execute("SELECT COUNT(*) FROM osint_results").fetchone()[0]
    print(f"  hunt_sessions rows: {hs_count}")
    print(f"  osint_results rows: {os_count}")

print("\n[SAMPLE HUNT SESSION DATA]")
with db_connection() as conn:
    rows = conn.execute("SELECT id, target, industry, objective, created_at FROM hunt_sessions ORDER BY id DESC LIMIT 3").fetchall()
    for row in rows:
        print(f"  id={row[0]}, target='{row[1]}', industry='{row[2]}', objective='{row[3]}', created_at='{row[4]}'")

# ─────────────────────────────────────────────────────────────
# SECTION 5: Error Handling — parameter sengaja salah
# ─────────────────────────────────────────────────────────────
print()
print("=" * 70)
print("ERROR HANDLING — Parameter sengaja salah")
print("=" * 70)

async def test_error_handling():
    print("\n[TEST] define_hunt_goal — target=None")
    try:
        r = await define_hunt_goal(target=None, industry="fintech", objective="rce")
        print(f"  Result: {r}")
        if "error" in r:
            print("  ✅ Graceful error dict")
        else:
            print("  ⚠️ No error but also no crash — saved None to DB")
    except Exception as e:
        print(f"  ❌ EXCEPTION RAISED (crash!): {type(e).__name__}: {e}")
    
    print("\n[TEST] logic_flow_mapper — empty string flow_type")
    try:
        r = await logic_flow_mapper(base_url="https://test.com", flow_type="")
        print(f"  Result: {r}")
        if "error" in r:
            print("  ✅ Graceful error dict")
        else:
            print("  ⚠️ Unexpected result without error")
    except Exception as e:
        print(f"  ❌ EXCEPTION RAISED (crash!): {type(e).__name__}: {e}")
    
    print("\n[TEST] escalation_advisor — finding_type=None")
    try:
        r = await escalation_advisor(finding_type=None, current_impact="test")
        print(f"  Result: {r}")
        if "error" in r:
            print("  ✅ Graceful error dict")
    except Exception as e:
        print(f"  ❌ EXCEPTION RAISED: {type(e).__name__}: {e}")
    
    print("\n[TEST] hidden_endpoint_discovery — base_url=None")
    try:
        r = await hidden_endpoint_discovery(base_url=None, context="")
        print(f"  Result keys: {list(r.keys()) if isinstance(r, dict) else type(r)}")
        if "error" in r:
            print("  ✅ Graceful error dict")
    except Exception as e:
        print(f"  ❌ EXCEPTION RAISED: {type(e).__name__}: {e}")

asyncio.run(test_error_handling())

# ─────────────────────────────────────────────────────────────
# SECTION 6: Cross-check intelligence.py vs hunter.py
# ─────────────────────────────────────────────────────────────
print()
print("=" * 70)
print("CROSS-CHECK: intelligence.py vs hunter.py")
print("=" * 70)

# Check tool name conflicts
from mcp_instance import mcp

# Get all registered tools
tools_list = mcp._tool_manager.list_tools()
tool_names = [t.name for t in tools_list]

print(f"\n[TOTAL TOOLS REGISTERED: {len(tool_names)}]")

# Count per module
hunter_tools = ["define_hunt_goal", "osint_recon", "logic_flow_mapper", "escalation_advisor", "hidden_endpoint_discovery"]
intel_tools = ["vulnx_exploitable", "searchsploit_query", "msf_module_search", "exploit_chain", "vulnx_enrich_finding"]

print("\n[Hunter tools registered?]")
for t in hunter_tools:
    found = t in tool_names
    print(f"  [{'✅' if found else '❌'}] {t}")

print("\n[Intelligence tools registered?]")
for t in intel_tools:
    found = t in tool_names
    print(f"  [{'✅' if found else '❌'}] {t}")

# Check for table conflicts
print("\n[DB TABLE CONFLICT CHECK]")
with db_connection() as conn:
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    table_names = [t[0] for t in tables]
    print(f"  All tables in DB: {table_names}")

# Check for duplicate tool names
from collections import Counter
name_counts = Counter(tool_names)
duplicates = {k: v for k, v in name_counts.items() if v > 1}
if duplicates:
    print(f"\n  ❌ DUPLICATE TOOL NAMES FOUND: {duplicates}")
else:
    print("\n  ✅ No duplicate tool names")

print("\n[ALL REGISTERED TOOLS - Full List]")
for i, name in enumerate(sorted(tool_names), 1):
    print(f"  {i:3d}. {name}")

print()
print("=" * 70)
print("AUDIT COMPLETE")
print("=" * 70)
