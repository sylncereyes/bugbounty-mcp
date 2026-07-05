#!/usr/bin/env python3
"""
Verification script for StealthVision-MCP Security
"""
import asyncio
import sys
import os
sys.path.insert(0, os.getcwd())

async def main():
    print("=" * 60)
    print("VERIFICATION: StealthVision-MCP Security Infrastructure")
    print("=" * 60)
    
    # 1. AD Modules Cleanup
    print("\n1. AD Module Cleanup:")
    all_deleted = True
    for mod in ['kerberos_attacks.py', 'credential_dumper.py', 'smb_pwn.py', 'priv_esc.py', 'internal_pivot.py', 'ad_enumeration.py']:
        path = f'/home/kali/bugbounty-mcp/tools/{mod}'
        if os.path.exists(path):
            print(f"   ✗ FAIL: {mod} still exists")
            all_deleted = False
        else:
            print(f"   ✓ {mod} deleted")
    
    # 2. SSRF Protection Test
    print("\n2. SSRF Protection Test:")
    from tools.http_utils import _resolve_and_validate, SSRFBlockedError
    
    try:
        await _resolve_and_validate("127.0.0.1")
        print("   ✗ FAIL: 127.0.0.1 should be blocked")
        return False
    except SSRFBlockedError:
        print("   ✓ 127.0.0.1 correctly blocked")
    
    try:
        await _resolve_and_validate("169.254.169.254")
        print("   ✗ FAIL: 169.254.169.254 should be blocked")
        return False
    except SSRFBlockedError:
        print("   ✓ 169.254.169.254 correctly blocked")
    
    # 3. Branding Verification
    print("\n3. Branding Verification:")
    
    # server.py
    with open('/home/kali/bugbounty-mcp/server.py', 'r') as f:
        server_content = f.read()
    if 'StealthVision-MCP Server' in server_content and 'OWASP Top 10 2021' in server_content:
        print("   ✓ server.py: StealthVision branding + OWASP 2021")
    else:
        print("   ✗ server.py: Branding or OWASP version missing")
        return False
    
    # README.md
    with open('/home/kali/bugbounty-mcp/README.md', 'r') as f:
        readme_content = f.read()
    
    if 'StealthVision-MCP' in readme_content:
        print("   ✓ README.md: StealthVision branding")
    else:
        print("   ✗ README.md: Missing StealthVision branding")
        return False
    
    if 'OWASP Top 10 2021' in readme_content:
        print("   ✓ README.md: OWASP 2021 version")
    else:
        print("   ✗ README.md: Missing OWASP 2021 version")
        return False
    
    # 4. Import Verification
    print("\n4. Import Verification:")
    try:
        from tools.http_utils import secure_request, validate_scope, assert_safe_target, tls_connect
        print("   ✓ All required imports from tools.http_utils")
    except ImportError as e:
        print(f"   ✗ Import error: {e}")
        return False
    
    # 5. Function Signature Verification
    print("\n5. Function Signature Verification:")
    import inspect
    
    # Check secure_request signature
    from tools.http_utils import secure_request
    sig = inspect.signature(secure_request)
    if 'target_id' in sig.parameters:
        print("   ✓ secure_request has target_id parameter")
    else:
        print("   ✗ secure_request missing target_id parameter")
        return False
    
    # Check validate_scope signature
    from tools.http_utils import validate_scope
    sig = inspect.signature(validate_scope)
    if len(sig.parameters) >= 2:
        print("   ✓ validate_scope has at least 2 parameters")
    else:
        print("   ✗ validate_scope has fewer than 2 parameters")
        return False
    
    # Check assert_safe_target signature
    sig = inspect.signature(assert_safe_target)
    if 'url' in sig.parameters:
        print("   ✓ assert_safe_target has url parameter")
    else:
        print("   ✗ assert_safe_target missing url parameter")
        return False
    
    # Check tls_connect signature
    from tools.http_utils import tls_connect
    sig = inspect.signature(tls_connect)
    if len(sig.parameters) >= 2:
        print("   ✓ tls_connect has at least 2 parameters")
    else:
        print("   ✗ tls_connect has fewer than 2 parameters")
        return False
    
    print("\n" + "=" * 60)
    print("VERIFICATION SUCCESSFUL")
    print("=" * 60)
    return True

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)