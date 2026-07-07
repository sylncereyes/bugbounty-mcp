"""
Test suite for scope enforcement in bugbounty-mcp tools.

This test verifies:
1. target_id is a required parameter (no default value) in tool signatures
2. Functions raise ValueError when target_id is missing or URL is out-of-scope
3. No HTTP requests are made when URL is out-of-scope (fail-closed)
4. Future: Redirect guard - each hop must be validated for scope

Run with: python -m pytest tests/test_scope_enforcement.py -v
"""
import pytest
import asyncio
import ast
import re
import os
import sys
from urllib.parse import urljoin
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, '/home/kali/bugbounty-mcp')

from tools.db import is_in_scope, init_db, add_target
from tools.http_utils import secure_request


# ============================================================================
# SECTION 1: AST-based signature verification
# ============================================================================

def check_tool_signatures():
    """Check all tool files for proper target_id signatures."""
    issues = []
    tool_files = [
        'tools/a01_access_control.py',
        'tools/a02_misconfiguration.py',
        'tools/a03_supply_chain.py',
        'tools/a04_cryptography.py',
        'tools/a05_injection.py',
        'tools/a06_insecure_design.py',
        'tools/a07_authentication.py',
        'tools/a08_integrity.py',
    ]
    
    for filepath in tool_files:
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            # Check for target_id = None pattern
            if 'target_id: int = None' in content:
                issues.append(f"{filepath}: Found 'target_id: int = None' (should be required)")
            # Check for target_id is not None and not is_in_scope pattern
            if 'target_id is not None and not is_in_scope' in content:
                issues.append(f"{filepath}: Found fail-open pattern 'target_id is not None and not is_in_scope'")
        except FileNotFoundError:
            pass
    
    return issues


class TestSignatureEnforcement:
    """Verify that target_id is required in all tool function signatures."""
    
    def test_no_target_id_default_none(self):
        """Ensure target_id has no default value in any tool function."""
        issues = check_tool_signatures()
        assert len(issues) == 0, f"Found fail-open signatures: {issues}"
    
    def test_target_id_positioned_before_optional(self):
        """Ensure target_id comes before optional parameters (Python syntax rule)."""
        tool_files = [
            'tools/a01_access_control.py',
            'tools/a05_injection.py',
            'tools/a06_insecure_design.py',
            'tools/a08_integrity.py',
        ]
        issues = []
        for filepath in tool_files:
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                # Look for pattern: def func(..., param: type = default, target_id: int)
                # This is a syntax error in Python
                pattern = r'async def \w+\([^)]*,\s*\w+:\s*str\s*=\s*"[^"]*",\s*target_id:\s*int[^)]*\)'
                if re.search(pattern, content):
                    issues.append(f"{filepath}: target_id appears after optional param with default")
            except FileNotFoundError:
                pass
        assert len(issues) == 0, f"Parameter ordering issues: {issues}"


# ============================================================================
# SECTION 2: Wildcard scope matching tests
# ============================================================================

class TestWildcardScope:
    """Test wildcard and apex domain matching in is_in_scope."""
    
    def setup_method(self):
        """Initialize test database with scope."""
        init_db()
        # Using a target we know exists for tests - scope passed to add_target
        target_id = add_target('test-target-1', 'https://example.com', scope=['*.example.com'])
        self.target_id = target_id
    
    def test_exact_domain_match(self):
        """Test exact domain matching."""
        assert is_in_scope(self.target_id, 'https://example.com/path')
    
    def test_subdomain_match(self):
        """Test wildcard subdomain matching."""
        assert is_in_scope(self.target_id, 'https://api.example.com/path')
        assert is_in_scope(self.target_id, 'https://v1.api.example.com/path')
    
    def test_apex_included_with_wildcard(self):
        """Test that *.example.com also matches example.com (apex)."""
        assert is_in_scope(self.target_id, 'https://example.com/page')
    
    def test_outside_scope_rejected(self):
        """Test that domains outside scope are rejected."""
        assert not is_in_scope(self.target_id, 'https://evil.com/path')
        assert not is_in_scope(self.target_id, 'https://example.org/path')


# ============================================================================
# SECTION 3: Runtime behavior tests (sync wrapper for async)
# ============================================================================

class TestRuntimeBehavior:
    """Test runtime behavior of scope enforcement."""
    
    def setup_method(self):
        init_db()
        self.target_id = add_target('test-target', 'https://example.com', scope=['*.example.com'])

    def test_out_of_scope_rejects_before_http_call(self):
        """
        When URL is out-of-scope, the function should:
        1. Return error dict (fail-closed)
        2. NOT make any HTTP requests
        """
        from tools.a02_misconfiguration import security_headers_check
        
        async def run_test():
            with patch('tools.a02_misconfiguration.secure_request', new_callable=AsyncMock) as mock_req:
                result = await security_headers_check('https://evil.com', target_id=self.target_id)
                return result, mock_req
        
        result, mock_req = asyncio.run(run_test())
        
        # Should return error dict
        assert 'error' in result
        assert 'out of scope' in result['error'].lower()
        # No HTTP request should have been made
        mock_req.assert_not_called()

    def test_in_scope_allows_http_call(self):
        """When URL is in-scope, HTTP request should be made."""
        from tools.a02_misconfiguration import security_headers_check
        
        async def run_test():
            with patch('tools.a02_misconfiguration.secure_request', new_callable=AsyncMock) as mock_req:
                mock_req.return_value = MagicMock(status_code=200, text="OK", headers={})
                await security_headers_check('https://api.example.com', target_id=self.target_id)
                return mock_req
        
        mock_req = asyncio.run(run_test())
        # HTTP request should have been made
        mock_req.assert_called()


# ============================================================================
# SECTION 4: Redirect guard test (expected to FAIL until implemented)
# ============================================================================

class TestRedirectGuard:
    """
    Test that redirects are validated against scope.
    
    EXPECTED FAILURE: This test FAILS until redirect guard is implemented.
    """
    
    @pytest.mark.xfail(
        reason="security_headers_check tidak melakukan manual redirect-following, "
               "sehingga test ini tidak benar-benar menguji redirect-scope-guard. "
               "Tidak ada logic 3xx/Location handling di http_utils.py. "
               "xfail sampai redirect guard sungguhan dibangun di secure_request().",
        strict=False,
    )
    def test_redirect_to_out_of_scope_should_fail(self):
        """
        When a request redirects to an out-of-scope URL, the tool should:
        1. Detect the redirect
        2. Validate the new URL against scope
        3. Raise ValueError or return error (NOT follow the redirect)
        
        Currently this test FAILS because redirect guard is not implemented.
        """
        from tools.a02_misconfiguration import security_headers_check
        
        async def run_test():
            with patch('tools.a02_misconfiguration.secure_request', new_callable=AsyncMock) as mock_req:
                # Setup: first call returns 302 to evil.com, second call is what we want to prevent
                mock_req.side_effect = [
                    MagicMock(status_code=302, headers={'Location': 'https://evil.com/steal'}),
                    MagicMock(status_code=200, text="Stolen!")
                ]
                
                await security_headers_check('https://example.com', target_id=1)
                return mock_req.call_count
        
        call_count = asyncio.run(run_test())
        
        # If redirect guard is NOT implemented, secure_request will be called twice
        # (once for initial, once for redirect following)
        # If implemented, it should be called only once (stops at 302)
        assert call_count == 1, f"VULNERABILITY: Request followed redirect to out-of-scope domain. Call count: {call_count}"


# ============================================================================
# SECTION 5: Real redirect guard tests (testing secure_request directly)
# ============================================================================

class TestRedirectGuardReal:
    """Real tests for redirect scope guard - testing secure_request directly."""

    def setup_method(self):
        init_db()
        # Add target with scope for example.com
        self.target_id = add_target('redirect-test', 'https://example.com', scope=['*.example.com'])

    @pytest.mark.asyncio
    async def test_manual_redirect_follows_in_scope(self):
        """Redirect ke domain yang SAMA scope-nya harus berhasil di-follow."""
        from tools.http_utils import secure_request
        from unittest.mock import AsyncMock, MagicMock
        
        mock_client = AsyncMock()
        mock_client.request.side_effect = [
            MagicMock(status_code=302, headers={"Location": "https://example.com/new"}),
            MagicMock(status_code=200, headers={}, text="OK"),
        ]
        res = await secure_request(
            mock_client, "GET", "https://example.com/old",
            target_id=self.target_id, dry_run=False, manual_follow_redirects=True,
        )
        assert mock_client.request.call_count == 2
        assert res.status_code == 200

    @pytest.mark.asyncio
    async def test_manual_redirect_blocks_out_of_scope(self):
        """Redirect ke domain LUAR scope harus di-block, bukan di-follow."""
        from tools.http_utils import secure_request
        from unittest.mock import AsyncMock, MagicMock
        
        mock_client = AsyncMock()
        mock_client.request.return_value = MagicMock(
            status_code=302, headers={"Location": "https://evil.com/steal"}
        )
        with pytest.raises(ValueError):  # scope validation harus raise
            await secure_request(
                mock_client, "GET", "https://example.com/old",
                target_id=self.target_id, dry_run=False, manual_follow_redirects=True,
            )
        # Pastikan HANYA request awal yang terjadi, TIDAK follow ke evil.com
        assert mock_client.request.call_count == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])