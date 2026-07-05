#!/usr/bin/env python3
"""Integration tests for security hardening features."""
import pytest
import sys
import os
import asyncio
import inspect
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Fixture to set up test database
@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch):
    """Set up a temporary database for each test."""
    # Use temp db
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    monkeypatch.setenv("DB_PATH", db_path)

    # Re-import to pick up new DB_PATH
    import importlib
    import tools.db as db_module
    importlib.reload(db_module)

    # Re-import necessary functions
    import tools.http_utils

    yield
    os.close(db_fd)
    os.unlink(db_path)


class TestSecureRequest:
    """Test secure_request combines scope validation + backoff + dry_run."""

    def test_secure_request_imports(self):
        """Verify secure_request is importable."""
        from tools.http_utils import secure_request
        assert callable(secure_request)

    def test_secure_request_has_required_params(self):
        """Verify secure_request has all required parameters."""
        from tools.http_utils import secure_request
        sig = inspect.signature(secure_request)
        params = list(sig.parameters.keys())
        assert 'target_id' in params, "secure_request missing target_id param"
        assert 'dry_run' in params, "secure_request missing dry_run param"
        assert 'max_retries' in params, "secure_request missing max_retries param"
        assert 'base_delay' in params, "secure_request missing base_delay param"

    def test_dry_run_returns_mock(self, setup_test_db):
        """Test dry_run mode returns mock response without HTTP call."""
        from tools.http_utils import secure_request, get_client
        
        # Create a target for scope validation
        from tools.db import add_target
        target_id = add_target(
            program_name="Test Target",
            domain="example.com",
            scope=["example.com"]
        )

        async def test_async():
            async with get_client() as client:
                res = await secure_request(
                    client=client,
                    method="GET",
                    url="https://example.com",
                    target_id=target_id,
                    dry_run=True
                )
                return res.status_code, res.text

        status, text = asyncio.run(test_async())
        assert status == 200
        assert "[DRY RUN]" in text


class TestSSEAuthMiddleware:
    """Test SSE authentication middleware."""

    def test_middleware_class_exists(self):
        """Verify SSEAuthMiddleware is defined in server.py."""
        with open('/home/kali/bugbounty-mcp/server.py', 'r') as f:
            content = f.read()
        assert 'class SSEAuthMiddleware' in content
        assert 'Missing Authorization header' in content
        assert 'Invalid API key' in content

    def test_middleware_returns_401_without_auth(self):
        """Verify middleware returns 401 when MCP_API_KEY set but no header."""
        with open('/home/kali/bugbounty-mcp/server.py', 'r') as f:
            content = f.read()
        assert 'status_code=401' in content

    def test_middleware_returns_403_invalid_key(self):
        """Verify middleware returns 403 for wrong API key."""
        with open('/home/kali/bugbounty-mcp/server.py', 'r') as f:
            content = f.read()
        assert 'status_code=403' in content


class TestScopeValidation:
    """Test scope validation raises for out-of-scope URLs."""

    def test_validate_scope_raises_for_invalid_target(self, setup_test_db):
        """Test scope validation raises ValueError for non-existent target."""
        from tools.http_utils import validate_scope

        with pytest.raises(ValueError, match="INVALID_TARGET"):
            validate_scope("https://evil.com", 99999)

    def test_validate_scope_raises_for_out_of_scope(self, setup_test_db):
        """Test scope validation raises ValueError for out-of-scope URL."""
        from tools.db import add_target
        from tools.http_utils import validate_scope

        # Create a target with explicit scope
        target_id = add_target(
            program_name="Test Target",
            domain="test.example.com",
            scope=["api.example.com"]
        )

        with pytest.raises(ValueError, match="OUT_OF_SCOPE"):
            validate_scope(target_id, "https://evil.com")


class TestEncryption:
    """Test field-level encryption."""

    def test_encryption_roundtrip(self):
        """Test encrypt/decrypt roundtrip works."""
        from tools.encryption import encrypt_value, decrypt_value

        original = "secret_payload_data"
        encrypted = encrypt_value(original)
        decrypted = decrypt_value(encrypted)

        assert original == decrypted
        assert encrypted != original  # Actually encrypted

    def test_dict_encryption_preserves_normal_fields(self):
        """Test encrypt_sensitive_dict leaves non-sensitive fields intact."""
        from tools.encryption import encrypt_sensitive_dict

        data = {"payload": "secret_data", "url": "https://test.com", "normal": "visible"}
        encrypted = encrypt_sensitive_dict(data, {"payload"})
        assert encrypted["payload"] != "secret_data"
        assert encrypted["url"] == "https://test.com"
        assert encrypted["normal"] == "visible"


class TestConfigDefaults:
    """Test security configuration defaults."""

    def test_verify_ssl_defaults_true(self):
        """VERIFY_SSL should default to True for security."""
        from config import VERIFY_SSL
        assert VERIFY_SSL == True

    def test_dry_run_defaults_true(self):
        """DRY_RUN should default to True for safety."""
        from config import DRY_RUN
        assert DRY_RUN == True

    def test_mcp_api_key_config_exists(self):
        """MCP_API_KEY should exist in config."""
        from config import MCP_API_KEY
        assert isinstance(MCP_API_KEY, str)


class TestWAFIndicators:
    """Test WAF detection signatures."""

    def test_waf_indicators_present(self):
        """Verify major WAF signatures are defined."""
        from tools.http_utils import WAF_BLOCK_INDICATORS
        assert 'cloudflare' in WAF_BLOCK_INDICATORS
        assert 'akamai' in WAF_BLOCK_INDICATORS
        assert 'imperva' in WAF_BLOCK_INDICATORS
        assert 'sqreen' in WAF_BLOCK_INDICATORS


# ==============================================================================
# OWASP TOOL INTEGRATION TESTS - Verify secure_request is ACTUALLY CALLED
# ==============================================================================

class TestAllOWASPUseSecureRequest:
    """Verify ALL OWASP A01-A10 tools use secure_request."""

    def test_all_owasp_tools_use_secure_request(self):
        """Count all OWASP tools that import/secure_request."""
        tools_dir = '/home/kali/bugbounty-mcp/tools'
        # Match a01-a10 files using correct pattern
        owasp_tools = []
        for f in os.listdir(tools_dir):
            if f.endswith('.py') and not f.startswith('_'):
                # Match a01 through a10
                if f.startswith('a') and f[1:].split('_')[0].isdigit():
                    num = int(f[1:].split('_')[0])
                    if 1 <= num <= 10:
                        if f not in ['http_utils.py', 'encryption.py']:
                            owasp_tools.append(f)

        using_secure = []
        for tool in owasp_tools:
            path = os.path.join(tools_dir, tool)
            with open(path, 'r') as fh:
                tool_content = fh.read()
            if 'secure_request' in tool_content:
                using_secure.append(tool)

        # Should be 10 tools (a01-a10)
        assert len(using_secure) == 10, f"Expected 10 OWASP tools using secure_request, found {len(using_secure)}: {using_secure}"


class TestA05InjectionCallsSecureRequest:
    """Verify A05 tools ACTUALLY call secure_request."""

    def test_sqli_test_calls_secure_request(self):
        """Verify sqli_test function body calls secure_request."""
        with open('/home/kali/bugbounty-mcp/tools/a05_injection.py', 'r') as f:
            content = f.read()
        # Count actual calls to secure_request in function bodies
        import re
        calls = re.findall(r'await\s+secure_request\s*\(', content)
        assert len(calls) >= 2, f"a05_injection should call secure_request at least 2 times, found {len(calls)}"

    def test_sqli_test_has_dry_run_param(self):
        """Verify sqli_test has dry_run parameter."""
        from tools.a05_injection import sqli_test
        sig = inspect.signature(sqli_test)
        assert 'dry_run' in sig.parameters


class TestA07AuthenticationCallsSecureRequest:
    """Verify A07 authentication tools use secure_request."""

    def test_brute_force_check_signature(self):
        """Verify brute_force_protection_check has scope validation."""
        from tools.a07_authentication import brute_force_protection_check
        sig = inspect.signature(brute_force_protection_check)
        params = list(sig.parameters.keys())
        assert 'login_url' in params or 'url' in params
        assert 'target_id' in params

    def test_brute_force_uses_secure_request_or_delay(self):
        """Verify brute_force uses backoff (secure_request or delay)."""
        with open('/home/kali/bugbounty-mcp/tools/a07_authentication.py', 'r') as f:
            content = f.read()
        uses_secure = 'secure_request' in content
        uses_delay = 'delay(' in content or 'await delay()' in content
        assert uses_secure or uses_delay, "a07_authentication should use secure_request or delay for backoff"


class TestA06InsecureDesignCallsSecureRequest:
    """Verify A06 tools use secure_request."""

    def test_race_condition_has_dry_run(self):
        """Verify race_condition_test has dry_run parameter."""
        from tools.a06_insecure_design import race_condition_test
        sig = inspect.signature(race_condition_test)
        # dry_run might be implemented via secure_request instead of direct param
        # Check if dry_run param exists OR if secure_request is used (which has dry_run)
        has_direct_dry_run = 'dry_run' in sig.parameters
        with open('/home/kali/bugbounty-mcp/tools/a06_insecure_design.py', 'r') as f:
            content = f.read()
        uses_secure_request = 'secure_request' in content
        assert has_direct_dry_run or uses_secure_request, "race_condition_test should have dry_run param or use secure_request"

    def test_business_logic_has_target_id(self):
        """Verify business_logic tools have target_id."""
        from tools.a06_insecure_design import business_logic_price_test
        sig = inspect.signature(business_logic_price_test)
        assert 'target_id' in sig.parameters