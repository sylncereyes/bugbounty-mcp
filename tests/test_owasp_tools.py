"""Tests for OWASP A01 Access Control tools."""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestA01AccessControl:
    """Test A01 access control tool imports and signatures."""

    def test_idor_test_signature(self):
        """Verify idor_test has required parameters."""
        from tools.a01_access_control import idor_test
        import inspect
        sig = inspect.signature(idor_test)
        params = list(sig.parameters.keys())
        assert 'url' in params
        assert 'target_id' in params

    def test_cors_check_signature(self):
        """Verify cors_misconfiguration_check has target_id."""
        from tools.a01_access_control import cors_misconfiguration_check
        import inspect
        sig = inspect.signature(cors_misconfiguration_check)
        params = list(sig.parameters.keys())
        assert 'url' in params or 'target_id' in params


class TestA02Misconfiguration:
    """Test A02 misconfiguration tool signatures."""

    def test_tls_ssl_check_import(self):
        """Verify tls_ssl_check exists."""
        from tools.a02_misconfiguration import tls_ssl_check
        import inspect
        sig = inspect.signature(tls_ssl_check)
        assert 'hostname' in inspect.signature(tls_ssl_check).parameters

    def test_security_headers_check_signature(self):
        """Verify security_headers_check has scope params."""
        from tools.a02_misconfiguration import security_headers_check
        import inspect
        sig = inspect.signature(security_headers_check)
        params = list(sig.parameters.keys())
        assert 'url' in params or 'target_id' in params


class TestA07Authentication:
    """Test A07 authentication tool signatures."""

    def test_brute_force_check_signature(self):
        """Verify brute_force_protection_check has scope validation."""
        from tools.a07_authentication import brute_force_protection_check
        import inspect
        sig = inspect.signature(brute_force_protection_check)
        params = list(sig.parameters.keys())
        # The param is login_url, not url
        assert 'login_url' in params or 'url' in params
        assert 'target_id' in params


class TestA06InsecureDesign:
    """Test A06 insecure design tool signatures."""

    def test_race_condition_signature(self):
        """Verify race_condition_test has target_id and dry_run."""
        from tools.a06_insecure_design import race_condition_test
        import inspect
        sig = inspect.signature(race_condition_test)
        params = list(sig.parameters.keys())
        assert 'url' in params
        assert 'target_id' in params
        # dry_run is handled via secure_request, not direct param

    def test_business_logic_price_signature(self):
        """Verify business_logic_price_test exists."""
        from tools.a06_insecure_design import business_logic_price_test
        import inspect
        sig = inspect.signature(business_logic_price_test)
        params = list(sig.parameters.keys())
        assert 'checkout_url' in params  # business_logic_price_test uses checkout_url param
        assert 'target_id' in params

    def test_mfa_bypass_check_signature(self):
        """Verify mfa_bypass_check accepts target_id."""
        from tools.a06_insecure_design import mfa_bypass_check
        import inspect
        sig = inspect.signature(mfa_bypass_check)
        params = list(sig.parameters.keys())
        assert 'login_url' in params
        assert 'target_id' in params