"""Tests for database module - targets, findings, and scope validation."""
import pytest
import os
import tempfile
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.db import (
    init_db, get_connection, db_connection,
    add_target, get_targets, get_target, delete_target,
    is_in_scope, validate_scope_or_fail,
    save_finding, get_findings, update_finding_status
)


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
    
    # Re-import functions from reloaded module
    global init_db, db_connection, add_target, get_targets, get_target, delete_target
    global is_in_scope, validate_scope_or_fail, save_finding, get_findings, update_finding_status
    from tools.db import (
        init_db, db_connection,
        add_target, get_targets, get_target, delete_target,
        is_in_scope, validate_scope_or_fail,
        save_finding, get_findings, update_finding_status
    )
    
    init_db()
    yield
    os.close(db_fd)
    os.unlink(db_path)


class TestTargetOperations:
    """Test target CRUD operations."""
    
    def test_add_target_returns_id(self):
        target_id = add_target(
            program_name="Test Program",
            domain="test.example.com",
            scope=["*.example.com", "test.example.com"]
        )
        assert target_id is not None
        assert isinstance(target_id, int)
    
    def test_get_targets_returns_list(self):
        add_target(program_name="Prog1", domain="a.com", scope=["a.com"])
        add_target(program_name="Prog2", domain="b.com", scope=["b.com"])
        
        targets = get_targets()
        assert len(targets) >= 2
    
    def test_get_target_returns_correct(self):
        target_id = add_target(
            program_name="Specific Test",
            domain="specific.test",
            scope=["specific.test"]
        )
        target = get_target(target_id)
        assert target is not None
        assert target["program_name"] == "Specific Test"
    
    def test_delete_target_removes(self):
        target_id = add_target(
            program_name="To Delete",
            domain="delete.test",
            scope=["delete.test"]
        )
        assert delete_target(target_id) is True
        assert get_target(target_id) is None


class TestScopeValidation:
    """Test scope validation logic."""
    
    def test_is_in_scope_exact_match(self):
        target_id = add_target(
            program_name="Scope Test",
            domain="example.com",
            scope=["api.example.com"]
        )
        assert is_in_scope(target_id, "https://api.example.com/endpoint") is True
        # other.example.com should NOT match - only explicit scope entries count
        assert is_in_scope(target_id, "https://other.example.com/endpoint") is False
    
    def test_is_in_scope_wildcard(self):
        target_id = add_target(
            program_name="Wildcard Test",
            domain="example.com",
            scope=["*.example.com"]
        )
        assert is_in_scope(target_id, "https://sub.example.com/endpoint") is True
        assert is_in_scope(target_id, "https://deep.sub.example.com/endpoint") is True
        assert is_in_scope(target_id, "https://notexample.com/endpoint") is False
    
    def test_is_in_scope_no_target_returns_false(self):
        assert is_in_scope(99999, "https://example.com") is False
    
    def test_validate_scope_or_fail_raises_for_invalid_target(self):
        with pytest.raises(ValueError, match="INVALID_TARGET"):
            validate_scope_or_fail(99999, "https://example.com")
    
    def test_validate_scope_or_fail_raises_for_out_of_scope(self):
        target_id = add_target(
            program_name="Strict Scope",
            domain="example.com",
            scope=["api.example.com"]
        )
        with pytest.raises(ValueError, match="OUT_OF_SCOPE"):
            validate_scope_or_fail(target_id, "https://evil.com")


class TestFindingOperations:
    """Test finding CRUD operations."""
    
    def test_save_finding_returns_id(self):
        target_id = add_target(
            program_name="Finding Test",
            domain="finding.test",
            scope=["*.finding.test"]
        )
        finding_id = save_finding(
            target_id=target_id,
            title="Test XSS",
            vulnerability_type="XSS",
            owasp_category="A05:2025 - Injection",
            severity="High",
            url="https://test.finding.test/search",
            parameter="q",
            payload="<script>alert(1)</script>"
        )
        assert finding_id is not None
    
    def test_get_findings_filters_by_target(self):
        target_id = add_target(
            program_name="Multi-Finding Test",
            domain="multi.test",
            scope=["multi.test"]
        )
        save_finding(target_id, "XSS", "XSS", "A05", "High", "https://multi.test")
        save_finding(target_id, "SQLi", "SQLi", "A05", "Critical", "https://multi.test")
        
        findings = get_findings(target_id=target_id)
        assert len(findings) >= 2