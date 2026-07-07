import pytest

class TestBrowserAnalysisScopeGuard:
    def setup_method(self):
        from tools.db import init_db, add_target
        init_db()
        self.target_id = add_target(program_name='Test', domain='example.com', scope=['example.com'])

    @pytest.mark.asyncio
    async def test_verify_target_is_web_blocks_out_of_scope(self):
        from tools.browser_analysis import verify_target_is_web
        with pytest.raises(ValueError, match="OUT_OF_SCOPE"):
            await verify_target_is_web('https://evil.com', target_id=self.target_id)

class TestHunterScopeGuard:
    def test_osint_recon_imports_is_in_scope(self):
        # Regression test: is_in_scope harus ter-import, bukan NameError
        from tools.hunter import is_in_scope
        assert callable(is_in_scope)
