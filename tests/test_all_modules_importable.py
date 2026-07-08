"""
Smoke test: pastikan setiap tool module yang terdaftar di server.py::_TOOL_MODULES
benar-benar bisa di-import tanpa NameError/ImportError/AttributeError.

Ini TIDAK memvalidasi logika internal (mis. urutan argumen validate_scope yang
terbalik tetap bisa lolos import check) — cuma menangkap kelas bug "modul gagal
di-load sama sekali", persis tiga bug yang ditemukan lewat pemakaian nyata via
Hermes: NameError is_in_scope (hunter.py), dan ImportError sanitize_output
(reporting.py).

Kalau daftar _TOOL_MODULES di server.py berubah, update juga daftar di bawah ini
supaya tetap sinkron -- lihat instruksi di akhir file untuk verifikasi sinkronisasi
otomatis.
"""
import importlib
import re
from pathlib import Path

import pytest


# Daftar ini HARUS persis sama dengan _TOOL_MODULES di server.py.
# Lihat test_tool_modules_list_matches_server_py di bawah untuk verifikasi otomatis.
_TOOL_MODULES = [
    # OWASP Top 10 2021 - Live Active Testing Tools
    "tools.a01_access_control",
    "tools.a02_misconfiguration",
    "tools.a03_supply_chain",
    "tools.a04_cryptography",
    "tools.a05_injection",
    "tools.a06_insecure_design",
    "tools.a07_authentication",
    "tools.a08_integrity",
    "tools.a09_logging",
    "tools.a10_exceptions",
    # Core functionality
    "tools.recon",
    "tools.reporting",
    "tools.intelligence",
    "tools.hunter",
    "tools.knowledge_base",
    "tools.owasp_wstg",
    "tools.owasp_api_top10",
    "tools.cve_kb",
    "tools.cwe_kb",
    "tools.htb_kb",
    "tools.thm_kb",
    "tools.patt_kb",
    "tools.lolbins_kb",
    "tools.attck_capec_kb",
    "tools.exploitdb_kb",
    "tools.nuclei_kb",
    "tools.hacktricks_kb",
    "tools.seclists_kb",
    "tools.portswigger_kb",
    "tools.portswigger_notes_kb",
    "tools.rfc_kb",
    "tools.rag_engine",
    # Static knowledge / cheatsheets
    "tools.api_testing",
    "tools.cloud_testing",
    "tools.git_testing",
    "tools.container_testing",
    "tools.mode_selector",
    "tools.js_analysis",
    "tools.jwt_advanced",
    "tools.oob_testing",
    "tools.impact_scoring",
    "tools.subdomain_brute",
    "tools.graphql_mutation",
    "tools.port_scanner",
    "tools.csti_chains",
    "tools.waf_bypass",
    "tools.graphql_introspect",
    "tools.nmap_scanner",
    "tools.rate_limit_bypass",
    "tools.browser_analysis",
    "tools.external_tools",
]


@pytest.mark.parametrize("module_name", _TOOL_MODULES, ids=_TOOL_MODULES)
def test_module_imports_without_error(module_name):
    """Setiap modul di _TOOL_MODULES harus bisa di-import tanpa error.

    Kalau ini gagal, pesan errornya akan menyebutkan nama modul yang gagal
    beserta exception aslinya (NameError, ImportError, dll) -- tidak perlu
    lagi jalankan satu-satu manual seperti sebelumnya.
    """
    try:
        importlib.import_module(module_name)
    except Exception as exc:
        pytest.fail(
            f"Module '{module_name}' failed to import: "
            f"{type(exc).__name__}: {exc}"
        )


def test_tool_modules_list_matches_server_py():
    """Pastikan daftar _TOOL_MODULES di file test ini tetap sinkron dengan
    server.py. Kalau seseorang menambah/menghapus modul di server.py tanpa
    update file test ini, test ini akan gagal dan mengingatkan.
    """
    server_py = Path(__file__).parent.parent / "server.py"
    content = server_py.read_text()
    match = re.search(r"_TOOL_MODULES\s*=\s*\[(.*?)\]", content, re.S)
    assert match, "Tidak menemukan _TOOL_MODULES di server.py"

    # Ekstrak semua string literal dari isi list di server.py
    actual_modules = re.findall(r'"(tools\.[a-zA-Z0-9_]+)"', match.group(1))

    missing_in_test = set(actual_modules) - set(_TOOL_MODULES)
    extra_in_test = set(_TOOL_MODULES) - set(actual_modules)

    assert not missing_in_test, (
        f"server.py punya modul yang belum ada di test ini, update _TOOL_MODULES "
        f"di file test: {missing_in_test}"
    )
    assert not extra_in_test, (
        f"File test ini punya modul yang sudah tidak ada di server.py, "
        f"bersihkan _TOOL_MODULES di file test: {extra_in_test}"
    )
