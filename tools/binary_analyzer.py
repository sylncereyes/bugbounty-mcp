"""StealthVision-MCP - Binary Analyzer Module"""
import base64
import re
from mcp_instance import mcp

@mcp.tool()
def binary_analyzer(file_bytes: str = "", hint: str = "") -> dict:
    """Analyze binary for potential strings/command injection."""
    strings = []
    
    # Extract printable strings (simulated)
    ascii_pattern = r'[ -~]{4,}'
    strings = re.findall(ascii_pattern, file_bytes)[:20]
    
    # Check for common binary indicators
    indicators = {
        "elf": "ELF binary detected" if file_bytes[:4] == "\x7fELF" else None,
        "pe": "PE binary detected" if file_bytes[:2] == "MZ" else None,
        "shellcode": "potential shellcode" if "\x90" * 4 in file_bytes else None,
    }
    
    found = {k: v for k, v in indicators.items() if v}
    
    return {
        "strings": strings[:10],
        "indicators": found,
        "success": True
    }

@mcp.tool()
def reverse_helper(binary_hint: str = "") -> dict:
    """Helper for reverse engineering tasks."""
    tips = [
        "Check strings with: strings -a binary",
        "Use objdump: objdump -d binary",
        "Use ghidra or IDA for disassembly",
        "Look for strcmp/strncmp comparisons"
    ]
    
    return {
        "tips": tips,
        "hint": binary_hint,
        "success": True
    }