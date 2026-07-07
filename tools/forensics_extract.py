"""Forensics Helper Module"""
import base64
import re
from mcp_instance import mcp

@mcp.tool()
def forensics_extract(data: str = "", file_type: str = "auto") -> dict:
    """Extract forensic artefacts from data."""
    artefacts = []
    
    # Find base64 patterns
    b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    matches = re.findall(b64_pattern, data)
    
    for match in matches[:5]:  # Limit to 5
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if decoded.isprintable():
                artefacts.append({"type": "base64", "content": decoded[:100]})
        except:
            pass
    
    # Find hex patterns
    hex_pattern = r'0x[a-fA-F0-9]{4,}'
    hex_matches = re.findall(hex_pattern, data)
    artefacts.extend([{"type": "hex", "content": h} for h in hex_matches[:5]])
    
    return {
        "artefacts": artefacts,
        "count": len(artefacts),
        "success": True
    }

@mcp.tool()
def file_signature_check(data: str) -> dict:
    """Check file magic signatures."""
    signatures = {
        "pdf": "25504446",
        "png": "89504e47",
        "jpg": "ffd8ff",
        "zip": "504b0304",
        "elf": "7f454c46",
    }
    
    results = []
    hex_data = data.encode().hex()[:8] if isinstance(data, str) else data[:8].hex()
    
    for ftype, sig in signatures.items():
        if hex_data.startswith(sig.lower()):
            results.append({"type": ftype, "matched": True})
    
    return {"signatures": results, "success": True}