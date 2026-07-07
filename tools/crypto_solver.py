"""CTF Crypto Solver Module"""
import base64
import codecs
import re
from mcp_instance import mcp

@mcp.tool()
def crypto_solver(encoded: str, method: str = "auto") -> dict:
    """Attempt to decode common CTF crypto encodings."""
    decodings = []
    
    # Common encoding methods
    if method in ["auto", "base64", "b64"]:
        try:
            decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
            decodings.append({"method": "base64", "result": decoded})
        except:
            pass
    
    if method in ["auto", "hex"]:
        try:
            decoded = bytes.fromhex(encoded).decode('utf-8', errors='ignore')
            decodings.append({"method": "hex", "result": decoded})
        except:
            pass
    
    if method in ["auto", "rot13"]:
        try:
            decoded = codecs.decode(encoded, 'rot_13')
            decodings.append({"method": "rot13", "result": decoded})
        except:
            pass
    
    if method in ["auto", "base32", "b32"]:
        try:
            decoded = base64.b32decode(encoded).decode('utf-8', errors='ignore')
            decodings.append({"method": "base32", "result": decoded})
        except:
            pass
    
    return {
        "input": encoded,
        "decodings": decodings,
        "count": len(decodings),
        "success": len(decodings) > 0
    }

@mcp.tool()
def hash_identifier(hash_value: str) -> dict:
    """Identify hash type for CTF cracking."""
    patterns = {
        "md5": r"^[a-f0-9]{32}$",
        "sha1": r"^[a-f0-9]{40}$",
        "sha256": r"^[a-f0-9]{64}$",
        "sha512": r"^[a-f0-9]{128}$",
        "ntlm": r"^[a-f0-9]{32}$",
    }
    
    hash_types = []
    for htype, pattern in patterns.items():
        if re.match(pattern, hash_value, re.I):
            hash_types.append(htype)
    
    return {
        "hash": hash_value,
        "identified": hash_types,
        "success": len(hash_types) > 0
    }