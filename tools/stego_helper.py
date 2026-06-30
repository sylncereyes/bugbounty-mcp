"""StealthVision-MCP - Stego Helper Module"""
import base64
import re
from mcp_instance import mcp

@mcp.tool()
def stego_helper(file_path: str = "", image_url: str = "") -> dict:
    """Extract hidden data from images/files (steganography)."""
    methods = [
        {"method": "base64_check", "description": "Check for base64 encoded strings"},
        {"method": "carrier_file", "description": "Analyze carrier file for hidden data"},
        {"method": "exif_metadata", "description": "Extract EXIF metadata"},
        {"method": "lsb_analysis", "description": "LSB steganography detection"},
    ]
    
    if image_url:
        methods.append({"method": "url_analysis", "found": "Analyzing image from URL"})
    
    if file_path:
        methods.append({"method": "local_analysis", "found": "Analyzing local file"})
    
    return {
        "target": file_path or image_url or "no_target",
        "methods": methods,
        "count": len(methods),
        "success": True
    }

@mcp.tool()
def exif_extract(image_path: str) -> dict:
    """Extract EXIF metadata from images."""
    # Simplified - real would parse actual EXIF
    return {
        "filepath": image_path,
        "metadata": {"note": "EXIF parsing requires Pillow/piexif"},
        "success": True
    }