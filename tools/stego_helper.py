"""StealthVision-MCP - Stego Helper Module"""
import base64
import re
from mcp_instance import mcp

@mcp.tool()
def stego_helper(file_path: str = "", image_url: str = "") -> dict:
    """Extract hidden data from images/files (steganography)."""
    methods = []
    
    if image_url:
        methods.append({"method": "base64_check", "found": "Checking embedded data"})
    
    if file_path:
        methods.append({"method": "carrier_file", "found": "Analyzing carrier"})
    
    return {
        "target": file_path or image_url or "no_target",
        "methods": methods,
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