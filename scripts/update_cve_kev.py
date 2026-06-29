#!/usr/bin/env python3
"""
update_cve_kev.py
Weekly update script for CISA KEV catalog.
Re-runs the build index script to refresh the database.
"""

import sys
import os
import subprocess
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def main():
    """Run weekly CVE KEV catalog update."""
    print(f"[{datetime.now().isoformat()}] Starting weekly CISA KEV catalog update...")
    
    build_script = os.path.join(os.path.dirname(__file__), "build_cve_kev_index.py")
    
    try:
        result = subprocess.run(
            [sys.executable, build_script],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=os.path.dirname(os.path.dirname(__file__))
        )
        
        if result.returncode == 0:
            print(f"[{datetime.now().isoformat()}] Update successful:")
            print(result.stdout.strip())
        else:
            print(f"[{datetime.now().isoformat()}] Update FAILED:")
            print(result.stderr.strip())
            return 1
            
    except subprocess.TimeoutExpired:
        print(f"[{datetime.now().isoformat()}] Update TIMED OUT after 120 seconds")
        return 1
    except Exception as e:
        print(f"[{datetime.now().isoformat()}] Update ERROR: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())