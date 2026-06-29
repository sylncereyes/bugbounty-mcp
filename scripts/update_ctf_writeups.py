#!/usr/bin/env python3
"""
Update CTF writeups index - incremental sync from CTFtime.org.
Runs the build script (which is already incremental) and logs the result.
"""

import subprocess
import sys
from pathlib import Path
from datetime import datetime

SCRIPT_DIR = Path(__file__).parent
BUILD_SCRIPT = SCRIPT_DIR / "build_ctf_writeups_index.py"

def main():
    print(f"[{datetime.now().isoformat()}] Starting CTF writeups update...")
    
    # Run the build script (incremental crawl)
    result = subprocess.run(
        [sys.executable, str(BUILD_SCRIPT)],
        capture_output=True,
        text=True,
        timeout=600
    )
    
    print(result.stdout)
    if result.stderr:
        print(f"STDERR: {result.stderr}", file=sys.stderr)
    
    if result.returncode == 0:
        print(f"[{datetime.now().isoformat()}] Update completed successfully.")
    else:
        print(f"[{datetime.now().isoformat()}] Update failed with exit code {result.returncode}")
        sys.exit(result.returncode)

if __name__ == "__main__":
    main()