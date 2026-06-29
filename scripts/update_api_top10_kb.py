#!/usr/bin/env python3
"""
update_api_top10_kb.py
Incremental update script for OWASP API Security Top 10 Knowledge Base.
Runs git pull on the source repo, then rebuilds the index.
"""
import os
import sys
import subprocess
from pathlib import Path

REPO_PATH = Path("/tmp/API-Security")


def main():
    if not REPO_PATH.exists():
        print(f"[ERROR] Repository not found at {REPO_PATH}")
        print("[INFO] Run: git clone https://github.com/OWASP/API-Security.git /tmp/API-Security")
        sys.exit(1)

    print("[INFO] Pulling latest changes from OWASP/API-Security...")
    try:
        result = subprocess.run(
            ["git", "pull"],
            cwd=REPO_PATH,
            capture_output=True,
            text=True,
            timeout=120,
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        if result.returncode != 0:
            print(f"[WARN] git pull returned {result.returncode}")
    except subprocess.TimeoutExpired:
        print("[ERROR] git pull timed out")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] git pull failed: {e}")
        sys.exit(1)

    # Run the build script
    build_script = Path(__file__).parent / "build_api_top10_index.py"
    print(f"[INFO] Rebuilding index via {build_script.name}...")
    try:
        result = subprocess.run(
            [sys.executable, str(build_script)],
            capture_output=False,
            text=True,
            timeout=180,
        )
        if result.returncode != 0:
            print(f"[ERROR] Build script failed with code {result.returncode}")
            sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[ERROR] Build script timed out")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Build script failed: {e}")
        sys.exit(1)

    print("[OK] API Top 10 KB update complete")


if __name__ == "__main__":
    from pathlib import Path
    main()