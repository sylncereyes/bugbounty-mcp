"""
update_wstg_kb.py
Pulls latest changes from the OWASP WSTG git repository, then rebuilds the
SQLite FTS5 index. Intended to be run manually or via cron.

Usage:
    python scripts/update_wstg_kb.py
"""
import sys
import os
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("update_wstg_kb")

WSTG_DIR = os.path.join(
    os.path.dirname(__file__), "..", "knowledge_base", "owasp_wstg_src"
)
BUILD_SCRIPT = os.path.join(
    os.path.dirname(__file__), "build_wstg_index.py"
)


def main():
    if not os.path.isdir(WSTG_DIR):
        logger.error(
            "WSTG repo not found at %s. "
            "Run the initial clone first: "
            "git clone --depth 1 https://github.com/OWASP/wstg.git %s",
            WSTG_DIR, WSTG_DIR,
        )
        sys.exit(1)

    logger.info("Pulling latest changes from OWASP WSTG repo...")
    result = subprocess.run(
        ["git", "pull", "--ff-only"],
        cwd=WSTG_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        logger.error("Git pull failed:\n%s", result.stderr)
        sys.exit(1)

    output = result.stdout.strip()
    logger.info("Git output: %s", output)

    if output == "Already up to date.":
        logger.info("No new changes — skipping index rebuild")
        print("Already up to date.")
        return

    logger.info("Changes detected, rebuilding index...")
    subprocess.run(
        [sys.executable, BUILD_SCRIPT],
        cwd=os.path.dirname(__file__),
        check=True,
    )
    logger.info("Index rebuild complete")


if __name__ == "__main__":
    main()
