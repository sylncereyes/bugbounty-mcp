"""
update_patt_kb.py
Pull latest changes from the PayloadsAllTheThings git repository, then rebuild the
SQLite FTS5 index for both documentation and raw payloads. Cocok untuk dijadwalkan melalui cron (mingguan).

Usage:
    python scripts/update_patt_kb.py
"""
import sys
import os
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("update_patt_kb")

PATT_DIR = os.path.join(
    os.path.dirname(__file__), "..", "knowledge_base", "patt_src"
)
BUILD_SCRIPT = os.path.join(
    os.path.dirname(__file__), "build_patt_index.py"
)


def main():
    if not os.path.isdir(PATT_DIR):
        logger.error(
            "Repo PATT tidak ditemukan di %s. "
            "Run initial clone: "
            "git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git %s",
            PATT_DIR, PATT_DIR,
        )
        sys.exit(1)

    logger.info("Pulling latest changes from PayloadsAllTheThings repo...")
    result = subprocess.run(
        ["git", "pull", "--ff-only"],
        cwd=PATT_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        logger.error("Git pull gagal:\n%s", result.stderr)
        sys.exit(1)

    output = result.stdout.strip()
    logger.info("Git output: %s", output)

    if output == "Sudah up to date.":
        logger.info("Tidak ada perubahan baru - melewati rebuild index")
        print("Sudah up to date.")
        return

    logger.info("Perubahan terdeteksi, rebuild index...")
    subprocess.run(
        [sys.executable, BUILD_SCRIPT],
        cwd=os.path.dirname(__file__),
        check=True,
    )
    logger.info("Rebuild index lengkap")


if __name__ == "__main__":
    main()
