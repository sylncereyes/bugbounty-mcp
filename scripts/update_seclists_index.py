"""
update_seclists_index.py
Detects source type (apt vs git) and updates SecLists index accordingly.
Supports both:
1. apt package installation (preferred: lightweight, easier maintenance)
2. git clone source (fallback when apt not available)
"""
import sys
import os
import subprocess
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("update_seclists_index")

SECLISTS_DIR = os.path.join(
    os.path.dirname(__file__), "..", "knowledge_base", "seclists_src"
)
BUILD_SCRIPT = os.path.join(
    os.path.dirname(__file__), "build_seclists_index.py"
)

# Detect which source type we're using based on current directory structure
def detect_source_type() -> str:
    if not os.path.isdir(SECLISTS_DIR):
        return None

    # If git directory exists, it's git clone
    git_dot = os.path.join(SECLISTS_DIR, ".git")
    if os.path.isdir(git_dot):
        return "git"

    # If there's an apt pkg manifest, it's apt
    apt_pkg = os.path.join(SECLISTS_DIR, "usr", "share", "seclists", "README.md")
    if os.path.isfile(apt_pkg):
        return "apt"

    # Check for WSL or dpkg metadata
    for parent in [os.path.join(SECLISTS_DIR, ".."), SECLISTS_DIR]:
        dpkg_path = os.path.join(parent, "usr", "share", "doc", "seclists")
        if os.path.exists(dpkg_path):
            return "apt"

    logger.warning("Tidak bisa detect source type - assuming 'git'")
    return "git"


def main():
    source_type = detect_source_type()

    if source_type == "git":
        logger.info("Sistem SecLists terdeteksi dari source git")
        return run_git_update()
    elif source_type == "apt":
        logger.info("Sistem SecLists terdeteksi dari package apt")
        return run_apt_update()
    else:
        logger.error("Tidak bisa detect source SecLists. Jangan bisa melanjutkan.")
        logger.error("Silakan install seclists manual via:")
        logger.error("  git clone --depth 1 https://github.com/danielmiessler/SecLists.seclists_src")
        sys.exit(1)


def run_git_update():
    if not os.path.isdir(SECLISTS_DIR):
        logger.error(
            "Repo PATT tidak ditemukan di %s. "
            "Silakan clone manual: "
            "git clone --depth 1 https://github.com/danielmiessler/SecLists %s",
            SECLISTS_DIR, SECLISTS_DIR,
        )
        sys.exit(1)

    logger.info("Pulling latest changes dari GitHub SecLists repo...")
    result = subprocess.run(
        ["git", "pull", "--ff-only"],
        cwd=SECLISTS_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        logger.error("Git pull gagal:\n%s", result.stderr)
        sys.exit(1)

    output = result.stdout.strip()
    logger.info("Git output: %s", output)

    if output == "Already up to date.":
        logger.info("Tidak ada perubahan baru - melewati index rebuild")
        print("Sudah up to date.")
        return

    logger.info("Perubahan terdeteksi, rebuild index...")
    subprocess.run(
        [sys.executable, BUILD_SCRIPT],
        cwd=os.path.dirname(__file__),
        check=True,
    )
    logger.info("Rebuild index complete")


def run_apt_update():
    logger.info("Updating SecLists apt package...")
    result = subprocess.run(
        ["apt", "update"],
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode != 0:
        logger.error("apt update gagal:\n%s", result.stderr)
        sys.exit(1)

    result = subprocess.run(
        ["apt", "install", "--only-upgrade", "-y", "seclists"],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        logger.error("apt install gagal:\n%s", result.stderr)
        sys.exit(1)

    logger.info("apt package update complete")

    logger.info("Rebuild index untuk data baru dari package apt...")
    subprocess.run(
        [sys.executable, BUILD_SCRIPT],
        cwd=os.path.dirname(__file__),
        check=True,
    )
    logger.info("Rebuild index complete")


if __name__ == "__main__":
    main()
