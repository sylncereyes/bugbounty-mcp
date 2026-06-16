"""
AGY Bug Bounty MCP - Centralized Configuration
All tool modules should import settings from here instead of defining their own.
"""
import os
import logging
from dotenv import load_dotenv

load_dotenv()

# ─── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.WARNING),
    format="[%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("agy")

# ─── HTTP Request Settings ─────────────────────────────────────────────────────
DEFAULT_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", "0.5"))
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "5"))
USER_AGENT = os.getenv(
    "USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AGY/1.0",
)
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() in ("true", "1", "yes")

# ─── API Keys ──────────────────────────────────────────────────────────────────
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
INTERACTSH_SERVER = os.getenv("INTERACTSH_SERVER", "")
INTERACTSH_TOKEN = os.getenv("INTERACTSH_TOKEN", "")

# ─── Paths ─────────────────────────────────────────────────────────────────────
REPORTS_DIR = os.getenv("REPORTS_DIR", "reports")
DB_PATH_ENV = os.getenv("DB_PATH", "database/bugbounty.db")
