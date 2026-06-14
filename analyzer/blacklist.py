"""
PhishGuard — Blacklist Checker

Loads domains from local blacklist/whitelist files and checks
incoming DNS queries against them. Uses Python sets for O(1)
lookup performance.

Sources:
    - OpenPhish community feed
    - URLhaus (abuse.ch)
    - PhishTank verified online phishing
    - CERT Polska Warning List
    - Static curated list (data/blacklist_domains.txt)
"""

import logging
from pathlib import Path

from config import config

logger = logging.getLogger(__name__)


class BlacklistChecker:
    """
    Checks domains against local blacklist and whitelist files.

    The blacklist contains known phishing/malicious domains.
    The whitelist contains trusted domains to reduce false positives.
    Both use set-based lookup for O(1) performance.
    """

    def __init__(self):
        self._blacklist: set[str] = set()
        self._whitelist: set[str] = set()
        self._load_lists()

    def _load_lists(self):
        """Load blacklist and whitelist from files."""
        self._blacklist = self._load_file(config.analyzer.blacklist_file, "blacklist")
        self._whitelist = self._load_file(config.analyzer.whitelist_file, "whitelist")
        logger.info(
            "Loaded %d blacklisted domains, %d whitelisted domains",
            len(self._blacklist), len(self._whitelist),
        )

    @staticmethod
    def _load_file(filepath: str, name: str) -> set[str]:
        """Load domains from a text file (one domain per line)."""
        path = Path(filepath)
        if not path.exists():
            logger.warning("%s file not found: %s", name, filepath)
            return set()

        domains = set()
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                # Skip comments and empty lines
                if line and not line.startswith("#"):
                    # Remove protocol prefix if present
                    domain = line.replace("https://", "").replace("http://", "")
                    # Remove path
                    domain = domain.split("/")[0]
                    # Remove port
                    domain = domain.split(":")[0]
                    if domain:
                        domains.add(domain)
        return domains

    def is_blacklisted(self, domain: str) -> bool:
        """Check if domain or any parent domain is in the blacklist."""
        domain = domain.lower().strip(".")
        # Exact match
        if domain in self._blacklist:
            return True
        # Check parent domains (e.g., evil.phishing.com → phishing.com)
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._blacklist:
                return True
        return False

    def is_whitelisted(self, domain: str) -> bool:
        """Check if domain or its parent is in the whitelist."""
        domain = domain.lower().strip(".")
        if domain in self._whitelist:
            return True
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._whitelist:
                return True
        return False

    def reload(self):
        """Reload lists from disk (after update)."""
        self._load_lists()

    @property
    def blacklist_count(self) -> int:
        return len(self._blacklist)

    @property
    def whitelist_count(self) -> int:
        return len(self._whitelist)
