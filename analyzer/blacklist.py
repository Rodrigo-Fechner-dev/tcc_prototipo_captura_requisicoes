"""
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
    def __init__(self):
        self._blacklist: set[str] = set()
        self._whitelist: set[str] = set()
        self._load_lists()

    def _load_lists(self):
        self._blacklist = self._load_file(config.analyzer.blacklist_file, "blacklist")
        self._whitelist = self._load_file(config.analyzer.whitelist_file, "whitelist")
        logger.info(
            "Loaded %d blacklisted domains, %d whitelisted domains",
            len(self._blacklist), len(self._whitelist),
        )

    @staticmethod
    def _normalize_domain(value: str) -> str:

        domain = value.strip().lower()
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0]
        domain = domain.split(":")[0]
        return domain.strip(".")

    @classmethod
    def _load_file(cls, filepath: str, name: str) -> set[str]:

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
                    domain = cls._normalize_domain(line)
                    if domain:
                        domains.add(domain)
        return domains

    def _resolve_list(self, list_type: str) -> tuple[set[str], str]:

        if list_type == "whitelist":
            return self._whitelist, config.analyzer.whitelist_file
        if list_type == "blacklist":
            return self._blacklist, config.analyzer.blacklist_file
        raise ValueError(f"Unknown list type: {list_type!r}")

    def get_domains(self, list_type: str) -> list[str]:
        """Return all domains of a list, alphabetically sorted."""
        target_set, _ = self._resolve_list(list_type)
        return sorted(target_set)

    def add_domain(self, domain: str, list_type: str) -> bool:

        domain = self._normalize_domain(domain)
        if not domain:
            return False

        target_set, filepath = self._resolve_list(list_type)
        if domain in target_set:
            return False

        target_set.add(domain)
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Append on a fresh line, tolerating files that don't end with "\n".
        prefix = ""
        if path.exists() and path.stat().st_size > 0:
            with open(path, "rb") as f:
                f.seek(-1, 2)
                if f.read(1) != b"\n":
                    prefix = "\n"
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{prefix}{domain}\n")
        logger.info("Added %s to %s", domain, list_type)
        return True

    def remove_domain(self, domain: str, list_type: str) -> bool:
        """
        Remove a domain from a list (memory + file).

        Rewrites the file, dropping every line that matches the domain
        while preserving comments and other entries. Returns True if removed.
        """
        domain = self._normalize_domain(domain)
        target_set, filepath = self._resolve_list(list_type)
        if domain not in target_set:
            return False

        target_set.discard(domain)
        path = Path(filepath)
        if path.exists():
            kept_lines = []
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip().lower()
                    if stripped and not stripped.startswith("#"):
                        if self._normalize_domain(stripped) == domain:
                            continue
                    kept_lines.append(line.rstrip("\n"))
            path.write_text("\n".join(kept_lines) + "\n", encoding="utf-8")
        logger.info("Removed %s from %s", domain, list_type)
        return True

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
