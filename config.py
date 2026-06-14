"""
PhishGuard — Centralized Configuration

All application settings are defined here as dataclasses for
type safety and easy modification. No magic strings scattered
across the codebase.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

LOGS_DIR.mkdir(exist_ok=True)


@dataclass
class SnifferConfig:
    """DNS packet capture settings."""
    interface: str | None = None  # None = auto-detect default interface
    dns_port: int = 53
    capture_timeout: int = 1  # seconds per sniff cycle (for clean stop)


@dataclass
class AnalyzerConfig:
    """Threat analysis engine settings."""
    blacklist_file: str = str(DATA_DIR / "blacklist_domains.txt")
    whitelist_file: str = str(DATA_DIR / "whitelist_domains.txt")
    popular_domains_file: str = str(DATA_DIR / "popular_domains.txt")

    # Suspicious TLDs commonly used in phishing
    suspicious_tlds: tuple[str, ...] = (
        ".xyz", ".top", ".club", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".buzz", ".work", ".icu", ".online", ".site", ".info",
        ".click", ".link", ".fit", ".win", ".review", ".stream",
    )

    # Suspicious keywords in domains (common in phishing URLs)
    suspicious_keywords: tuple[str, ...] = (
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "banking", "password", "credential", "suspend",
        "alert", "notification", "urgent", "limited", "blocked",
    )

    # Thresholds for classification
    max_levenshtein_distance: int = 2
    min_score_suspicious: int = 30
    min_score_malicious: int = 70


@dataclass
class GUIConfig:
    """Interface settings."""
    title: str = "PhishGuard — Monitor de Rede Doméstica"
    width: int = 1200
    height: int = 750
    theme: str = "dark"
    update_interval_ms: int = 500  # GUI polling interval


@dataclass
class AppConfig:
    """Root configuration container."""
    sniffer: SnifferConfig = field(default_factory=SnifferConfig)
    analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    gui: GUIConfig = field(default_factory=GUIConfig)
    log_file: str = str(LOGS_DIR / "phishguard_resumo.txt")
    export_dir: str = str(BASE_DIR / "exports")


# Singleton instance
config = AppConfig()
