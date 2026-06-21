"""
PhishGuard — Centralized Configuration
"""

import sys
import shutil
from pathlib import Path
from dataclasses import dataclass, field

# Modo empacotado (PyInstaller) vs. execução normal por script.
FROZEN = getattr(sys, "frozen", False)

if FROZEN:
    # Recursos embutidos (somente leitura) vivem em sys._MEIPASS.
    # data/ e logs/ ficam na RAIZ do projeto: se o .exe está em "dist/",
    # sobe um nível; assim não são criados espalhados onde o exe roda.
    exe_dir = Path(sys.executable).parent
    APP_DIR = exe_dir.parent if exe_dir.name.lower() == "dist" else exe_dir
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
else:
    APP_DIR = Path(__file__).parent
    BUNDLE_DIR = APP_DIR

BASE_DIR = APP_DIR
DATA_DIR = APP_DIR / "data"
LOGS_DIR = APP_DIR / "logs"


def _provision_data():
    if not FROZEN:
        return
    bundled = BUNDLE_DIR / "data"
    if not bundled.exists():
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for src in bundled.glob("*"):
        dest = DATA_DIR / src.name
        if src.is_file() and not dest.exists():
            try:
                shutil.copy2(src, dest)
            except OSError:
                pass


_provision_data()
LOGS_DIR.mkdir(parents=True, exist_ok=True)


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
