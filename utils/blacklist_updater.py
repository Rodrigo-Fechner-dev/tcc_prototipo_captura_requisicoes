"""
PhishGuard — Blacklist Updater

Downloads phishing domain lists from trusted public sources
and merges them into the local blacklist file.

Sources:
    - OpenPhish Community Feed (free, no API key)
    - URLhaus by abuse.ch (free, open data)

Usage:
    python -m utils.blacklist_updater
"""

import logging
import sys
from pathlib import Path
from datetime import datetime

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from config import config

logger = logging.getLogger(__name__)

SOURCES = {
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "description": "OpenPhish Community Feed",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "description": "URLhaus Recent URLs (abuse.ch)",
    },
    "phishtank": {
        "url": "http://data.phishtank.com/data/online-valid.csv",
        "description": "PhishTank Verified Online Phishing",
    },
}


def _extract_domains_from_urls(urls: list[str]) -> set[str]:
    """Extract domain names from full URLs."""
    domains = set()
    for url in urls:
        url = url.strip()
        if not url or url.startswith("#"):
            continue
        # Remove protocol
        domain = url.replace("https://", "").replace("http://", "")
        # Remove path, port, query
        domain = domain.split("/")[0].split(":")[0].split("?")[0]
        domain = domain.lower().strip(".")
        if domain and "." in domain:
            domains.add(domain)
    return domains


def download_source(name: str, source: dict) -> set[str]:
    """Download and parse a single blacklist source."""
    url = source["url"]
    desc = source["description"]
    logger.info("Downloading: %s (%s)", desc, url)

    try:
        response = requests.get(url, timeout=30, headers={
            "User-Agent": "PhishGuard-MVP/1.0 (Academic Research)"
        })
        response.raise_for_status()

        lines = response.text.strip().split("\n")

        if name == "phishtank":
            # PhishTank CSV: skip header, URL is in column 1
            domains = set()
            for line in lines[1:]:  # skip header
                parts = line.split(",")
                if len(parts) >= 2:
                    url_field = parts[1].strip('"')
                    extracted = _extract_domains_from_urls([url_field])
                    domains.update(extracted)
            return domains
        else:
            # Plain text URL list (OpenPhish, URLhaus)
            return _extract_domains_from_urls(lines)

    except requests.RequestException as e:
        logger.warning("Failed to download %s: %s", desc, e)
        return set()


def update_blacklist(sources: list[str] | None = None):
    """
    Download from specified sources and merge into local blacklist.

    Args:
        sources: List of source names to download. None = all sources.
    """
    if sources is None:
        sources = list(SOURCES.keys())

    all_domains: set[str] = set()

    # Download from online sources
    for name in sources:
        if name in SOURCES:
            domains = download_source(name, SOURCES[name])
            logger.info("  → %s: %d domains", name, len(domains))
            all_domains.update(domains)

    if not all_domains:
        logger.warning("No domains downloaded from any source")
        return

    # Load existing blacklist
    blacklist_path = Path(config.analyzer.blacklist_file)
    existing = set()
    if blacklist_path.exists():
        with open(blacklist_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    existing.add(line.lower())

    # Count new additions
    new_domains = all_domains - existing
    merged = existing | all_domains

    # Write merged blacklist
    with open(blacklist_path, "w", encoding="utf-8") as f:
        f.write(f"# PhishGuard — Blacklist de Domínios Maliciosos\n")
        f.write(f"# Atualizado: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"# Total: {len(merged)} domínios\n")
        f.write(f"# Fontes: {', '.join(sources)}\n\n")
        for domain in sorted(merged):
            f.write(domain + "\n")

    logger.info(
        "Blacklist updated: %d existing + %d new = %d total",
        len(existing), len(new_domains), len(merged),
    )
    print(f"\n✅ Blacklist atualizada com sucesso!")
    print(f"   Existentes: {len(existing)}")
    print(f"   Novos:      {len(new_domains)}")
    print(f"   Total:      {len(merged)}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    print("=" * 50)
    print("PhishGuard — Atualizador de Blacklist")
    print("=" * 50)

    # Try OpenPhish and URLhaus (most reliable free sources)
    update_blacklist(["openphish", "urlhaus"])
