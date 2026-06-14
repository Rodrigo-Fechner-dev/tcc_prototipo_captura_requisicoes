"""
PhishGuard — Blacklist Updater

Downloads phishing domain lists from trusted public sources
and merges them into the local blacklist file.

Sources:
    - OpenPhish Community Feed (free, no API key)
    - URLhaus by abuse.ch (free, open data)
    - PhishTank verified online phishing
    - CERT Polska Warning List

Usage:
    python -m utils.blacklist_updater
"""

import logging
import sys
import csv
import io
from pathlib import Path
from datetime import datetime
from urllib.parse import urlsplit

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
from config import config

logger = logging.getLogger(__name__)

SOURCES = {
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "description": "OpenPhish Community Feed",
        "format": "urls",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "description": "URLhaus Recent URLs (abuse.ch)",
        "format": "urls",
    },
    "phishtank": {
        "url": "http://data.phishtank.com/data/online-valid.csv",
        "description": "PhishTank Verified Online Phishing",
        "format": "phishtank_csv",
    },
    "cert_pl": {
        "url": "https://hole.cert.pl/domains/v2/domains.txt",
        "description": "CERT Polska Warning List",
        "format": "domains",
    },
}

# Hosts where blocking the whole hostname from a URL feed is usually too broad
# for DNS-only detection. Exact phishing subdomains remain allowed.
HIGH_FALSE_POSITIVE_HOSTS = {
    "github.com",
    "www.github.com",
    "raw.githubusercontent.com",
    "docs.google.com",
    "drive.google.com",
    "script.google.com",
    "sites.google.com",
    "forms.gle",
    "form.jotform.com",
    "eu.jotform.com",
    "www.jotform.com",
    "0.gravatar.com",
    "www.dropbox.com",
    "onedrive.live.com",
    "storage.googleapis.com",
    "s3.amazonaws.com",
    "linktr.ee",
    "bit.ly",
    "tinyurl.com",
}


def _extract_domains_from_urls(urls: list[str]) -> set[str]:
    """Extract domain names from full URLs."""
    domains = set()
    for url in urls:
        url = url.strip()
        if not url or url.startswith("#"):
            continue
        parsed = urlsplit(url if "://" in url else f"http://{url}")
        domain = parsed.hostname or ""
        domain = domain.lower().strip(".")
        if _is_usable_domain(domain):
            domains.add(domain)
    return domains


def _is_usable_domain(domain: str) -> bool:
    """Keep domains that are specific enough for DNS-level blocking."""
    return bool(domain and "." in domain and domain not in HIGH_FALSE_POSITIVE_HOSTS)


def _extract_domains_from_lines(lines: list[str]) -> set[str]:
    """Extract already-normalized domain lists."""
    domains = set()
    for line in lines:
        domain = line.strip().lower().strip(".")
        if not domain or domain.startswith("#"):
            continue
        if "/" in domain or "://" in domain:
            domains.update(_extract_domains_from_urls([domain]))
            continue
        if _is_usable_domain(domain):
            domains.add(domain)
    return domains


def _extract_domains_from_phishtank_csv(text: str) -> set[str]:
    """Extract URL column from PhishTank CSV safely."""
    domains = set()
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        url = row.get("url", "")
        domains.update(_extract_domains_from_urls([url]))
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

        source_format = source.get("format", "urls")
        lines = response.text.strip().splitlines()

        if source_format == "phishtank_csv":
            return _extract_domains_from_phishtank_csv(response.text)
        if source_format == "domains":
            return _extract_domains_from_lines(lines)
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
                domain = line.lower()
                if domain and not domain.startswith("#") and _is_usable_domain(domain):
                    existing.add(domain)

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

    update_blacklist(["openphish", "urlhaus", "phishtank", "cert_pl"])
