"""
PhishGuard — Heuristic Analysis Engine

Applies rule-based heuristics to detect phishing patterns in domain names.
Each rule returns a HeuristicMatch with a score contribution (0-100).

Rules implemented:
    1. Typosquatting detection (Levenshtein distance to popular domains)
    2. Suspicious TLD check (.xyz, .tk, .ml, etc.)
    3. Suspicious keyword detection (login, verify, secure, etc.)
    4. Excessive subdomain depth
    5. Direct IP access (no hostname)
    6. Homograph attack patterns (character substitution)
    7. Domain length anomaly
"""

import logging
import re
from pathlib import Path

from config import config
from models import HeuristicMatch

logger = logging.getLogger(__name__)


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost,
            ))
        prev_row = curr_row
    return prev_row[-1]


# Common character substitutions used in homograph attacks
HOMOGRAPH_MAP = {
    "0": "o", "1": "l", "l": "i", "rn": "m",
    "vv": "w", "cl": "d", "nn": "m", "5": "s",
    "3": "e", "4": "a", "@": "a", "$": "s",
}

# Regex for IP-based domains
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


class HeuristicAnalyzer:
    """
    Applies multiple heuristic rules to a domain name and returns
    a list of matches with individual scores.
    """

    def __init__(self):
        self._popular_domains: list[str] = self._load_popular_domains()
        logger.info("Loaded %d popular domains for typosquatting check", len(self._popular_domains))

    @staticmethod
    def _load_popular_domains() -> list[str]:
        """Load popular/legitimate domains for typosquatting comparison."""
        path = Path(config.analyzer.popular_domains_file)
        if not path.exists():
            logger.warning("Popular domains file not found: %s", path)
            return []

        domains = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    domains.append(line)
        return domains

    def analyze(self, domain: str) -> list[HeuristicMatch]:
        """Run all heuristic rules against a domain. Returns list of matches."""
        domain = domain.lower().strip(".")
        matches: list[HeuristicMatch] = []

        # Skip very short or internal domains
        if len(domain) < 4 or domain.endswith(".local") or domain.endswith(".lan"):
            return matches

        # Rule 1: Typosquatting
        match = self._check_typosquatting(domain)
        if match:
            matches.append(match)

        # Rule 2: Suspicious TLD
        match = self._check_suspicious_tld(domain)
        if match:
            matches.append(match)

        # Rule 3: Suspicious keywords
        match = self._check_suspicious_keywords(domain)
        if match:
            matches.append(match)

        # Rule 4: Excessive subdomains
        match = self._check_subdomain_depth(domain)
        if match:
            matches.append(match)

        # Rule 5: Direct IP access
        match = self._check_direct_ip(domain)
        if match:
            matches.append(match)

        # Rule 6: Homograph patterns
        match = self._check_homograph(domain)
        if match:
            matches.append(match)

        # Rule 7: Domain length
        match = self._check_domain_length(domain)
        if match:
            matches.append(match)

        return matches

    def _check_typosquatting(self, domain: str) -> HeuristicMatch | None:
        """
        Check if domain is suspiciously similar to a popular domain.
        Uses Levenshtein distance for fuzzy matching.
        """
        # Extract the registrable domain (e.g., "evil.g00gle.com" → "g00gle.com")
        parts = domain.split(".")
        if len(parts) >= 2:
            registrable = ".".join(parts[-2:])
        else:
            registrable = domain

        threshold = config.analyzer.max_levenshtein_distance
        for popular in self._popular_domains:
            dist = _levenshtein_distance(registrable, popular)
            if 0 < dist <= threshold:
                return HeuristicMatch(
                    rule_name="typosquatting",
                    description=f'Domínio similar a "{popular}" (diferença: {dist} caractere(s))',
                    score=60 if dist == 1 else 40,
                    details=f"Levenshtein distance: {dist}",
                )
        return None

    @staticmethod
    def _check_suspicious_tld(domain: str) -> HeuristicMatch | None:
        """Check if domain uses a TLD commonly associated with phishing."""
        for tld in config.analyzer.suspicious_tlds:
            if domain.endswith(tld):
                return HeuristicMatch(
                    rule_name="suspicious_tld",
                    description=f'Extensão de domínio suspeita: "{tld}"',
                    score=20,
                    details=f"TLD: {tld}",
                )
        return None

    @staticmethod
    def _check_suspicious_keywords(domain: str) -> HeuristicMatch | None:
        """Check for keywords commonly found in phishing URLs."""
        found = [kw for kw in config.analyzer.suspicious_keywords if kw in domain]
        if found:
            return HeuristicMatch(
                rule_name="suspicious_keywords",
                description=f'Palavras suspeitas no domínio: {", ".join(found)}',
                score=15 * min(len(found), 3),  # Cap at 45
                details=f"Keywords: {found}",
            )
        return None

    @staticmethod
    def _check_subdomain_depth(domain: str) -> HeuristicMatch | None:
        """Flag domains with excessive subdomain levels (potential obfuscation)."""
        depth = domain.count(".")
        if depth >= 4:
            return HeuristicMatch(
                rule_name="excessive_subdomains",
                description=f"Domínio com {depth} níveis — possível ofuscação",
                score=25,
                details=f"Subdomain depth: {depth}",
            )
        return None

    @staticmethod
    def _check_direct_ip(domain: str) -> HeuristicMatch | None:
        """Flag direct IP access without hostname (uncommon for legitimate sites)."""
        if IP_PATTERN.match(domain):
            return HeuristicMatch(
                rule_name="direct_ip",
                description="Acesso direto via IP — sites legítimos usam nomes de domínio",
                score=35,
                details=f"IP: {domain}",
            )
        return None

    def _check_homograph(self, domain: str) -> HeuristicMatch | None:
        """
        Detect character substitutions commonly used in homograph attacks.
        Example: g00gle (0→o), paypa1 (1→l), rnicrosoft (rn→m)

        Only triggers when the normalized version (after undoing the
        substitution) is close to a known popular domain. This avoids
        false positives on legitimate domains that simply contain
        characters like 'l', '0', or '1'.
        """
        # Extract registrable part (e.g., "sub.g00gle.com" → "g00gle.com")
        parts = domain.split(".")
        registrable = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        for fake, real in HOMOGRAPH_MAP.items():
            if fake not in registrable:
                continue

            normalized = registrable.replace(fake, real)
            if normalized == registrable:
                continue

            # Only alert if the normalized domain is close to a popular one
            for popular in self._popular_domains:
                dist = _levenshtein_distance(normalized, popular)
                if dist <= 1:
                    return HeuristicMatch(
                        rule_name="homograph",
                        description=(
                            f'Possível ataque homográfico: "{fake}" substituindo "{real}" '
                            f'— domínio similar a "{popular}"'
                        ),
                        score=45,
                        details=f"Pattern: {fake}→{real}, normalized: {normalized}, similar_to: {popular}",
                    )
        return None

    @staticmethod
    def _check_domain_length(domain: str) -> HeuristicMatch | None:
        """Extremely long domains are suspicious."""
        if len(domain) > 50:
            return HeuristicMatch(
                rule_name="long_domain",
                description=f"Domínio incomumente longo ({len(domain)} caracteres)",
                score=15,
                details=f"Length: {len(domain)}",
            )
        return None
