"""
PhishGuard — Heuristic Analysis Engine

Rules implemented:
    0. IDN / Punycode / Unicode homoglyph (Cyrillic/Greek look-alikes)
    1. Typosquatting detection (Levenshtein distance to popular domains)
    2. Suspicious TLD check (.xyz, .tk, .ml, etc.)
    3. Suspicious keyword detection (login, verify, secure, etc.)
    4. Excessive subdomain depth
    5. Direct IP access (no hostname)
    6. Homograph attack patterns (ASCII character substitution)
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


HOMOGRAPH_MAP = {
    "0": "o", "1": "l", "l": "i", "rn": "m",
    "vv": "w", "cl": "d", "nn": "m", "5": "s",
    "3": "e", "4": "a", "@": "a", "$": "s",
}

# Regex for IP-based domains
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Caracteres Unicode confundíveis (cirílico/grego) → equivalente latino.
# Usado para "achatar" homóglifos antes de comparar com domínios populares.
UNICODE_CONFUSABLES = {
    # Cirílico
    "а": "a", "б": "b", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m",
    "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h", "г": "r",
    "д": "d", "л": "n", "п": "n", "и": "u", "ц": "u", "ч": "y", "ь": "b",
    # Grego
    "ο": "o", "α": "a", "ρ": "p", "ι": "i", "ν": "v", "τ": "t", "ε": "e",
    "κ": "k", "μ": "m", "χ": "x", "υ": "u", "ζ": "z", "η": "n", "σ": "o",
    "ω": "w", "γ": "y", "θ": "o", "β": "b",
}

# Sufixos de segundo nível (TLDs compostos) p/ achar o rótulo registrável.
COMPOUND_SUFFIXES = {
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br",
    "co.uk", "org.uk", "gov.uk", "com.au", "co.jp", "com.mx", "com.ar",
}


def _char_script(ch: str) -> str:
    """Classifica o alfabeto de um caractere (para detectar mistura de scripts)."""
    o = ord(ch)
    if 0x0400 <= o <= 0x04FF:
        return "CYRILLIC"
    if 0x0370 <= o <= 0x03FF:
        return "GREEK"
    if (0x41 <= o <= 0x5A) or (0x61 <= o <= 0x7A) or (0x00C0 <= o <= 0x024F):
        return "LATIN"
    return "OTHER"


class HeuristicAnalyzer:
    """
    Applies multiple heuristic rules to a domain name and returns
    a list of matches with individual scores.
    """

    def __init__(self):
        self._popular_domains: list[str] = self._load_popular_domains()
        # Rótulos registráveis dos populares (ex: "itau.com.br" → "itau"),
        # usados na detecção de homóglifo Unicode/Punycode.
        self._popular_labels: set[str] = {
            self._registrable_label(d) for d in self._popular_domains
        }
        logger.info("Loaded %d popular domains for typosquatting check", len(self._popular_domains))

    @staticmethod
    def _registrable_label(domain: str) -> str:
        """Retorna o rótulo registrável (SLD), tratando TLDs compostos (.com.br)."""
        parts = domain.split(".")
        if len(parts) >= 3 and ".".join(parts[-2:]) in COMPOUND_SUFFIXES:
            return parts[-3]
        if len(parts) >= 2:
            return parts[-2]
        return parts[0]

    @staticmethod
    def _registrable_domain(domain: str) -> str:
        """
        Retorna o domínio registrável completo, tratando TLDs compostos.

        Ex.: "secure.portaldoconsumidor.com.br" → "portaldoconsumidor.com.br"
             "evil.g00gle.com"                  → "g00gle.com"

        Evita o falso positivo em que ".com.br" era reduzido a "com.br" e
        casava com "gov.br" por distância de edição.
        """
        parts = domain.split(".")
        if len(parts) >= 3 and ".".join(parts[-2:]) in COMPOUND_SUFFIXES:
            return ".".join(parts[-3:])
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

    @staticmethod
    def _decode_idn(domain: str) -> str:
        """Decodifica rótulos Punycode (xn--) para Unicode; os demais ficam iguais."""
        out = []
        for label in domain.split("."):
            if label.startswith("xn--"):
                try:
                    out.append(label[4:].encode("ascii").decode("punycode"))
                except Exception:
                    out.append(label)
            else:
                out.append(label)
        return ".".join(out)

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

        # Rule 0: IDN / Punycode / homóglifo Unicode (cirílico, grego)
        match = self._check_idn_homograph(domain)
        if match:
            matches.append(match)

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

    def _check_idn_homograph(self, domain: str) -> HeuristicMatch | None:
        """
        Detecta ataques baseados em Punycode (xn--) e homóglifos Unicode
        (caracteres cirílicos/gregos que imitam letras latinas).

        Estratégia:
            1. Decodifica rótulos Punycode para Unicode.
            2. "Achata" caracteres confundíveis para o equivalente latino,
               gerando um esqueleto ASCII.
            3. Se o esqueleto imita uma marca popular → perigoso.
            4. Se mistura alfabetos (latino + cirílico/grego) → perigoso.
            5. Punycode/não-latino sem correspondência → suspeito.
        """
        had_punycode = "xn--" in domain
        decoded = self._decode_idn(domain)
        letters = [c for c in decoded if c.isalpha()]
        non_ascii = [c for c in letters if ord(c) > 127]

        # Sem IDN/Punycode aqui — deixa para as regras ASCII.
        if not had_punycode and not non_ascii:
            return None

        # Achata confundíveis e compara o rótulo registrável aos populares.
        skeleton = "".join(UNICODE_CONFUSABLES.get(c, c) for c in decoded).lower()
        skeleton_label = self._registrable_label(skeleton)

        matched = None
        for popular_label in self._popular_labels:
            if popular_label and _levenshtein_distance(skeleton_label, popular_label) <= 1:
                matched = popular_label
                break

        scripts = {_char_script(c) for c in letters}
        mixed = len(scripts & {"LATIN", "CYRILLIC", "GREEK"}) > 1
        shown = decoded if decoded != domain else domain

        if matched:
            return HeuristicMatch(
                rule_name="idn_homograph",
                description=f'Domínio imita "{matched}" via caracteres Unicode/Punycode (real: "{shown}")',
                score=70,
                details=f"decoded={decoded}, skeleton={skeleton_label}, similar_to={matched}",
            )
        if mixed:
            return HeuristicMatch(
                rule_name="idn_mixed_script",
                description=f'Mistura de alfabetos no domínio ("{shown}") — típico de homóglifo',
                score=70,
                details=f"decoded={decoded}, scripts={sorted(scripts)}",
            )
        if non_ascii and skeleton.isascii():
            return HeuristicMatch(
                rule_name="idn_homoglyph",
                description=f'Caracteres não-latinos imitando letras comuns ("{shown}")',
                score=65,
                details=f"decoded={decoded}, skeleton={skeleton}",
            )
        if had_punycode:
            return HeuristicMatch(
                rule_name="punycode_idn",
                description=f'Domínio internacionalizado (Punycode) com caracteres não-latinos ("{shown}")',
                score=40,
                details=f"decoded={decoded}",
            )
        return None

    def _check_typosquatting(self, domain: str) -> HeuristicMatch | None:
        """
        Check if domain is suspiciously similar to a popular domain.
        Uses Levenshtein distance for fuzzy matching.
        """
        # Extract the registrable domain (e.g., "evil.g00gle.com" → "g00gle.com")
        registrable = self._registrable_domain(domain)

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
                    # Sinal fraco: sozinho já atinge o limiar de "suspeito" (30),
                    # mas precisa de outro sinal para escalar a "perigoso".
                    score=30,
                    details=f"TLD: {tld}",
                )
        return None

    @staticmethod
    def _check_suspicious_keywords(domain: str) -> HeuristicMatch | None:
        
        registrable = HeuristicAnalyzer._registrable_label(domain)
        found = [kw for kw in config.analyzer.suspicious_keywords if kw in registrable]
        if found:
            return HeuristicMatch(
                rule_name="suspicious_keywords",
                description=f'Palavras suspeitas no domínio: {", ".join(found)}',
                # 1 palavra = 30 (suspeito sozinho); cada palavra extra soma 10,
                # até o teto de 50 — combinada com TLD/marca escala a perigoso.
                score=min(30 + 10 * (len(found) - 1), 50),
                details=f"Keywords em '{registrable}': {found}",
            )
        return None

    @staticmethod
    def _check_subdomain_depth(domain: str) -> HeuristicMatch | None:
        depth = domain.count(".")

        if depth >= 5:
            return HeuristicMatch(
                rule_name="excessive_subdomains",
                description=f"Domínio com {depth} níveis — possível ofuscação",
                score=35,  # Sinal médio
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
                score=60,  # Sinal forte: suspeito sozinho, perigoso com +1 sinal
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
        registrable = self._registrable_domain(domain)

        for fake, real in HOMOGRAPH_MAP.items():
            if fake not in registrable:
                continue

            normalized = registrable.replace(fake, real)
            if normalized == registrable:
                continue

            for popular in self._popular_domains:
                dist = _levenshtein_distance(normalized, popular)
                if dist <= 1:
                    return HeuristicMatch(
                        rule_name="homograph",
                        description=(
                            f'Possível ataque homográfico: "{fake}" substituindo "{real}" '
                            f'— domínio similar a "{popular}"'
                        ),
                        score=65,  
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
                score=30,  
                details=f"Length: {len(domain)}",
            )
        return None
