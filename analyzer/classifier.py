"""
PhishGuard — Threat Classifier

Combines blacklist results and heuristic scores to produce a final
threat classification for each DNS event.

Classification logic:
    1. Whitelisted domain → SAFE (skip analysis)
    2. Blacklisted domain → MALICIOUS (score = 100)
    3. Heuristic score >= 70 → MALICIOUS
    4. Heuristic score >= 30 → SUSPICIOUS
    5. Otherwise → SAFE
"""

import logging
from models import DNSEvent, AnalysisResult, ThreatLevel
from analyzer.blacklist import BlacklistChecker
from analyzer.heuristics import HeuristicAnalyzer
from config import config

logger = logging.getLogger(__name__)


class ThreatClassifier:
    """
    Central classification engine. Orchestrates blacklist checking
    and heuristic analysis to produce a final AnalysisResult.
    """

    def __init__(self):
        self.blacklist = BlacklistChecker()
        self.heuristics = HeuristicAnalyzer()

        # Metrics counters (TP, FP, FN tracking for TCC evaluation)
        self.stats = {
            "total": 0,
            "safe": 0,
            "suspicious": 0,
            "malicious": 0,
        }

    def classify(self, event: DNSEvent) -> AnalysisResult:
        """
        Classify a DNS event through the full analysis pipeline.

        Pipeline:
            1. Check whitelist → if match, return SAFE immediately
            2. Check blacklist → if match, return MALICIOUS
            3. Run heuristic rules → compute total score
            4. Apply score thresholds → determine threat level
        """
        domain = event.domain.lower().strip(".")
        self.stats["total"] += 1

        # Step 1: Whitelist check (skip known-safe domains)
        is_whitelisted = self.blacklist.is_whitelisted(domain)
        if is_whitelisted:
            self.stats["safe"] += 1
            return AnalysisResult(
                event=event,
                threat_level=ThreatLevel.SAFE,
                total_score=0,
                is_blacklisted=False,
                is_whitelisted=True,
                traffic_type=event.traffic_type,
            )

        # Step 2: Blacklist check
        is_blacklisted = self.blacklist.is_blacklisted(domain)

        # Step 3: Heuristic analysis
        heuristic_matches = self.heuristics.analyze(domain)
        heuristic_score = sum(m.score for m in heuristic_matches)

        # Step 4: Determine final score and level
        if is_blacklisted:
            total_score = 100
            threat_level = ThreatLevel.MALICIOUS
        else:
            total_score = min(heuristic_score, 100)
            if total_score >= config.analyzer.min_score_malicious:
                threat_level = ThreatLevel.MALICIOUS
            elif total_score >= config.analyzer.min_score_suspicious:
                threat_level = ThreatLevel.SUSPICIOUS
            else:
                threat_level = ThreatLevel.SAFE

        # Update stats
        self.stats[threat_level.value] += 1

        result = AnalysisResult(
            event=event,
            threat_level=threat_level,
            total_score=total_score,
            is_blacklisted=is_blacklisted,
            is_whitelisted=False,
            traffic_type=event.traffic_type,
            heuristic_matches=heuristic_matches,
        )

        # Log non-safe events for review
        if threat_level != ThreatLevel.SAFE:
            logger.warning(
                "[%s] %s → score=%d, reasons=%s",
                threat_level.value.upper(), domain,
                total_score, result.reasons,
            )

        return result

    def get_stats(self) -> dict:
        """Return current classification statistics."""
        return dict(self.stats)

    def reset_stats(self):
        """Reset all counters."""
        self.stats = {k: 0 for k in self.stats}
