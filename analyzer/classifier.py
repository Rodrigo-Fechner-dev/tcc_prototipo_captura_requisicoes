"""
PhishGuard — Threat Classifier
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

    def classify(self, event: DNSEvent, update_stats: bool = True) -> AnalysisResult:

        domain = event.domain.lower().strip(".")
        if update_stats:
            self.stats["total"] += 1

        is_whitelisted = self.blacklist.is_whitelisted(domain)
        if is_whitelisted:
            if update_stats:
                self.stats["safe"] += 1
            return AnalysisResult(
                event=event,
                threat_level=ThreatLevel.SAFE,
                total_score=0,
                is_blacklisted=False,
                is_whitelisted=True,
                traffic_type=event.traffic_type,
            )

        is_blacklisted = self.blacklist.is_blacklisted(domain)

        heuristic_matches = self.heuristics.analyze(domain)
        heuristic_score = sum(m.score for m in heuristic_matches)

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

        if update_stats:
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
