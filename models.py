from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

class TrafficType(Enum):
    
    ACTIVE = "active"
    BACKGROUND = "background"
    CDN = "cdn"
    CACHE = "cache"

    @property
    def label_pt(self) -> str:
        labels = {
            "active": "Ativo",
            "background": "Segundo Plano",
            "cdn": "CDN / Rastreador",
            "cache": "Socket / Cache",
        }
        return labels[self.value]


class ThreatLevel(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

    @property
    def label_pt(self) -> str:
        labels = {
            "safe": "Seguro",
            "suspicious": "Suspeito",
            "malicious": "Perigoso",
        }
        return labels[self.value]

    @property
    def color(self) -> str:
        colors = {
            "safe": "#2ecc71",
            "suspicious": "#f39c12",
            "malicious": "#e74c3c",
        }
        return colors[self.value]

    @property
    def emoji(self) -> str:
        emojis = {
            "safe": "🟢",
            "suspicious": "🟡",
            "malicious": "🔴",
        }
        return emojis[self.value]


@dataclass
class DNSEvent:
    """Represents a captured DNS query or response."""
    timestamp: datetime
    domain: str
    query_type: str
    src_ip: str
    dst_ip: str
    protocol: str = "UDP"
    event_type: str = "query"
    traffic_type: TrafficType = TrafficType.ACTIVE
    answers: list[str] = field(default_factory=list)

    @property
    def timestamp_str(self) -> str:
        return self.timestamp.strftime("%H:%M:%S")


@dataclass
class HeuristicMatch:
    rule_name: str
    description: str
    score: int
    details: str = ""


@dataclass
class AnalysisResult:
    event: DNSEvent
    threat_level: ThreatLevel
    total_score: int  # 0-100
    is_blacklisted: bool
    is_whitelisted: bool
    traffic_type: TrafficType = TrafficType.ACTIVE
    heuristic_matches: list[HeuristicMatch] = field(default_factory=list)

    @property
    def reasons(self) -> list[str]:
        result = []
        if self.is_blacklisted:
            result.append("Domínio encontrado em lista de phishing conhecida")
        for match in self.heuristic_matches:
            result.append(match.description)
        return result

    @property
    def recommendation_pt(self) -> str:
        if self.threat_level == ThreatLevel.SAFE:
            return "Acesso normal. Nenhuma ameaça identificada."
        elif self.threat_level == ThreatLevel.SUSPICIOUS:
            return (
                "⚠️ Atenção: Este domínio apresenta características suspeitas. "
                "Verifique se você realmente pretendia acessar este site. "
                "Evite inserir dados pessoais ou senhas."
            )
        else:
            return (
                "🚨 PERIGO: Este domínio foi identificado como potencialmente "
                "malicioso. NÃO insira dados pessoais, senhas ou informações "
                "bancárias. Feche a página imediatamente se estiver aberta."
            )
