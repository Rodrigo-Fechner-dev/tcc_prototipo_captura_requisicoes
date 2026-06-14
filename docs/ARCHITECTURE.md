# ARCHITECTURE.md — Arquitetura do PhishGuard MVP

## Visão Geral

```
┌─────────────────────────────────────────────────────────┐
│                    REDE DOMÉSTICA (LAN)                  │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐               │
│  │ PC   │  │Celular│  │Smart │  │ IoT  │               │
│  │      │  │      │  │ TV   │  │      │               │
│  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘               │
│     └─────────┴─────────┴─────────┘                     │
│                    │                                     │
│             ┌──────┴──────┐                              │
│             │  Roteador   │                              │
│             │  (Gateway)  │                              │
│             └──────┬──────┘                              │
└────────────────────┼────────────────────────────────────┘
                     │ Tráfego DNS (UDP 53)
                     ▼
┌─────────────────────────────────────────────────────────┐
│              PHISHGUARD MVP (Python)                     │
│                                                         │
│  ┌─────────────────┐                                    │
│  │  Sniffer (Scapy) │ ◄── Thread separada               │
│  │  Filtro: UDP 53  │                                    │
│  └────────┬────────┘                                    │
│           │ DNSEvent (via Queue)                         │
│           ▼                                              │
│  ┌─────────────────────────────────────────────┐        │
│  │         Motor de Análise                     │        │
│  │                                              │        │
│  │  1. Whitelist ──► Seguro (skip)              │        │
│  │  2. Blacklist ──► Perigoso (score=100)       │        │
│  │  3. Heurísticas:                             │        │
│  │     • Typosquatting (Levenshtein)            │        │
│  │     • TLD suspeito                           │        │
│  │     • Keywords suspeitas                     │        │
│  │     • Profundidade de subdomínios            │        │
│  │     • Acesso a IP direto                     │        │
│  │     • Ataque homográfico                     │        │
│  │     • Comprimento do domínio                 │        │
│  │  4. Classificador (Score → Nível)            │        │
│  └────────┬────────────────────────────────────┘        │
│           │ AnalysisResult                               │
│           ▼                                              │
│  ┌─────────────────────────────────────────────┐        │
│  │      Interface GUI (CustomTkinter)           │        │
│  │                                              │        │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐       │        │
│  │  │Total │ │Seguro│ │Susp. │ │Perig.│       │        │
│  │  └──────┘ └──────┘ └──────┘ └──────┘       │        │
│  │  ┌──────────────────┬──────────────────┐    │        │
│  │  │ Tabela de Eventos│ Painel Detalhes  │    │        │
│  │  │ (Treeview)       │ (PT-BR)          │    │        │
│  │  └──────────────────┴──────────────────┘    │        │
│  │  [Iniciar] [Parar] [Limpar] [Exportar]      │        │
│  └─────────────────────────────────────────────┘        │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐                      │
│  │ Logs (.log) │  │ Export JSON  │                      │
│  └─────────────┘  └─────────────┘                      │
└─────────────────────────────────────────────────────────┘
```

## Fluxo de Dados

```
Pacote DNS capturado
    ↓
DNSEvent (timestamp, domain, IPs, query_type)
    ↓
Queue (thread-safe)
    ↓
GUI poll (500ms)
    ↓
ThreatClassifier.classify()
    ├── BlacklistChecker.is_whitelisted() → skip se True
    ├── BlacklistChecker.is_blacklisted() → score=100
    └── HeuristicAnalyzer.analyze() → lista de HeuristicMatch
    ↓
AnalysisResult (threat_level, score, reasons, recommendation)
    ↓
Treeview + EventDetailPanel (em português)
```

## Tecnologias

| Camada | Tecnologia | Versão |
|--------|-----------|--------|
| Linguagem | Python | 3.10+ |
| Captura | Scapy + Npcap | 2.5+ |
| GUI | CustomTkinter | 5.2+ |
| HTTP | requests | 2.31+ |
| Dados | Arquivos .txt (sets) | - |
| Logs | logging (stdlib) | - |
| Export | JSON (stdlib) | - |

## Decisões de Arquitetura (ADRs)

### ADR-001: Foco em DNS

**Contexto:** O TCC menciona captura completa de pacotes como objetivo, com DNS-only como plano alternativo.

**Decisão:** Iniciar com DNS-only.

**Justificativa:** DNS(UDP 53) é o vetor mais eficaz para detectar phishing (todo acesso a site começa com consulta DNS). Captura completa adiciona complexidade sem benefício proporcional para o escopo do MVP.

### ADR-002: CustomTkinter em vez de Tkinter puro

**Contexto:** O TCC recomenda Tkinter para simplicidade.

**Decisão:** Usar CustomTkinter.

**Justificativa:** Mesma API do Tkinter, mas com visual moderno (dark mode, widgets arredondados). Melhora significativamente a aparência sem adicionar complexidade. Instala via pip, sem dependências externas.

### ADR-003: Heurísticas baseadas em score

**Contexto:** Detecção de phishing pode usar ML, regras fixas, ou scoring.

**Decisão:** Sistema de scoring com regras heurísticas.

**Justificativa:** Transparente e explicável — essencial para um trabalho acadêmico. O usuário pode ver exatamente **por que** algo foi classificado como suspeito. ML seria opaco e requer dados de treinamento.
