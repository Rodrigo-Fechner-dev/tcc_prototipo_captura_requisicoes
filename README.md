# 🛡️ PhishGuard — Monitor de Rede Doméstica

O **PhishGuard** é um protótipo (MVP) de monitoramento de rede doméstica desenvolvido como Trabalho de Conclusão de Curso (TCC) do curso de Análise e Desenvolvimento de Sistemas na **UNISINOS (2026)**.

Ele captura requisições **DNS** em tempo real, classifica cada domínio consultado por meio de **listas de reputação** e **heurísticas explicáveis**, e alerta o usuário sobre possíveis tentativas de phishing em um painel gráfico interativo.

---

## 🚀 Como executar (usuário final)

O jeito mais simples é pelo **executável**, que não exige Python instalado:

1. **Instale o Npcap** (driver de captura): <https://npcap.com/> — marque a opção de compatibilidade com WinPcap.
2. Vá até a pasta [`dist/`](dist/) e dê **duplo-clique em `PhishGuard.exe`**.
3. Confirme a elevação de **Administrador** (necessária para a captura de pacotes).

Na primeira execução, o programa cria automaticamente, ao lado do `.exe`, as pastas `data/` (listas editáveis) e `logs/`.

> Sem o Npcap a captura não funciona, mas a **Validação de URL** (análise offline) continua disponível.

---

## ✨ Funcionalidades

- **Captura de DNS em tempo real** (UDP e TCP, porta 53) com arquitetura assíncrona *producer-consumer* (thread de captura + fila thread-safe), mantendo a interface fluida.
- **Classificação em 3 níveis:** 🟢 Seguro, 🟡 Suspeito, 🔴 Perigoso, separada por abas **Ativo / Background / Socket-Cache**.
- **Cards de estatística clicáveis** que filtram a tabela por classificação.
- **Gerenciador de Whitelist e Blacklist:** visualizar, buscar, adicionar e remover domínios direto pela interface (mudanças persistem).
- **Validação de URL (offline):** cole uma URL ou um JSON de domínios — ou carregue um arquivo — e veja a classificação de cada um, com métricas (acurácia/precisão/recall) quando há rótulo real.
- **Resposta a perigo:** ao detectar um domínio perigoso durante a captura, o PhishGuard para a captura e exibe um alerta com a opção de encerrar os navegadores e recomendar reinício do computador.
- **Exportação** dos eventos em JSON.

---

## 🧠 Como a classificação funciona

Cada domínio passa pelo pipeline em [`analyzer/classifier.py`](analyzer/classifier.py):

1. **Whitelist** → se confiável, é marcado como Seguro.
2. **Blacklist** → se conhecido como malicioso, é Perigoso (score 100).
3. **Heurísticas** ([`analyzer/heuristics.py`](analyzer/heuristics.py)) somam um score; os limiares (Suspeito ≥ 30, Perigoso ≥ 70) definem o nível.

Filosofia de pontuação: **um sinal fraco sozinho fica em "suspeito"; é a combinação de sinais que leva a "perigoso"**.

| Heurística | Peso | Tipo |
|---|---|---|
| IDN / Punycode / homóglifo Unicode (cirílico, grego) | 40–70 | forte |
| Acesso direto por IP | 60 | forte |
| Homográfico ASCII (g00gle, paypa1) | 65 | forte |
| Typosquatting (distância de Levenshtein) | 40–60 | médio |
| Subdomínios excessivos (≥ 5 níveis) | 35 | médio |
| TLD suspeito (.tk, .xyz, .top…) | 30 | fraco |
| Palavra-chave no domínio registrável (login, secure…) | 30–50 | fraco |
| Comprimento anômalo do domínio | 30 | fraco |

---

## 🛠️ Tecnologias

- **Python 3.10+**
- **CustomTkinter** — interface gráfica
- **Scapy + Npcap** — captura de pacotes
- **PyInstaller** — empacotamento do `.exe`

---

## 💻 Executar a partir do código-fonte (desenvolvimento)

```bash
git clone https://github.com/seu-usuario/phishguard-mvp.git
cd phishguard-mvp

python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS

pip install -r requirements.txt
python main.py                  # executar como Administrador no Windows
```

---

## 📦 Gerar o executável

```bash
pip install pyinstaller
python -m PyInstaller PhishGuard.spec --noconfirm
```

O resultado é `dist/PhishGuard.exe` — um único arquivo, com manifesto de Administrador e os dados embutidos.

---

## 🧪 Validação de dataset (linha de comando)

Para medir o desempenho de detecção contra um dataset rotulado:

```bash
python validate_dataset.py caminho/para/dataset.json
```

Espera um JSON com objetos contendo `dominio` e `rotulo_real` (`phishing`/`legitimo`). Gera matriz de confusão, acurácia, precisão, recall e F1, e salva um dataset enriquecido e um relatório em `logs/`.

---

## 📁 Estrutura

```text
├── analyzer/                 # Classificação e heurísticas
│   ├── blacklist.py          # Listas de bloqueio/liberação (com edição)
│   ├── classifier.py         # Orquestra score e nível de risco
│   └── heuristics.py         # Heurísticas (IDN, Levenshtein, TLD, etc.)
├── data/                     # Base local (editável em runtime)
│   ├── blacklist_domains.txt
│   ├── whitelist_domains.txt
│   └── popular_domains.txt
├── gui/                      # Interface (CustomTkinter)
│   ├── app.py                # Janela principal e loop de eventos
│   ├── widgets.py            # Componentes (cards, diálogos, pop-ups)
│   └── escudo-de-seguranca.ico
├── sniffer/
│   └── capture.py            # Thread de captura (Scapy / filtro BPF)
├── utils/
│   └── blacklist_updater.py  # Atualizador das listas de reputação
├── config.py                 # Configurações e limiares
├── main.py                   # Ponto de entrada
├── models.py                 # Estruturas de dados
├── validate_dataset.py       # Validação offline de dataset
├── PhishGuard.spec           # Receita do PyInstaller
└── requirements.txt
```

---

## 🔒 Limitações do escopo (relevante para o TCC)

1. **Wi-Fi em Managed Mode:** o adaptador só recebe o tráfego destinado ao próprio MAC. Para capturar o tráfego de outros aparelhos é preciso *Monitor Mode* ou *Port Mirroring* no roteador.
2. **DNS criptografado (DoH/DoT):** consultas via *DNS over HTTPS/TLS* trafegam cifradas (portas 443/853) e não são inspecionáveis pelo monitor passivo na porta 53.
3. **Detecção heurística:** por ser baseada em regras, está sujeita a falsos positivos/negativos — não substitui uma solução de segurança completa.

---

## 👨‍🎓 Autor

**Rodrigo Dalavia Fechner** — Trabalho de Conclusão de Curso — Análise e Desenvolvimento de Sistemas (UNISINOS, 2026).
