# Guia de Arquitetura e Captura de Pacotes

Este documento detalha o funcionamento interno do módulo de captura do MVP. Ele serve como base teórica e técnica para compor os capítulos de desenvolvimento e metodologia do seu Trabalho de Conclusão de Curso (TCC).

---

## 1. Arquitetura Orientada a Eventos e Threads

A interface de rede de um computador processa milhares de pacotes por segundo. Se o sistema tentasse desenhar a interface gráfica (GUI) no exato momento em que captura cada pacote, o programa travaria severamente (freeze).

Para solucionar isso, o MVP adota uma **Arquitetura Producer-Consumer** usando múltiplas *Threads*:
1. **Thread de Captura (Producer):** Roda em segundo plano infinitamente observando a placa de rede.
2. **Fila de Eventos (Queue):** Uma estrutura thread-safe na memória. Os pacotes traduzidos são armazenados aqui.
3. **Thread Principal/GUI (Consumer):** A cada segundo, a GUI busca eventos novos na Queue e os processa assincronamente (`_poll_events`), mantendo o painel perfeitamente fluído.

---

## 2. O Motor de Interceptação: Scapy e Npcap

A captura é realizada utilizando a biblioteca **Scapy**, uma poderosa ferramenta de manipulação de pacotes em Python. No Windows, o Scapy não consegue interceptar o tráfego sozinho; ele depende dos drivers subjacentes do SO.

Por isso, o sistema exige o **Npcap** (WinPcap moderno) e **Privilégios de Administrador**. O Npcap insere um *hook* no NDIS (Network Driver Interface Specification) do Windows, permitindo ler as cópias brutas dos quadros (frames) de rede assim que entram ou saem da placa TCP/IP, antes do Sistema Operacional processá-los ou ocultá-los.

---

## 3. O Filtro BPF e a Dualidade do DNS (UDP x TCP)

O MVP otimiza o uso de CPU descartando tráfego não-DNS logo na origem. Para isso, usa um **BPF (Berkeley Packet Filter)** com a expressão literal `port 53`.

Por design (RFC 1035), o protocolo DNS adota dois comportamentos de transporte:

* **DNS sobre UDP (User Datagram Protocol):**
  Usado em 95% das queries padrão. O UDP é ágil e contínuo, perfeito para consultas simples de domínios. O Scapy abstrai perfeitamente isso, bastando verificar `packet.haslayer(DNS)`.
* **DNS sobre TCP (Transmission Control Protocol):**
  Usado quando a resposta excederia 512 bytes (ex: DNSSEC ou configurações massivas de rotas) ou em tunelamentos.
  > **Desafio Técnico Resolvido:** No TCP, a RFC do DNS impõe a presença de um **cabeçalho de 2 bytes** antes do payload DNS (para indicar o comprimento total). O Scapy por padrão falha ao fatiar pacotes TCP. O MVP lida com isso inspecionando manualmente a camada bruta (`Raw`) do TCP e extraindo (`dns_layer = DNS(payload[2:])`) a carga DNS, cobrindo assim 100% da porta 53.

---

## 4. Estrutura de Extração de Dados (Ética e Privacidade)

Alinhado ao viés acadêmico e aos princípios da LGPD, o modelo foi construído para **ignorar cargas úteis agressivas (Payloads HTML/dados)** e processar exclusivamente metadados.

Por pacote, o modelo `DNSEvent` extrai:
* `timestamp`: Hora precisa da ocorrência.
* `domain`: O domínio questionado (Ex: `google.com`).
* `query_type`: O tipo do registro (Ex: `A` para IPv4, `AAAA` para IPv6, `MX` para emails).
* `src_ip` e `dst_ip`: Endereços IPs (ajuda a descobrir quem da rede local fez o pedido).
* `protocol`: A camada de transporte detectada.

---

## 5. Limitações Sistêmicas da Captura Passiva

Para sua seção de **Trabalhos Futuros ou Limitações** do TCC, discorra profundamente sobre duas realidades modernas das redes que afetam o PhishGuard:

> **O Paradoxo do Wi-Fi Promíscuo (Por que não pega o celular?)**
> Roteadores Wi-Fi aplicam Isolamento Espacial. Uma placa de rede de Notebook operando no "Managed Mode" só recebe ondas de rádio destinadas ao próprio Mac Address. Para capturar tráfego de outros aparelhos celulares via sniffer, a placa precisaria operar em "Monitor Mode" (incomum no Windows), ou a infraestrutura do roteador precisaria duplicar o tráfego pelo protocolo *Port Mirroring*.

> **DNS over HTTPS (DoH) e DNS over TLS (DoT)**
> Navegadores modernos (Chrome, Firefox) encapsulam o tráfego DNS não na porta 53 em texto claro, mas sim sob criptografia pesada na porta 443 (HTTPS). O Scapy não enxergará isso sob nenhum filtro passivo de "port 53".

---

## 6. Instigações Inovadoras para Melhorar o Sistema (Gatilhos Científicos)

Abaixo estão ideias para amadurecer e expandir a pesquisa e a implementação do seu TCC:

* 💡 **Evoluir de Passivo (Sniffer) para Ativo (Proxy / Sinkhole):** Em vez de ficar "escutando" a porta 53, o MVP poderia atuar como um *Servidor DNS Local* operando nos moldes arquitetônicos do Pi-Hole. O SO manda todas as requisições (DoH out-of-box) para o aplicativo diretor, e ele decide processar ou dropar o tráfego (trazendo o poder de bloqueio real contra phishing).
* 💡 **Inteligência de IP vs Domínio Remoto:** Uma heurística interessante seria testar não apenas o "nome" do domínio, mas checar as origens com bancos de Threat Intelligence como o *AbuseIPDB* em background, atrelando as requisições a servidores C&C perigosos já catalogados globalmente.
* 💡 **Machine Learning na Análise Lexical:** O uso de NLP (Processamento de Linguagem Natural) via *Scikit-Learn* para treinar o script a julgar que "seguranca-itau-renegociacao" possui contexto semântico malicioso (mesmo não sendo um typsoquatting óbvio), evoluindo além de algoritmos estáticos como Levenshtein.

