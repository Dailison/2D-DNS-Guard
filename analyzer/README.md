# 2D DNS Analyzer

Análise contínua (24/7) dos logs DNS do **Technitium** com **IA local e gratuita**
(Ollama + Qwen3 8B, sem nuvem): agrupa as consultas por cliente/computador/domínio,
classifica cada domínio como **TRABALHO / NAO_TRABALHO / SUSPEITO / MALICIOSO /
DESCONHECIDO**, calcula **RISK_SCORE** e **WORK_SCORE** (0–100) e gera **alertas
comportamentais** por cliente.

- **Onde roda:** VM dedicada `10.100.10.4` (Debian 13) — coleta, banco, IA e API.
- **Onde se vê:** console **2D DNS Guard** em `dns-guard.2dtecnologia.com` → **Análise (IA)**
  (código em `web/app/analise.py` deste repo). A VM não tem tela própria.
- **Listas, não DNS:** o analisador põe cada domínio na lista da categoria (bloqueio ou
  whitelist) e publica as listas em texto (`/listas/<cat>.txt`, `/whitelist/<cat>.txt`).
  O Technitium baixa as listas de hora em hora. O analisador **nunca escreve no Technitium**;
  as políticas por empresa e as exceções imediatas são gravadas pelo console.

## Arquitetura

```
Technitium (10.100.10.15, API Query Logs, usuário só-leitura)
      │  coleta incremental (janelas fechadas, cursor transacional)
      ▼
 coletor ──► agregação por tenant/computador/FQDN/hora ──► PostgreSQL (partições mensais)
      │
      ├─ feeds de Threat Intel baixados e comparados LOCALMENTE (URLhaus, ThreatFox, HaGeZi…)
      ├─ Tranco top 1M (popularidade) · RDAP (idade do domínio; só o nome sai da rede)
      ▼
 classificador (5 fases, ver abaixo)
   1 IA local · 2 WHOIS + IA local · 3 busca web + IA local · 4 IA online (Gemini) · 5 Decisões
      ▼
 listas por categoria (blocklists, whitelists, aprovados) ──► /listas/*.txt, /whitelist/*.txt
      ▼                                                          (o Technitium baixa a cada 1 h)
 comportamento (por tenant) ──► alertas / webhook / push
      ▼
 API interna (FastAPI :8088, token) ──► console dns-guard
```

Três serviços systemd: `dnsanalyzer-collector`, `dnsanalyzer-classifier`,
`dnsanalyzer-api` (+ `postgresql` e `ollama`). A busca web usa um SearXNG local
(`WEB_SEARCH_URL`). A IA online usa o plano grátis do Gemini (`GEMINI_API_KEY`).

### Por que escala

A IA trabalha por **domínio** (com cache), não por consulta: se os logs crescerem
100×, o custo da IA acompanha só os **domínios inéditos**. As consultas são agregadas
por hora (`query_agg`, particionada por mês — retenção = `DROP` de partição).

## Como a classificação funciona

1. **Catálogo** (`dnsanalyzer/data/catalog.yaml`): domínios conhecidos (Microsoft,
   bancos, gov.br, CDNs, redes sociais, anúncios…). Decisão determinística, sem IA.
   `protected: true` marca infraestrutura crítica que **nenhuma lista consegue
   condenar sozinha** (lição aprendida: listas agressivas derrubavam Microsoft/CDNs).
2. **Regras** (`rules.py`): monta um dossiê com **evidências numeradas** (E0, E1…) —
   TI, popularidade, idade, entropia/DGA, TLD abusado, subdomínios aleatórios (túnel
   DNS), taxa de NXDOMAIN — e calcula o risco.
3. **IA** (`llm.py`): recebe só o dossiê e responde em **JSON Schema**. Primeiro diz
   *o que é o serviço* (`service`), se o **reconhece** (`recognized`), e só então
   classifica — citando o id da evidência de cada razão.
4. **Política** (`policy.py`) — salvaguardas sobre a resposta da IA:
   - razão que cita evidência inexistente é **descartada** (anti-alucinação);
   - `MALICIOSO` exige feed de **alta confiança**; senão vira `SUSPEITO`;
   - o **risco fica ancorado nas regras** (a IA ajusta no máximo ±15);
   - se a IA não reconhece o serviço — ou o domínio está **fora do top 1M do Tranco**
     (um modelo de 8B não tem como conhecê-lo) — vira `DESCONHECIDO` (work 50);
   - `BLOCK_CANDIDATE` só com `MALICIOSO` (ou `SUSPEITO` com risco ≥ 75), nunca em
     infraestrutura protegida.

Não estar numa lista **não** significa que o domínio é seguro — isso aparece
explicitamente nas evidências.

### As 5 fases e as listas

| Fase | Código | O que faz |
|---|---|---|
| 1. IA local | `classifier.py`, `llm.py`, `listas_ia.py` | classifica e sugere a lista (`lista_sugerida`, confiança) |
| 2. WHOIS + IA local | `whois.py` | RDAP/registro.br + titular (CNPJ via BrasilAPI); até 3 tentativas (`whois_tries`) |
| 3. Busca web + IA local | `webintel.py` | SearXNG para o que a IA não reconhece (depois do WHOIS) |
| 4. IA online | `online.py` | Gemini/Gemma com **todo** o contexto das fases 1-3 (`contexto_completo`) |
| 5. Decisões | `listas.FASE5_SQL` | o que sobrou sem certeza; a TI decide no console |

Cascata por confiança (≥ `LISTA_CONFIANCA_MIN`, 0,9): sem confiança alta, o site segue para a fase seguinte
(`incerta_sql`/`proxima_fase`; fase sem dados também avança). **A IA local não decide sozinha**: toda resposta
dela — lista de bloqueio ou whitelist ("wl:<categoria>") — espera a IA online validar (`lista_duvida`). Nas provas de
27/09 ela errou com 100% de confiança tanto no bloqueio (typosquat -> redes_sociais) quanto na liberação (mensageiro ->
wl:comunicacao). A resposta de cada fase é aplicada na hora (`aplicar(ids=...)`). Depois da resposta online,
`listas_ia.aplicar`:
- aplica a resposta online (a última, com ou sem certeza — sem fase 5 desde 27/09). Com `MALICIOSO`, o domínio vai
  para **Ameaças**; "nenhuma lista"/whitelist tira o domínio das listas que a IA tinha posto e o põe na whitelist;
- com trava (`guardado`, incoerência), não bloqueia: whitelist só na lista; decisão de pessoa vale sempre;
- sem resposta válida da IA online (3 rodadas), vale a sugestão da IA local (`lista_fonte` `online:sem_resposta`);
- `listas.sem_destino` (a cada 5 min) garante que nenhum domínio analisado fique sem lista.

Salvaguardas (`guardado`):
- infraestrutura protegida do catálogo nunca é bloqueada;
- NEVER_BLOCK só sai com as duas IAs concordando;
- em Mensageiros, IA/Chatbots e Nuvem/Acesso remoto (uso misto), só o catálogo trava;
- **DoH/DNS exige dois modelos com ≥ 0,95**;
- decisão humana ("manter liberado") nunca volta;
- uma entrada da migração em Infraestrutura só sai com dois modelos dizendo "nenhuma".

**IA online** (`online.py`):
- os modelos ficam em níveis, cada um com a cota do plano grátis (`GEMINI_MODELS`,
  `GEMINI_ESCALATE_MODELS`, formato `modelo:rpm:rpd`);
- uma segunda opinião (Gemma/Flash) é pedida quando o primeiro modelo não tem certeza,
  discorda da IA local ou responde uma candidata a DoH, a whitelist ou à remoção de
  Infraestrutura;
- se falta evidência, a IA online faz a busca web antes de responder.

**Whitelists** (`whitelist.py`), por categoria: essenciais, produtividade, comunicacao,
financas, governo, infraestrutura, seguranca, desenvolvimento, educacao, saude, utilidades,
outros_trabalho.
- **Entra** o que é protegido no catálogo, ou o que dois modelos classificam como TRABALHO
  ou "nenhuma" com ≥ 0,9.
- **Não entram** hospedagem compartilhada, o pai de um domínio bloqueado e nomes de
  CDN/analytics/streaming/jogos.
- **Sai** se aparecer em feed de ameaça, virar SUSPEITO/MALICIOSO ou entrar em conflito
  com uma blocklist.

**Aprovados** (`revisado_at`): domínio avaliado sem lista de bloqueio. Não é reanalisado
(`reanalyze_stale` pula), a menos que alguém peça (`POST /domains-reanalyze`).

**Rotinas do classificador:** a cada ciclo rodam `bloquear_auto` (categorias
`AUTO_BLOCK_CATEGORIES`, que também esperam a IA online), `expirar_ameacas`, `listas_ia.aplicar`
e `whitelist.aplicar`. A cada hora, `marcar_inexistentes`.
- **Ameaças expiram:** o que foi posto automaticamente sai 7 dias depois de sumir dos feeds,
  e o domínio é reanalisado. O que uma pessoa pôs não expira.
- **Inexistentes:** ≥ 95% das consultas com NXDOMAIN em 7 dias (e ≥ 3 consultas) viram
  `kind = 'inexistente'`, fora da IA e de Decisões. Voltam se passarem a resolver. Se o domínio
  está em feed de ameaça, fica no fluxo (DGA também dá NXDOMAIN).

**Auditoria:** um trigger em `category_lists` e `whitelist_domains` grava cada inclusão e
remoção em `list_audit`. O contexto (quem e por quê) vem de
`set_config('dnsguard.por'/'dnsguard.motivo')` (`listas.contexto`). Esse é o histórico de cada
domínio no console e a base da **precisão da IA** (`GET /ai/precisao`): quanto do que cada
fonte aplicou (IA online, IA local, bloqueio automático, whitelist) foi corrigido por uma pessoa.

**Pulso e proteção das listas:**
- cada download do Technitium fica em `list_fetches`. `/health` mostra `listas_atrasadas`
  quando uma lista aplicada não é baixada há mais de 2 h;
- se uma lista com ≥ 50 domínios encolhe mais de 20% de uma vez, a publicação é recusada
  (HTTP 503, alerta `lista_recusada`). O Technitium segue com a versão anterior até alguém
  aceitar em *Domínios bloqueados*.

### Threat Intelligence

Fontes na tabela `ti_sources` (ligar/desligar/peso pelo admin, em *Fontes e IA*;
adicionar = `INSERT` na tabela). Só `confidence = high` leva a `MALICIOSO`.

| Fonte | Confiança | Uso |
|---|---|---|
| URLhaus (abuse.ch) | alta | hosts com malware online |
| ThreatFox (abuse.ch) | alta | IOCs de malware/C2 |
| HaGeZi TIF (via registro AdGuard `filter_44`) | média | feed agregado de ameaças |
| HaGeZi Badware Hoster / DynDNS / Bypass (VPN/DoH) / TLDs abusados | baixa | sinais |
| Phishing.Database | baixa | tem falsos positivos em plataformas grandes |

Entradas de lista que são **sufixos públicos/plataformas** (ex.: `s3.us-east-1.amazonaws.com`,
`github.io`) são descartadas, e o casamento nunca sobe acima do domínio registrável —
um site malicioso em plataforma compartilhada não condena a plataforma. Falsos
positivos marcados no admin viram supressões (`ti_suppressions`).

### Multiempresa

Todo dado de cliente tem `tenant_id`. O tenant de uma consulta é a **rede mais
específica** que contém o IP (`tenant_networks`). IPs da malha WireGuard
`10.100.100.N` (roteador do site que faz NAT) vão para o dono de `10.N.0.0/16`.
Redes desconhecidas viram um tenant automático `Rede 10.X.0.0/16` (nunca caem no
tenant de outra empresa) — renomeie em *Clientes e redes*. `domains` guarda só
inteligência **pública** sobre o nome (reaproveitada entre tenants); a IA não recebe
dados de computadores/IPs.

### Alertas (por tenant)

`malicious_access` (crítico) · `suspicious_access` · `dga_burst` (nomes aleatórios
com NXDOMAIN — assinatura de malware) · `new_domains_spike` (computador com muito
mais domínios inéditos que os colegas) · `volume_spike`. Os dois últimos só rodam
após 7 dias de histórico do tenant.

`blocked_work` (site de trabalho bloqueado) e `block_spike` (um domínio bloqueado para muitos
computadores na mesma hora) só disparam para bloqueios **novos**, sem bloqueio relevante nas
24 h anteriores. Também ficam de fora os bloqueios intencionais: domínios postos por pessoa ou
migração e categorias de uso misto. O webhook só envia os tipos de `WEBHOOK_KINDS`.

## Instalação (Debian 13)

Requisitos da VM: ≥ 8 vCPU com **AVX2** (no Hyper-V, *compatibilidade de processador
desligada*), 12–16 GB de RAM (o Qwen3 8B usa ~6 GB), ~80 GB de disco.

```bash
# 1) Ollama + modelo
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:8b

# 2) copie a pasta analyzer/ para a VM e rode (idempotente):
sudo bash analyzer/deploy/install.sh
#    -> cria usuário, venv, banco, /etc/2d-dnsanalyzer/analyzer.env (senhas geradas),
#       migrações, wrapper /usr/local/bin/dnsanalyzer e units systemd

# 3) preencha TECHNITIUM_TOKEN no analyzer.env (usuário do Technitium só-leitura:
#    permissão Logs: View; token via Administration > Sessions > Create Token)

# 4) tenants e primeira carga
sudo dnsanalyzer import-tenants deploy/tenants.2d.json
sudo dnsanalyzer ti-refresh --force
sudo dnsanalyzer tranco-refresh --force
sudo systemctl start dnsanalyzer-collector dnsanalyzer-classifier
```

Override recomendado do Ollama (`/etc/systemd/system/ollama.service.d/override.conf`):
`OLLAMA_HOST=127.0.0.1:11434`, `OLLAMA_KEEP_ALIVE=60m`, `OLLAMA_NUM_PARALLEL=1`,
`OLLAMA_MAX_LOADED_MODELS=1`, `OLLAMA_CONTEXT_LENGTH=4096`.

No console (k3s, namespace `dns-guard`): `ANALYZER_URL` no ConfigMap `dns-guard-config` e
`ANALYZER_TOKEN` no Secret `dns-guard-secrets` (= `API_TOKEN` do analyzer.env).

## Configuração

Todas as variáveis estão em [`.env.example`](.env.example) (em produção:
`/etc/2d-dnsanalyzer/analyzer.env`, `root:dnsanalyzer`, `640`). **O systemd não aceita
comentário na mesma linha do valor.** Principais: `DATABASE_URL`, `TECHNITIUM_URL/TOKEN`,
`OLLAMA_MODEL`, `LLM_ENABLED`, `EXCLUDE_CLIENTS`, `RETENTION_DAYS`, `API_TOKEN`,
`WEB_SEARCH_URL`, `LISTS_ALLOWED_IPS`, `WEBHOOK_URLS/KINDS`.

IA online (fase 4): `GEMINI_API_KEY` (sem ela a fase 4 fica desligada), `GEMINI_API_KEY_2..4` (chaves de outros
projetos, cada uma com a própria cota por modelo; usadas depois da principal), `ONLINE_ENABLED`,
`ONLINE_WORKERS` (6), `ONLINE_CONFIANCA_MIN` (0,8), `GEMINI_MODELS` (volume),
`GEMINI_ESCALATE_MODELS` (segunda opinião), `GEMINI_SEARCH_MODELS` (grounding, vazio nesta
conta). Os padrões e as cotas estão comentados em `dnsanalyzer/config.py`.

## Operação

```bash
dnsanalyzer status                 # filas (regras / IA) e totais
dnsanalyzer collect                # uma janela de coleta manual
dnsanalyzer ti-refresh [--force] [--source urlhaus]
dnsanalyzer classify --limit 5     # fase A + 5 domínios pela IA
dnsanalyzer behavior               # roda os detectores de alerta agora
journalctl -u dnsanalyzer-classifier -f
tail -f /var/log/2d-dnsanalyzer/*.log
```

Reclassificar um domínio: botão *Reanalisar* no console (ou `POST /domains/{nome}/reanalyze`;
em lote, `POST /domains-reanalyze`, que também tira o domínio de *Aprovados*).
Ajuste manual por cliente: *override* na página do domínio (não afeta outros clientes).

Atualizar o código (sempre **antes** do push do console):

```bash
rsync -a --delete --exclude __pycache__ --exclude .pytest_cache --exclude .env analyzer/ /opt/2d-dnsanalyzer/app/
dnsanalyzer migrate
systemctl restart dnsanalyzer-api dnsanalyzer-collector dnsanalyzer-classifier
```

## API interna (token `Authorization: Bearer <API_TOKEN>`)

A lista completa está em `dnsanalyzer/api.py`. Os principais grupos:

- **Saúde e painel:** `GET /health` (sem token; inclui o pulso das listas) · `GET /stats` ·
  `GET /charts` · `GET /runs` · `GET /ai/events` · `GET /ai/precisao?days=` ·
  `GET /listas-ia/status` · `GET /online/status`.
- **Empresas:** `GET/POST /tenants` · `PATCH/DELETE /tenants/{id}` ·
  `POST/DELETE /tenants/{id}/networks` · `GET /tenants/{id}/summary|domains|clients|alerts`.
- **Domínios:** `GET /domains/{nome}` · `GET /domains/{nome}/historico` (auditoria) ·
  `GET /domains/{nome}/irmaos` (mesmo certificado ou titular) · `POST /domains/{nome}/reanalyze` ·
  `POST /domains-reanalyze` · `POST /domains/impacto`.
- **Blocklists:** `GET /listas/{cat}.txt` (só `LISTS_ALLOWED_IPS`) · `GET /listas` ·
  `GET /listas/{cat}/detalhes` · `GET /sem-lista` · `POST /listas/{cat}` · `POST /listas-lote` ·
  `POST /listas-mover` · `POST /listas-aprovar` · `POST /listas-remover` ·
  `POST /listas/{cat}/aceitar` · `GET /auditoria`.
- **Whitelists e liberações:** `GET /whitelist/{cat}.txt` · `GET /whitelist` ·
  `GET /whitelist/{cat}/detalhes` · `POST /whitelist/{cat}` · `POST /whitelist-remover` ·
  `GET/POST /liberacao` · `GET /servico/{slug}.txt` · `GET /liberacao/{slug}.txt`.
- **Fila da IA online (manual):** `GET /online/pendentes` · `POST /online/decisao`.
- **Políticas e console:** `GET /policies` · `PUT/DELETE /policies/{escopo}` ·
  `GET /policies/impacto` · `GET/POST /console/excecoes` · `POST /console/excecoes/remover` ·
  `GET/POST /console/technitium-backups` · `/console/operators` · `GET /logs/grouped`.

## Novas categorias

`INSERT INTO categories (code, label, description, ...)`: o prompt e o JSON Schema
da IA leem a tabela, e o painel mostra o código. Ajuste o catálogo se quiser
classificar domínios conhecidos na nova categoria.

## Testes

```bash
pip install -r requirements-dev.txt pgserver
pytest          # unitários + testes com PostgreSQL real (pgserver): listas pela IA, fases 3-5,
                # whitelist, inexistentes, auditoria, irmãos, precisão. Sem pgserver, esses são pulados.
```

## Desempenho (referência: 16 vCPU, Qwen3 8B Q4, CPU)

- Fase A (regras): ~500 domínios em ~2 s.
- Triagem por acesso (`LLM_MIN_QUERIES`/`LLM_MIN_CLIENTS`, 27/09): domínio com menos de 3 consultas de 1
  computador fica só com as regras, na fila da IA com a prioridade suspensa (`aguarda_recorrencia`),
  até recorrer. Risco (feed de ameaça, SUSPEITO/MALICIOSO) e análise pedida por pessoa não esperam.
- IA: ~35 s por domínio (geração ~5 tokens/s — CPU virtualizada é limitada por banda
  de memória). Por isso a resposta é compacta e o catálogo resolve o óbvio.
- Carga inicial de ~500 domínios: algumas horas em segundo plano; depois, só os
  domínios inéditos do dia.
- IA online: Flash-Lite ~2-5 s, Gemma 31B ~40-75 s por domínio. `ONLINE_WORKERS` consultas
  simultâneas, limitadas pela cota diária de cada modelo.
