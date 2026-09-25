# 2D DNS Analyzer

Análise contínua (24/7) dos logs DNS do **Technitium** com **IA local e gratuita**
(Ollama + Qwen3 8B, sem nuvem): agrupa as consultas por cliente/computador/domínio,
classifica cada domínio como **TRABALHO / NAO_TRABALHO / SUSPEITO / MALICIOSO /
DESCONHECIDO**, calcula **RISK_SCORE** e **WORK_SCORE** (0–100) e gera **alertas
comportamentais** por cliente.

- **Onde roda:** VM dedicada `10.100.10.4` (Debian 13) — coleta, banco, IA e API.
- **Onde se vê:** console **2D DNS Guard** em `dns-guard.2dtecnologia.com` → **Análise (IA)**
  (código em `web/app/analise.py` deste repo). A VM não tem tela própria.
- **Somente análise:** nada é bloqueado automaticamente. "Candidato a bloqueio" é só
  uma sugestão; bloquear continua sendo decisão humana (Decisões / Bloqueios).

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
 classificador
   Fase A (segundos): catálogo + TI + regras em TODOS os domínios novos
   Fase B (contínua): IA local refina os pendentes, do maior volume para o menor
      ▼
 comportamento (por tenant) ──► alertas
      ▼
 API interna (FastAPI :8088, token) ──► console dns-guard /analise
```

Três serviços systemd: `dnsanalyzer-collector`, `dnsanalyzer-classifier`,
`dnsanalyzer-api` (+ `postgresql` e `ollama`).

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
`OLLAMA_MODEL`, `LLM_ENABLED`, `EXCLUDE_CLIENTS`, `RETENTION_DAYS`, `API_TOKEN`.

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

Reclassificar um domínio: botão *Reanalisar* no admin (ou `POST /domains/{nome}/reanalyze`).
Ajuste manual por cliente: *override* na página do domínio (não afeta outros clientes).

## API interna (token `Authorization: Bearer <API_TOKEN>`)

`GET /health` (sem token) · `GET /stats` · `GET/POST /tenants` · `PATCH /tenants/{id}` ·
`POST/DELETE /tenants/{id}/networks` · `GET /tenants/{id}/summary?days=` ·
`GET /tenants/{id}/domains` · `GET /tenants/{id}/domains/{nome}` ·
`PUT /tenants/{id}/domains/{nome}/override` · `GET /tenants/{id}/clients[/{ip}]` ·
`GET /tenants/{id}/alerts` · `POST /tenants/{id}/alerts/{aid}/status` ·
`POST /domains/{nome}/false-positive` · `POST /domains/{nome}/reanalyze` ·
`GET /domains/{nome}` · `GET/PATCH /sources` · `GET /runs`

## Novas categorias

`INSERT INTO categories (code, label, description, ...)`: o prompt e o JSON Schema
da IA leem a tabela, e o painel mostra o código. Ajuste o catálogo se quiser
classificar domínios conhecidos na nova categoria.

## Testes

```bash
pip install -r requirements-dev.txt
pytest          # unitários (sem banco): nomes/PSL, feeds, tenants, coleta, regras, política da IA
```

## Desempenho (referência: 16 vCPU, Qwen3 8B Q4, CPU)

- Fase A (regras): ~500 domínios em ~2 s.
- IA: ~35 s por domínio (geração ~5 tokens/s — CPU virtualizada é limitada por banda
  de memória). Por isso a resposta é compacta e o catálogo resolve o óbvio.
- Carga inicial de ~500 domínios: algumas horas em segundo plano; depois, só os
  domínios inéditos do dia.
