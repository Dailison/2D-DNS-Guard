# Plano: confiabilidade do bloqueio no 2D DNS Guard

Objetivo: reduzir falsos positivos (bloquear o que a empresa usa para trabalhar) e falsos
negativos (deixar aberto o que expõe a empresa), sem depender de vigilância manual.
Origem: avaliação do repositório em 2026-09-26 (commit base `4e5267e`).

Este documento é a especificação para uma sessão de IA implementar. Cada fase é
independente das seguintes, gera um commit próprio e termina com os testes passando.

---

## Regras gerais (valem para todas as fases)

1. **Ler antes de mexer**: [README.md](../README.md), [analyzer/README.md](../analyzer/README.md),
   e os módulos citados em cada tarefa. Preservar o estilo do projeto: comentários e nomes
   em português, funções pequenas, SQL direto com psycopg, sem ORM.
2. **Testes**: `cd analyzer && python3 -m pytest -q` deve passar ao final de cada fase
   (78 testes na base). Testes com banco usam `pgserver` (ver `tests/test_listas_ia.py`).
   Toda regra nova de decisão ganha teste.
3. **Migrações**: arquivos novos em `analyzer/migrations/` numerados a partir de `031_`,
   idempotentes (`IF NOT EXISTS`, `ON CONFLICT DO NOTHING`).
4. **Commits**: um por fase (ou por tarefa grande), mensagem em português no padrão do
   histórico (`git log`), terminando com `Co-Authored-By: Claude <noreply@anthropic.com>`.
   Não fazer push sem o usuário pedir.
5. **Deploy** (só quando o usuário pedir): o analisador vai para a VM `10.100.10.4`
   (rsync para `/opt/2d-dnsanalyzer/app`, `dnsanalyzer migrate`, restart de
   `dnsanalyzer-api dnsanalyzer-collector dnsanalyzer-classifier`) **antes** do push na
   `main`, senão o console fica com filtro ignorado. Pushes só em `analyzer/`, `*.md` e
   `docs/` não disparam o Woodpecker.
6. **Não mexer** em `.woodpecker.yml`, `k3s/deploy.yaml` nem em qualquer ingress.
7. **Nunca gravar no Technitium a partir do analisador**: o analisador só publica listas
   (`/listas/<cat>.txt`); quem grava no Technitium é o console (`web/app/technitium.py`).
8. **Vocabulário**: "lista" = `category_lists.category`; "Decisões"/"fase 5" =
   lista `para_revisar`; "decidido" = `dominio_decidido(id)` (SQL) = há linha em
   `global_reviews` ou `tenant_domains.review_status`.

Mapa rápido do código:

| O quê | Onde |
|---|---|
| Etapa "lista" da IA local + `aplicar` (o que entra/sai das listas) | `analyzer/dnsanalyzer/listas_ia.py` |
| Bloqueio automático rápido por categoria (`bloquear_auto`), conteúdo das listas | `analyzer/dnsanalyzer/listas.py` |
| Fase 4 (Gemini/Gemma), `gravar`, `habilitado()` | `analyzer/dnsanalyzer/online.py` |
| Ciclo do classificador (`run_forever`, `phase_a`) | `analyzer/dnsanalyzer/classifier.py` |
| Regras, evidências, flag `protected` | `analyzer/dnsanalyzer/rules.py`, `catalog.py`, `data/catalog.yaml` |
| Recomendação corporativa, `NEVER_BLOCK` | `analyzer/dnsanalyzer/corporate.py` |
| Detectores de alerta | `analyzer/dnsanalyzer/behavior.py`, envio em `webhook.py` |
| API (FastAPI :8088) | `analyzer/dnsanalyzer/api.py` (listas a partir da linha ~1076) |
| Feed "IA ao vivo" (`ai_events`, apagado com 7 dias) | `analyzer/dnsanalyzer/eventos.py` |
| Console: listas, políticas, ações em lote | `web/app/dns.py` |
| Console: Technitium (config do Advanced Blocking, sincronização das políticas) | `web/app/technitium.py` |
| Console: cliente da API do analisador | `web/app/analyzer_client.py` |

---

## Fase 1 — Travas nos caminhos automáticos (falsos positivos)

Hoje três caminhos põem domínio em lista sem pessoa: `listas_ia.aplicar` (IA local com
certeza quando a IA online está desligada; IA online com confiança ≥ 0,8) e
`listas.bloquear_auto` (categoria de risco pela classificação da IA local, sem passar
pela IA online). Nenhum deles olha se o domínio é infraestrutura protegida ou serviço
de trabalho.

### 1.1 Função `guardado(r)` em `listas_ia.py`

Retorna um motivo (string) quando o domínio **não pode entrar sozinho** em lista, ou
`None`. Critérios:

- `catalog.match(r["name"])` retorna entrada com `protected: true`;
- `r["category"]` está em `corporate.NEVER_BLOCK`;
- `r["popularity_rank"]` ≤ 10.000 **e** `r["classification"] == "TRABALHO"`.

Ajustar o `SELECT` de `aplicar` para trazer `d.popularity_rank`. Quando `guardado`
retorna motivo e o caminho seria "entra direto": em vez disso chamar `para_decisoes`
(fase 5) com `added_by = "IA com dúvida (<cat>) · <motivo>"` e registrar evento
`fase5` com o motivo. Se o domínio já está em alguma lista posta por pessoa, nada muda.

Exceção explícita: `doh_dns` não sofre a trava de popularidade (dns.google é popular e
é exatamente o que a lista existe para bloquear); mantém a trava de `protected`.

### 1.2 `bloquear_auto` com a mesma validação da IA online

Em `listas.py`:

- aplicar `listas_ia.guardado` aos candidatos (quem cai na trava vai para `para_revisar`
  com `added_by = "bloqueio automático (<cat>) · <motivo>"`, sem `global_reviews`);
- quando `online.habilitado()` é verdadeiro, só bloquear automaticamente se
  `domains.lista_fonte LIKE 'online%'`, `domains.lista_ia = category` e
  `domains.lista_conf >= settings().online_confianca_min`. Caso contrário marcar
  `lista_duvida = true` (entra na fila da fase 4) e não bloquear ainda. Sem IA online,
  comportamento atual.
- em `listas_ia.aplicar`, incluir as entradas `added_by LIKE 'bloqueio automático%'` no
  conjunto `da_ia` (móveis), para que a resposta "nenhuma" com certeza da IA online
  também retire o que o bloqueio automático pôs.

Migração `031_valida_bloqueio_auto.sql`: para entradas de `category_lists` com
`added_by LIKE 'bloqueio automático%'` cujo domínio tem `online_at IS NULL`, marcar
`domains.lista_duvida = true` (ficam bloqueadas enquanto a fase 4 revalida).

### 1.3 "Nenhuma" sem certeza vai para Decisões

Em `aplicar`, hoje `if not cat: continue` descarta a resposta "nenhuma" sem certeza.
Nova regra, antes desse `continue`: se a fonte é online, `not certo`, `cat is None`, o
domínio não está em nenhuma lista, e (`classification == 'NAO_TRABALHO'` **ou**
`corp_action == 'BLOQUEAR'`), chamar `para_decisoes(r, None)` com texto
"IA online sem certeza: talvez não seja de lista". Trazer `d.corp_action` no `SELECT`.

### 1.4 Aplicar na hora e sem travar a fila (caso pagbet.com, 2026-09-26)

Caso observado: o Gemini respondeu `apostas` com 100% e o domínio apareceu em Decisões em
vez de na lista. `aplicar` só roda a cada 300 s no laço de `run_forever`, e Decisões mostra
o item assim que `online_at` é gravado; nessa janela o site parece "não bloqueado". Além
disso, `aplicar` roda numa transação única: um erro em uma linha desfaz e repete o lote
inteiro para sempre.

- Em `online.gravar` (e em `api.online_decisao`), depois de salvar a resposta, chamar
  `listas_ia.aplicar` restrito ao domínio (novo parâmetro `domain_id`), na mesma conexão.
- Em `aplicar`, processar cada linha dentro de `SAVEPOINT`/`ROLLBACK TO` (psycopg:
  `with c.transaction():` por linha); linha com erro registra evento `lista_ia` com o erro
  e segue para a próxima.
- Item em `para_revisar` cujo domínio cai em `humano_contra` (alguém já decidiu "manter
  liberado", override TRABALHO ou `locked`): remover de `para_revisar` e registrar evento
  "decidido por pessoa; sugestão da IA ignorada". Hoje fica em Decisões para sempre com a
  sugestão da IA, o que confunde o operador.
- Decisões: quando o domínio tem resposta online com certeza ainda não aplicada
  (`lista_aplicada_at IS DISTINCT FROM lista_at`), mostrar "aguardando aplicação" em vez de
  listar como pendente de decisão.

### 1.5 Testes

Em `tests/test_listas_ia.py` (banco real via pgserver, IA simulada):

- domínio protegido do catálogo com resposta online `streaming` 0,95 → vai para
  `para_revisar`, não para `streaming`;
- domínio `category = 'financas'` com resposta local `compras` 0,95 e IA online desligada
  → `para_revisar`;
- `bloquear_auto` com IA online ligada e `lista_fonte = 'local'` → não bloqueia, marca
  `lista_duvida`; com `lista_fonte = 'online:gemini'` e `lista_conf = 0.9` → bloqueia;
- resposta online `nenhuma` 0,5 em domínio `NAO_TRABALHO` fora de lista → `para_revisar`;
- `dns.google` (rank alto, `doh_dns`) com resposta online 0,9 → entra em `doh_dns`.

Critério de aceite: nenhum domínio `protected` ou de categoria em `NEVER_BLOCK` entra
em lista sem passar por `para_revisar`; `pytest` verde.

---

## Fase 2 — Sincronização segura com o Technitium

`web/app/technitium.py::sincronizar_politicas` lê o config inteiro do app Advanced
Blocking, altera e regrava. É o código de maior raio de estrago do projeto: não há
backup, validação nem teste, e dois operadores salvando ao mesmo tempo se sobrescrevem.

### 2.1 Backup antes de gravar

- Analisador: migração `032_technitium_backups.sql` com tabela
  `technitium_config_backups (id bigserial, taken_at timestamptz default now(),
  taken_by text, motivo text, config jsonb)`. Endpoints em `api.py`:
  `POST /console/technitium-backups` (grava; mantém só os 100 mais recentes) e
  `GET /console/technitium-backups?limit=` (lista `id, taken_at, taken_by, motivo`, sem
  o config) e `GET /console/technitium-backups/{id}` (com config).
- Console: `_set_config(cfg, por, motivo)` passa a gravar o config **anterior** (o que foi
  lido) no analisador antes do `apps/config/set`. Falha ao gravar o backup = aborta a
  gravação com erro claro. Ajustar os chamadores (`liberar`, `revogar`,
  `sincronizar_politicas`) para passar quem e por quê.

### 2.2 Validação do resultado antes de gravar

Em `sincronizar_politicas`, antes de `_set_config`, recusar (levantar `RuntimeError`
com mensagem em português) se:

- o grupo de isenção (`TECHNITIUM_LIBERADOS_GROUP`) existia e sumiu;
- algum grupo que existia e **não** começa com `PREFIXO_GRUPO` sumiu;
- o `networkGroupMap` ficou com menos de 80% das entradas que tinha (exceto quando tinha
  menos de 5);
- alguma rede mapeada para o grupo de isenção mudou de grupo.

### 2.3 Gravação sem sobrescrever a alteração de outro operador

Antes do `apps/config/set`, reler o config (`_get_config`) e comparar o JSON canônico
(`json.dumps(sort_keys=True)`) com o lido no início. Se mudou, refazer a operação
inteira a partir do config novo, até 3 vezes; na 4ª, erro "config alterado por outra
pessoa; tente de novo". Implementar como um laço em `sincronizar_politicas`, `liberar`
e `revogar` (extrair um helper `_read_modify_write(fn, por, motivo)`).

### 2.4 Primeira suíte de testes do console

Criar `web/tests/conftest.py` (app via `create_app` com config de teste:
`TECHNITIUM_URL`, `ANALYZER_URL` fictícios, `TESTING=True`), `web/pytest.ini`,
`web/requirements-dev.txt` (pytest). Testes em `web/tests/test_technitium_sync.py`
com `monkeypatch` em `_get_config`/`_set_config`/`api.post`:

- `plano_politicas`: empresa com política, unidade com exceção, empresa sem política
  (fica no default), rede inválida ignorada;
- `_aplica_politica`: URLs de terceiros preservadas; listas e serviços viram URLs certas;
  serviço liberado vence serviço bloqueado;
- `sincronizar_politicas(aplicar=False)`: cria/atualiza/apaga grupos `Empresa: …`,
  nunca toca no grupo de isenção nem nas redes dele;
- as quatro recusas de 2.2;
- 2.3: `_get_config` devolve config diferente na releitura → refaz e grava a partir da
  nova.

Critério de aceite: `cd web && python3 -m pytest -q` verde; um backup por gravação
visível em `GET /console/technitium-backups`.

---

## Fase 3 — Visibilidade e reversão rápida

### 3.1 Prévia de impacto de uma política

- Analisador, `api.py`: `GET /policies/impacto?tid=<id>&lists=a,b&days=7`. Para cada
  lista: `computadores` (clientes distintos), `consultas` e `top` (20 domínios mais
  consultados) da empresa nos últimos `days` dias que casam com a lista. Casamento por
  domínio registrável: `query_agg` → `domains.name` (= registrável) contra
  `listas.dominios(c, cat)` e os pais (reaproveitar a lógica de `listas._em_lista`).
  `tid=0` = todas as empresas (para o default). Sem `tid`: erro 422.
- Console, `web/app/dns.py` + templates dos modais de política (`listas_categoria.html`
  e o modal da empresa em `analise/empresas.html`, conferir onde está): ao marcar uma
  lista ainda não aplicada, buscar a prévia e mostrar "nos últimos 7 dias: N computadores,
  M consultas; mais acessados: …" antes do botão salvar. Só leitura; não bloqueia salvar.
- Ação "pôr na lista"/"mover" de um domínio: mostrar quantas empresas e computadores
  consultaram o domínio nos últimos 7 dias (`GET /domains/{name}` já traz parte; se
  faltar, acrescentar `empresas` e `computadores_7d`).

### 3.2 Alertas de bloqueio suspeito

Em `behavior.py`, dois detectores novos por tenant, a cada ciclo (janela = última hora,
dados de `query_agg.blocked`):

- `blocked_work` (severidade `high`): domínio com `blocked > 0` cuja classificação é
  `TRABALHO`, ou categoria em `corporate.NEVER_BLOCK`, ou `protected` no catálogo.
  Dedup por `tenant + domínio + dia`. Título: "Site de trabalho bloqueado: <domínio>
  (<n> computadores)".
- `block_spike` (severidade `high`): um domínio bloqueado para ≥ max(5, 30% dos
  computadores ativos da empresa na hora). Dedup por `tenant + domínio + dia`.

Incluir os dois em `WEBHOOK_KINDS` padrão (`config.py` e `.env.example`) e no texto de
`webhook._payload`. Testar com dados sintéticos (há padrão em `tests/test_logs_ia.py`
para popular `query_agg`).

### 3.3 Liberação imediata

Quando uma pessoa decide "manter liberado" (ações `tirar`, `aprovar` com sugestão
"nenhuma", `dominio_listas` com nenhuma lista, `listas_categoria_rem`), além de gravar a
decisão global, o console adiciona o domínio em `allowed` de todos os grupos
`Empresa: …` e do `default` em que `bloqueado_em` diz que ele está bloqueado. Exceção
vale na hora; a lista se acerta no próximo ciclo do Technitium.

- `technitium.py`: `excecao_imediata(dominio, por)` e `remover_excecao(dominio, por)`
  (usa o helper de 2.3 e o backup de 2.1).
- Quando uma pessoa depois põe o domínio em lista (`por`, `mover`, `listas_categoria_add`,
  `dominio_listas` com listas), chamar `remover_excecao`.
- Registrar no analisador (`POST /console/excecoes`, tabela `technitium_allowed_console
  (domain, grupo, added_by, added_at)`, migração `033_`) para saber o que é nosso e não
  mexer em `allowed` posto à mão no Technitium.
- Mensagens do console: trocar "O DNS atualiza em até 1 h" por "Liberado agora nas
  empresas X, Y; a lista atualiza em até 1 h" quando a exceção foi aplicada.

Critério de aceite: teste no console cobrindo `excecao_imediata` (grupos certos, sem
duplicar, não toca em `allowed` manual) e `remover_excecao`.

---

## Fase 4 — Ameaças com validade, auditoria e pulso das listas

### 4.1 Bloqueio por Threat Intel com validade

Domínio em `ameaca` posto por `bloqueio automático (ameaca)` fica bloqueado para sempre,
mesmo quando o feed o remove (`global_reviews` marca como decidido e a fila da IA ignora
decididos).

- Migração `034_ti_cleared.sql`: `ALTER TABLE domains ADD COLUMN ti_cleared_at timestamptz`.
- `classifier.save` (ou `phase_a`): quando `ti_signature` passa de não vazio para vazio,
  gravar `ti_cleared_at = now()`; quando volta a ter acerto, `NULL`.
- Rotina `listas.expirar_ameacas(c, dias=7)` chamada no laço de `run_forever` junto com
  `bloquear_auto`: para entradas `category = 'ameaca'` com `added_by LIKE 'bloqueio
  automático%'` e `domains.ti_cleared_at < now() - dias`, apagar a entrada, apagar
  `global_reviews` se `reviewed_by` for o mesmo `added_by`, marcar `needs_analysis = true`
  e `lista_aplicada_at = NULL`, registrar evento `lista_rem` com motivo "saiu dos feeds
  há N dias". Entradas postas por pessoa não expiram.
- Tela da lista Ameaças: coluna "nos feeds?" (`ti_signature` vazio = "saiu dos feeds em
  <data>").

### 4.2 Auditoria permanente de listas

- Migração `035_list_audit.sql`: `list_audit (id bigserial, at timestamptz default now(),
  domain text, category text, acao text CHECK (acao IN ('add','remove')), por text,
  motivo text)`, índice em `(domain, at desc)`.
- Helper `listas.auditar(c, domain, category, acao, por, motivo)`. Chamar em **todo**
  ponto que insere ou apaga em `category_lists`: `listas_ia.aplicar`, `online.gravar`
  (quando insere `para_revisar`), `listas.bloquear_auto`, `expirar_ameacas`, e os
  endpoints `POST /listas/{cat}`, `DELETE /listas/{cat}/{domain}`, `/listas-lote`,
  `/listas-remover`, `/listas-mover`, `/listas-aprovar`. Usar `grep -n category_lists`
  para não esquecer nenhum.
- `GET /auditoria?domain=&category=&limit=` na API; no console, seção "Histórico nas
  listas" na página do domínio (`analise/dominio.html`) e filtro por lista na tela da lista.

### 4.3 Pulso das listas publicadas

- Migração `036_list_fetches.sql`: `list_fetches (category text primary key, last_at
  timestamptz, last_ip text, last_n int)`.
- `api.lista_txt`: após montar a lista, gravar (`ON CONFLICT DO UPDATE`). **Proteção
  contra esvaziar**: se `last_n >= 50` e a lista nova tem menos de 80% de `last_n`,
  responder 503 com log de erro e evento `lista_rem`-like ("lista <cat> encolheu de A para
  B; publicação recusada"), a menos que `?force=1`. O Technitium mantém a última versão
  baixada quando a URL falha.
- `GET /health`: incluir `listas: {cat: {last_at, last_n}}` e `listas_atrasadas` = listas
  que alguma política aplica (`policies.lists`) e não foram buscadas há mais de 2 h.
  O 2D-Monitoramento já lê `/health`.

---

## Fase 5 — Cobertura (falsos negativos) e medição

### 5.1 Domínios irmãos

- `GET /domains/{name}/irmaos`: domínios já vistos nos logs (`domains`) que compartilham
  certificado (`lookup_cache` → `web.cert.san_domains`; conferir a estrutura salva por
  `webintel.lookup`) ou titular de WHOIS (`whois.lookup`, campo do titular/CNPJ) com o
  domínio, e que **não** estão na mesma lista. Responder `{domain, motivo, listas_atuais,
  total_queries}`.
- Console: na página do domínio e na tela da lista, botão "irmãos" que abre a seleção em
  lote já existente (`listas_lote_dominios`) pré-preenchida.

### 5.2 Taxa de correção da IA

- `GET /ai/precisao?days=7`: a partir de `ai_events` (`lista_add` por fonte "IA local"/
  "IA online" e `decisao` manual que move ou tira), calcular por fonte: sugestões
  aplicadas, corrigidas por pessoa, mantidas. Como `ai_events` só guarda 7 dias, gravar
  o resumo semanal em `list_audit` (fase 4.2) ou numa tabela `ai_precisao_semana`.
- Mostrar em `analise/ia.html` ("nesta semana a IA online foi corrigida em X% dos casos").

### 5.3 README

Atualizar [README.md](../README.md) e [analyzer/README.md](../analyzer/README.md):
políticas por empresa (não mais "política por grupo"), cinco fases (IA local; WHOIS; busca
na web; IA online; Decisões), listas por categoria, e as rotinas novas (validade de
ameaças, auditoria, pulso, prévia de impacto).

---

## Fase 6 — Performance (avaliação de 2026-09-27 na VM em produção)

Medido em produção: o llama-server na VM ocupava 22 GB dos 26 GB e toda a CPU para entregar 15%
das análises locais (34 s por domínio); 4 GB de swap em uso; API com resumo em 0,9 a 2,2 s, logs
agrupados em 2,8 s, gráficos em 1,3 s; poll da IA ao vivo em 0,4 s; fila da fase 1 com 6.429
domínios, 83% deles com até 2 consultas.

PC 10.100.50.201 (reforço): AMD RX 9070 com 16 GB. O gemma4:26b Q4_K_M tem 15,8 GB e não cabe
inteiro com o contexto; parte das camadas fica na CPU e a geração cai para 3,5 a 7,6 tokens/s
por slot (4 slots). O `size_vram` de 1,9 GB no `ollama ps` é erro de relatório. Decisão do
Dailison em 27/09: fica como está; a alternativa é um quant menor (~10 a 11 GB) do mesmo modelo.

Feito em 27/09: `LLM_VM_RESERVA=true` na VM (Ollama local só se o PC cair; modelo descarregado);
PostgreSQL com `shared_buffers` 2 GB, `effective_cache_size` 6 GB, `work_mem` 32 MB,
`pg_stat_statements` e `log_min_duration_statement = 500ms` (a VM tem memória dinâmica no
Hyper-V: `free` mostra 4 GB quando ociosa e cresce sob demanda); triagem por acesso
(migração 060, `LLM_MIN_QUERIES`/`LLM_MIN_CLIENTS`).

### 6.1 Consultas da API (medir antes, com `pg_stat_statements`)

- `SELECT query, calls, mean_exec_time FROM pg_stat_statements ORDER BY total_exec_time DESC
  LIMIT 20` depois de 24 h de uso: atacar as 5 primeiras.
- Índice `(tenant_id, bucket)` nas partições de `query_agg` (criar em `collector.ensure_partitions`
  para as partições novas e numa migração para as existentes). Hoje só há `pkey`, `bucket` e
  `(domain_id, bucket)`; resumo, gráficos, logs agrupados e prévia de impacto filtram por empresa
  e período.
- `/ai/events` (poll da IA ao vivo): as quatro contagens de fila chamam `dominio_decidido()` por
  linha em `domains`. Guardar as contagens em memória por 15 s (módulo `api`, `time.monotonic`)
  e reescrever com `NOT EXISTS` em `global_reviews`/`tenant_domains` em vez da função.
- `/tenants/{tid}/summary`: três agregações separadas sobre `query_agg` (não trabalho, risco,
  todos) e a CTE de computadores. Unir numa agregação por domínio com `FILTER` e cachear o
  resultado por empresa por 60 s. Mesmo cache para `/charts`.
- Rollup diário `query_day (tenant_id, domain_id, dia, queries, blocked, clients)` alimentado
  pelo coletor a cada janela (upsert do dia corrente). Resumo, gráficos, logs agrupados por
  domínio e prévia de impacto passam a ler dele quando o período é de dias inteiros;
  `query_agg` fica para a última hora e para o detalhe por FQDN.

### 6.2 Console

- `technitium.indice_bloqueio` e `dominios_das_listas`: cache de módulo com 60 s (hoje é por
  requisição, refeito em toda página), invalidado por qualquer ação que grave lista.
- `listas.detalhes`, `sem_lista` e `detalhes_whitelist` carregam todos os itens e filtram e
  facetam em Python. Está em 0,3 s com 13 mil domínios; mover filtros e facetas para SQL
  quando passar de 50 mil, ou paginar no banco.

### 6.3 IA local

- Custo do prompt na CPU: 620 a 710 tokens por domínio. Se a VM voltar a inferir, encurtar as
  evidências e revisar `SYSTEM_PROMPT` em `llm.py`.
- No PC, `OLLAMA_NUM_PARALLEL` igual a `LLM_EXTRA_WORKERS` (4). Se um dia trocar o quant,
  conferir no log do servidor que todas as camadas ficaram na GPU.
- Chave `GEMINI_API_KEY_3` responde 401 ("service account deleted or disabled") desde 27/09:
  trocar ou remover da `analyzer.env`; cada tentativa pausa aquele modelo por 10 min.

### 6.4 Operação

- `journalctl` do classificador mostrou `httpx.RemoteProtocolError` do Ollama quando a VM
  estava em swap; reavaliar depois de uma semana com a VM em reserva.
- Alertar no 2D-Monitoramento quando `/health` trouxer `listas_recusadas` não vazio (a lista
  `infra_bloqueio` ficou recusada da noite de 26/09 até ser aceita).

---

## Fora deste plano (decisão do Dailison antes de implementar)

- **Quarentena de 24 h** para entradas automáticas (`category_lists.effective_at`).
- **Listas públicas base** (HaGeZi TIF, Gambling, NSFW, DoH/VPN bypass) assinadas direto
  nos grupos do Technitium, começando por uma empresa piloto.
- **Página de bloqueio com pedido de liberação** (`blockingAddresses` por grupo apontando
  para um IP interno; em HTTPS o navegador mostra erro de certificado).
- **Firewall** 53/853 de saída só para o Technitium e canário `use-application-dns.net`.

---

## Checklist de entrega por fase

- [ ] `cd analyzer && python3 -m pytest -q` verde (e `cd web && python3 -m pytest -q` a
      partir da fase 2)
- [ ] migrações novas rodam duas vezes sem erro (idempotentes)
- [ ] `grep -n category_lists` confere que todo insert/delete passa pela auditoria
      (fase 4 em diante)
- [ ] commit com mensagem em português descrevendo o comportamento novo
- [ ] nada de push/deploy sem o usuário pedir; ordem de deploy: analisador na VM → push
