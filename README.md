# 2D DNS Guard

**Protective DNS com análise por IA** da 2D Tecnologia. Faz parte do ecossistema de apps
do [2D Hub](https://portal.2dtecnologia.com) (login único + launcher).

Filtra ameaças e sites improdutivos **por empresa**. Todo domínio que aparece nos logs passa
por um fluxo de 4 fases e as IAs põem **todo** site numa lista (de bloqueio ou de liberação), sem revisão humana
(desde 27/09: a fase 5, *Decisão Humana*, saiu). A TI corrige os erros direto nas listas, e a IA não desfaz a correção.

| Parte | Onde roda | Pasta |
|---|---|---|
| **Console web**: Análise (IA), Empresas, Domínios bloqueados, Domínios liberados, IPs liberados, Logs, Gráficos, Operadores | k3s, ns `dns-guard`, `https://dns-guard.2dtecnologia.com` | [`web/`](web/) |
| **Analisador**: coleta dos logs, regras, Threat Intel, IA local (Ollama/Qwen3), IA online (Gemini), listas, alertas, API | VM `10.100.10.4` (systemd + PostgreSQL) | [`analyzer/`](analyzer/) |
| **Resolvedor/filtro**: Technitium + app Advanced Blocking | VM `10.100.10.15` | (fora do repo) |

```
clientes ──DNS──► Technitium (10.100.10.15) ──logs──► analisador (10.100.10.4) ──API :8088──┐
                   ▲   ▲ baixa /listas/*.txt e /whitelist/*.txt (1 h)  │                    ▼
                   │   └───────────────────────────────────────────────┘                    │
                   └──────── políticas / exceções / logs ◄──────────────────── console web (k3s)
```

O console não tem banco próprio. Empresas (CIDR), políticas, listas, whitelists, operadores e
auditoria ficam no PostgreSQL do analisador, acessados pela API. **Só o console escreve no
Technitium**: a configuração do Advanced Blocking e os `allowed` de exceção imediata.
O analisador apenas publica as listas em texto, e o Technitium as baixa.

## Como funciona

**Fluxo de um domínio novo** (o mesmo vale para os que estão em *Outros*):

| Fase | O que faz |
|---|---|
| 1. IA local | catálogo, Threat Intel e regras, depois a IA local (gemma4:26b) classifica e escolhe a lista; com confiança alta decide sozinha |
| 2. WHOIS + IA local | RDAP/registro.br e o titular (CNPJ) entram no dossiê |
| 3. Busca web + IA local | SearXNG com o nome do domínio, para o que a IA ainda não reconhece |
| 4. IA online | Gemini/Gemma recebe **todo** o contexto das fases 1-3 e decide: a resposta dela é a **última** |

- A resposta da IA online vale com ou sem certeza (lista de bloqueio ou whitelist). Sem resposta válida, vale a
  sugestão da IA local. `MALICIOSO` vai para **Ameaças**.
- Trava (protegido do catálogo, site de trabalho, DoH sem dois modelos, incoerência): a IA não bloqueia e o site vai
  para a whitelist, só na lista (nada muda no DNS). Decisão de pessoa ("manter liberado" ou lista posta à mão) vale sempre.
- **DoH/DNS** exige dois modelos com confiança ≥ 0,95. Isso nasceu de um incidente: CDNs
  foram parar em DoH e bloquearam o seu.ze.delivery.
- **Travas**: infraestrutura protegida do catálogo e decisões humanas ("manter liberado")
  nunca são desfeitas pela IA.
- **Domínios inexistentes** (≥ 95% das consultas com NXDOMAIN em 7 dias) saem do fluxo e
  voltam sozinhos se passarem a resolver.

**Três grandes listas**

- **Blocklists** por categoria, em seções:
  - Segurança: Ameaças⚡, VPN/Proxy⚡, DoH/DNS⚡, Adware⚡.
  - Conteúdo: Adulto⚡, Apostas⚡, Jogos, Redes sociais, Streaming, Mensageiros, Cripto/Trading.
  - Web: Publicidade, Notícias, Pirataria.
  - Trabalho: Compras, IA/Chatbots, Nuvem/Acesso remoto.
  - Sistema: Infraestrutura, Outros.

  ⚡ só marca risco visualmente. Cada empresa escolhe quais categorias bloquear.
- **Whitelists** por categoria: essenciais, produtividade, comunicação, finanças, governo,
  infraestrutura, segurança, desenvolvimento, educação, saúde, utilidades, outros de trabalho.
  A IA inclui sozinha o que tem certeza (catálogo protegido, ou dois modelos concordando com
  ≥ 0,9). Hospedagem compartilhada e o "pai" de algo bloqueado ficam de fora. Todas as
  políticas recebem as whitelists: no Technitium, liberado vence bloqueado.
- **Aprovados**: sites avaliados (pela IA ou por uma pessoa) que não bloqueiam nada e não vão
  ao Technitium. Não são reanalisados, a menos que alguém peça. Os feeds de ameaça continuam
  valendo para eles.

**Políticas por empresa.** Cada política vira um grupo interno do Advanced Blocking
(`Empresa: <nome>[ · unidade]`) com as URLs das categorias bloqueadas, das liberações de
serviço e de todas as whitelists. O console sincroniza por *read-modify-write*: faz backup da
configuração antes (`technitium_config_backups`) e valida depois.

**Serviço liberado só para um IP** (*Domínios liberados* → serviço → *IPs que liberam…*): o IP (ou faixa)
ganha um grupo próprio, `Empresa: <nome> · IP <ip>`, com a política da rede dele (unidade > empresa >
padrão) mais o serviço. Os dados são os mesmos dos IPs liberados (tabela `ip_servicos`; histórico em
`liberado_log`). Revogar apaga o grupo e o IP volta para a rede.

**Rotinas de confiabilidade** ([docs/PLANO-CONFIABILIDADE.md](docs/PLANO-CONFIABILIDADE.md)):
- **Exceção imediata**: liberar um domínio (para todos ou só para uma empresa) grava um
  `allowed` no Technitium na hora, sem esperar a atualização de 1 h das listas.
- **Prévia de impacto**: antes de bloquear ou mudar uma política, mostra quantas empresas e
  computadores acessaram o domínio.
- **Auditoria** (`list_audit`): quem pôs ou tirou cada domínio de cada lista e por quê. É o
  histórico clicável de cada domínio.
- **Pulso das listas**: registra quando o Technitium baixou cada lista e alerta se ela atrasa
  ou é recusada.
- **Validade das ameaças**: o que foi posto em Ameaças automaticamente sai da lista 7 dias
  depois de sumir dos feeds, e o domínio é reanalisado. O que uma pessoa pôs não expira.
- **Alertas** só para bloqueios **novos** e não intencionais.
- **Domínios irmãos**: mesmo certificado (SAN) ou mesmo titular (CNPJ), para pôr a família
  inteira na lista de uma vez.
- **Precisão da IA** (7 dias): quanto do que cada fonte aplicou foi corrigido por uma pessoa.

## Acesso

- **Login único 2D** (usuário do ERP). No 1º acesso o operador fica *aguardando liberação*;
  um super-admin libera em **Operadores**.
- Contingência: `https://dns-guard.2dtecnologia.com/login?local=1` (e-mail + senha local).
- Todo operador ativo usa todas as telas. **Super** só acrescenta a tela Operadores.

## Deploy

**Ordem:** primeiro o analisador na VM (código + `migrate` + restart), **depois** o push no
`main`. O console novo chama endpoints do analisador. Se o push vier antes, o console fica sem
filtro ou mostra "Aguardando IA".

**Analisador (manual):** copiar `analyzer/` para a VM e rodar `sudo bash deploy/install.sh`.
Para só atualizar o código: rsync para `/opt/2d-dnsanalyzer/app`, `dnsanalyzer migrate`
e `systemctl restart dnsanalyzer-api dnsanalyzer-collector dnsanalyzer-classifier`.
Detalhes em [`analyzer/README.md`](analyzer/README.md).

**Console (automático):** push no `main` do GitHub → Woodpecker builda
`registry.2dtecnologia.com/dailison/2d-dns-guard:<sha>` → `kubectl set image` no ns
`dns-guard`. Pushes que só mexem em `analyzer/` não disparam o build.
Os manifests ficam em [`k3s/deploy.yaml`](k3s/deploy.yaml) e são aplicados por admin (o SA
do CI só troca a imagem). Secret `dns-guard-secrets`: `SECRET_KEY`, `TECHNITIUM_TOKEN`,
`ANALYZER_TOKEN`.

## Desenvolvimento local

```bash
cd web && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
ANALYZER_URL=http://10.100.10.4:8088 ANALYZER_TOKEN=... TECHNITIUM_URL=http://10.100.10.15:5380 \
TECHNITIUM_TOKEN=... SESSION_COOKIE_SECURE=false .venv/bin/flask --app wsgi run -p 8080
```

Testes:
- Console: `cd web && pip install -r requirements-dev.txt && pytest`. Cobre a sincronização
  das políticas com um Technitium falso.
- Analisador: `cd analyzer && pip install -r requirements-dev.txt pgserver && pytest`. Os
  testes de banco sobem um PostgreSQL temporário com `pgserver` e são pulados sem ele.

Histórico: extraído do `2D-HotspotPortal` em 2026-09-25 (último commit comum `34b7644`).
