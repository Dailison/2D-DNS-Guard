# 2D DNS Guard

**Protective DNS com análise por IA** da 2D Tecnologia. Faz parte do ecossistema de apps
do [2D Hub](https://portal.2dtecnologia.com) (login único + launcher).

Filtra ameaças e sites improdutivos por empresa (política por grupo no Technitium). A IA
local analisa todo domínio acessado, e a empresa decide o que bloquear. **Nada é bloqueado
automaticamente:** a IA sugere e uma pessoa decide na fila *Decisões*.

| Parte | Onde roda | Pasta |
|---|---|---|
| **Console web**: Análise, Decisões, Bloqueios, Liberados, Logs DNS, Empresas, Operadores | k3s, ns `dns-guard`, `https://dns-guard.2dtecnologia.com` | [`web/`](web/) |
| **Analisador**: coleta dos logs, regras, Threat Intel, IA (Ollama/Qwen3), alertas, API | VM `10.100.10.4` (systemd + PostgreSQL) | [`analyzer/`](analyzer/) |
| **Resolvedor/filtro**: Technitium + app Advanced Blocking | VM `10.100.10.15` | (fora do repo) |

```
clientes ──DNS──► Technitium (10.100.10.15) ──logs──► analisador (10.100.10.4) ──API :8088──┐
                        ▲                                                                   ▼
                        └──────── bloqueios / liberados / logs ◄──────────── console web (k3s)
```

O console não tem banco próprio. Análise, empresas (CIDR), **operadores** e as descrições
dos **liberados** ficam no PostgreSQL do analisador (via API). Bloqueios, liberados e logs
são lidos e gravados direto no Technitium.

## Acesso

- **Login único 2D** (usuário do ERP). No 1º acesso o operador fica *aguardando liberação*;
  um super-admin libera em **Operadores**.
- Contingência: `https://dns-guard.2dtecnologia.com/login?local=1` (e-mail + senha local).
- Todo operador ativo usa todas as telas. **Super** só acrescenta a tela Operadores.

## Deploy

**Console (automático):** push no `main` do GitHub → Woodpecker builda
`registry.2dtecnologia.com/dailison/2d-dns-guard:<sha>` → `kubectl set image` no ns
`dns-guard`. Pushes que só mexem em `analyzer/` não disparam o build.
Manifests em [`k3s/deploy.yaml`](k3s/deploy.yaml), aplicados por admin (o SA do CI só troca a imagem).
Secret `dns-guard-secrets`: `SECRET_KEY`, `TECHNITIUM_TOKEN`, `ANALYZER_TOKEN`.

**Analisador (manual):** copiar `analyzer/` para a VM e rodar `sudo bash deploy/install.sh`.
Para só atualizar o código: rsync para `/opt/2d-dnsanalyzer/app`, `dnsanalyzer migrate`
e `systemctl restart dnsanalyzer-api dnsanalyzer-collector dnsanalyzer-classifier`.
Detalhes em [`analyzer/README.md`](analyzer/README.md).

## Desenvolvimento local

```bash
cd web && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
ANALYZER_URL=http://10.100.10.4:8088 ANALYZER_TOKEN=... TECHNITIUM_URL=http://10.100.10.15:5380 \
TECHNITIUM_TOKEN=... SESSION_COOKIE_SECURE=false .venv/bin/flask --app wsgi run -p 8080
```

Testes do analisador: `cd analyzer && pytest`.

Histórico: extraído do `2D-HotspotPortal` em 2026-09-25 (último commit comum `34b7644`).
