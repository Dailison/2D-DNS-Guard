# Analisador: VM 10.100.10.4 → k3s (04/11/2026)

**Por quê:** pedido do usuário. A infraestrutura local não é confiável para guardar o banco do analisador.

**O que mudou de lugar**

| Peça | Antes (VM `2dia` 10.100.10.4) | Agora |
|---|---|---|
| PostgreSQL 17 (banco `dnsanalyzer`, ~24 GB) | serviço local | k3s `dns-guard/analyzer-db` (StatefulSet, PVC `analyzer-db-data` 100Gi local-path, PV com `Retain`) |
| api (`:8088`) | systemd | `dns-guard/dnsanalyzer-api` (Service interno + hostPort `10.100.50.202:8088` só na VPN) |
| coletor / classificador | systemd | `dns-guard/dnsanalyzer-collector` / `dnsanalyzer-classifier` |
| Ollama (`gemma4:26b`, CPU) | VM | **fica na VM**, agora escutando em `0.0.0.0:11434` |
| SearXNG 8888 / 8889 (+ túnel SOCKS 10.9.10.10) | VM | **ficam na VM**, agora escutando em `0.0.0.0` |

Os manifestos estão em `k3s/analyzer.yaml`, a imagem em `analyzer/Dockerfile` e o CI no Woodpecker (steps `analyzer-*`, por caminho).

## Como o tráfego anda

- O console chama o analisador por dentro do cluster: `ANALYZER_URL=http://dnsanalyzer-api:8088`.
- Os Technitium (10.100.10.15 e o Cloud 10.250.100.1) baixam as listas de `http://10.100.50.202:8088/...`.
  - O console grava as URLs com `ANALYZER_LISTAS_URL`.
  - O hostPort preserva o IP de origem, que o `LISTS_ALLOWED_IPS` confere.
- A API do ERP (`2dtecnologia/api-2dtecnologia`, atendente virtual do 2D-Suporte) usa `IA_ANALISADOR_URL=http://dnsanalyzer-api.dns-guard.svc:8088`. É uma env no deployment; o padrão no código ainda é a VM.
- O analisador chama:
  - o Ollama da VM: `OLLAMA_URL=http://10.100.10.4:11434`;
  - os SearXNG: `http://10.100.10.4:8888`, `http://searxng:8080` (o do próprio k3s) e `http://10.100.10.4:8889`;
  - os reforços, como antes.
- O k3s sai para a rede da 2D pelo `wg0` do VPN-Hostinger (10.100.50.202, AllowedIPs 10.0.0.0/8, via escritório).

## VM 10.100.10.4 depois da troca

- **Firewall:** `analisador-firewall.service` (`/etc/analisador-firewall.nft`, tabela `inet analisador`, prerouting antes do DNAT do podman).
  - Só `10.100.50.202` e o próprio host (lo) chegam nas portas 11434/8888/8889.
- **Ollama:** `/etc/systemd/system/ollama.service.d/override.conf` → `OLLAMA_HOST=0.0.0.0:11434`.
- **SearXNG:**
  - `/etc/containers/systemd/searxng.container` → `PublishPort=8888:8080`;
  - `searxng-2.container` → `GRANIAN_HOST=0.0.0.0`.
  - Backups dos dois em `/root/*.bak-20261104`.
- **Rollback:** `dnsanalyzer-api/collector/classifier` ficam parados e *disabled*, e o PostgreSQL local fica como estava (cópia de 04/11).

## Particularidades

- **Threads do Ollama:** `LLM_NUM_THREAD=22`. O padrão "CPUs − 2" contaria as 8 do k3s, e não as 24 da VM.
- **Ordenação (collation):** a imagem `postgres:17` não tem o locale `pt_BR.UTF-8` do glibc. O banco usa ICU `pt-BR` (`POSTGRES_INITDB_ARGS`).
  - Fuso (`America/Sao_Paulo`), `DateStyle=ISO, DMY` e `default_text_search_config=portuguese` iguais aos da VM.
- **Migrações:** o initContainer `migrate` da api aplica `migrations/` novas a cada imagem; o `install.sh` fazia isso na VM.
  - O CI atualiza a api primeiro e só depois o coletor e o classificador.
- **Partições:** `query_log` é dividida por dia **em UTC** e `query_agg` por mês.
  - As partições já fechadas não mudam. A exceção é mover um computador de empresa pelo console (`registry.py`).
  - Por isso foram copiadas antes, com tudo rodando. Na parada só foi o resto.
- **Firewall do k3s:** o host do k3s não tem firewall (firewalld/nftables inativos). Nada do analisador pode usar NodePort nem hostPort sem `hostIP`.
- **Configuração do analisador:** o Secret `dnsanalyzer-env` é o `analyzer.env` da VM com as diferenças listadas em `k3s/analyzer.yaml`.
  - Para mudar uma configuração: `kubectl -n dns-guard edit secret dnsanalyzer-env`, ou recriar com `--from-env-file`.
  - Depois, `kubectl -n dns-guard rollout restart deploy/dnsanalyzer-{api,collector,classifier}`.

## Pendências

- O reforço `10.9.10.10` (PC de Barretos) não aceita o k3s na 11434. O firewall do Windows dele só libera a VM.
  - Até liberar `10.100.50.202`, o analisador o deixa de lado.
  - A busca do SearXNG 3 continua saindo por ele, pelo túnel da VM.
- O reforço `10.100.50.201` (notebook) só responde quando está ligado, como antes.
