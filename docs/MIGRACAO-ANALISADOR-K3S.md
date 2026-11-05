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
- **DESFEITO em 05/11 às 14:20 (o que está abaixo é só histórico):** o túnel direto quebrou o k3s → sites que vão
  pela VPS (21 hosts fora do monitoramento). Com o `10.100.50.202/32` no peer do k3s, a VPS passou a descartar esse IP
  vindo pelo peer do escritório (no WireGuard, cada IP de origem pertence a um peer só). O k3s → sites passa pelo
  escritório, e a VPS é a reserva desse caminho, então a mesma identidade nos dois caminhos não funciona.
  - Removidos: o `wg-quick@wg-vps` no k3s (desabilitado; o `.conf` ficou), o peer `site 250` do `wg0.conf` e a regra
    `K3S_PUBLICO` do `vpn.nft`. Backups `*.antes-tirar-k3s`.
  - Para refazer: o k3s precisa de um IP próprio no túnel (ex.: `10.250.100.250`), sem tomar o `10.100.50.202`.
    Também precisa de roteamento por origem para as respostas do hostPort `:8088` voltarem pelo `wg0`.
- **Túnel direto k3s ↔ VPS (05/11, desfeito):** interface `wg-vps` no k3s (`/etc/wireguard/wg-vps.conf`, `wg-quick@wg-vps`) com a
  MESMA identidade `10.100.50.202`, roteando só `10.250.100.1/32`; na VPS é o peer `# site 250` do `wg0.conf`
  (`AllowedIPs = 10.100.50.202/32`, mais específico que o `10.100.0.0/16` do escritório) e o firewall aceita o UDP 13231
  só do `46.202.150.204` (`K3S_PUBLICO`). Console → Technitium Cloud e Cloud → listas (`:8088`) não passam mais pelo
  escritório (65 ms → 5 ms). A rede da 2D, os Technitium local e os sites continuam pelo `wg0`.
  - Sem failover automático: com o `wg-vps` parado (`systemctl stop wg-quick@wg-vps`), o k3s volta a alcançar a VPS pelo
    escritório, mas a VPS continua mandando `10.100.50.202` para o peer direto — para voltar de vez, tirar também o peer
    `site 250` (`wg set wg0 peer <chave> remove`).

## VM 10.100.10.4 depois da troca

- **Firewall:** `analisador-firewall.service` (`/etc/analisador-firewall.nft`, tabela `inet analisador`, prerouting antes do DNAT do podman).
  - Só `10.100.50.202` e o próprio host (lo) chegam nas portas 11434/8888/8889.
- **Ollama:** `/etc/systemd/system/ollama.service.d/override.conf` → `OLLAMA_HOST=0.0.0.0:11434`.
- **SearXNG:**
  - `/etc/containers/systemd/searxng.container` → `PublishPort=8888:8080`;
  - `searxng-2.container` → `GRANIAN_HOST=0.0.0.0`.
  - Backups dos dois em `/root/*.bak-20261104`.
- **Limpeza (04/11, pedido do usuário):** a VM agora roda só a IA e a busca. Já depois de conferir as contagens e do 1º backup no k3s, foram removidos:
  - o PostgreSQL inteiro (pacotes e `/var/lib/postgresql`, 25 GB);
  - `/opt/2d-dnsanalyzer`, `/etc/2d-dnsanalyzer`, `/var/log` e `/var/lib/2d-dnsanalyzer`;
  - as units `dnsanalyzer-*`, o wrapper `/usr/local/bin/dnsanalyzer` e o usuário `dnsanalyzer`.
  - Disco da VM: de 49 para 24 GB usados.
  - Rollback para a VM agora só com `install.sh` + restaurar um dump do backup do k3s.

## Como foi a troca (04/11, ~21:51–22:13)

1. **Com tudo rodando (5,5 min, 1,16 GB):** `pg_dump --data-only` das partições fechadas `query_agg_202609/202610` e `query_log_20261029..20261104`, direto para o host do k3s.
2. **Parada às 21:51:**
   - parar os serviços da VM;
   - `pg_dump` do resto com `--exclude-table-data` dessas partições (466 MB, 2 min);
   - `pg_restore -j 4` (2 min);
   - Ollama em `0.0.0.0`;
   - ligar os pods.
   - O analisador ficou fora do ar das 21:51 às 21:56, e o coletor retomou do cursor sem perder consultas.
3. **Depois:**
   - console: `ANALYZER_URL`, `ANALYZER_LISTAS_URL` e `ANALYZER_VM_IP`;
   - ERP: `IA_ANALISADOR_URL`;
   - troca das 2.615 URLs nos dois Technitium, com backup em `/var/lib/analyzer-migra/antes-*.json` no host do k3s. O script `troca-urls.py` está lá.
4. **Em segundo plano (15 min):** carga das partições copiadas antes e conferência das contagens contra a VM (iguais). Depois, `ANALYZE` e o 1º backup (1,78 GB).

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

- **Feito em 04/11:** o reforço `10.9.10.10` (PC de Barretos) teve a regra "Ollama (analisador DNS)" ampliada para `10.100.10.4,10.100.50.202`. Os outros reforços precisam da mesma regra.
- O reforço `10.100.50.201` (notebook) só responde quando está ligado, como antes.
- **Backup fora do k3s:** o dump diário fica no mesmo host do banco. Proposta: copiar para a VPS 187.41.115.189. Aguarda decisão do usuário, porque precisa liberar SSH do IP 46.202.150.204 na VPS.
- O erro `behavior falhou ... unsupported format string passed to NoneType` no coletor já existia na VM (1.181 vezes no log). Não tem relação com a migração.
