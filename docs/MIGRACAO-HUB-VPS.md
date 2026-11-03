# Migração de um cliente para o hub WireGuard na VPS

Roteiro feito na migração da **AgenciaCanaa** (site 39) em 03/11/2026, para repetir nos próximos clientes.
Nos comandos, troque **N** pelo número do site (rede `10.N.0.0/16`), **NOME** pelo nome do cliente e
**ASN** pelo provedor dele.

## Visão geral

| Peça | Onde | Detalhes |
|---|---|---|
| Hub WireGuard | VPS Hostinger `187.41.115.189` (AlmaLinux 10) | `wg0` = `10.250.100.1/24`, UDP 13231 |
| Túnel | `10.250.100.0/24` | VPS `.1`, site N `.N`, escritório `.100` |
| Escritório (2DRTR001) | `10.100.30.1` | interface `wg-vps-2d` (`10.250.100.100`), peer `VPS-2D` |
| Technitium Cloud | VPS, `10.250.100.1` | clone do `10.100.10.15`; o console espelha o Advanced Blocking (`TECHNITIUM_REPLICAS`) |
| Technitium local | `10.100.10.15` | principal do console; secundário dos sites |
| Túnel antigo | 2DRTR001 `wireguard_2D` (`10.100.100.0/24`) | fica de reserva (`distance=2`) até ser removido |

Chave pública do hub: `iKud2SFrya0Ddqv8EJtq1Zf/Ig5CXADTWCSv1IX+CXk=`.

Na VPS:
- `wg-site add N CHAVE "NOME"`: cadastra o peer do site (`10.250.100.N/32` + `10.N.0.0/16`).
- `wg-asn add ASN "nome"`: libera a porta 13231 para os prefixos do provedor (atualização semanal).
- Firewall: `/etc/nftables/vpn.nft`.
  - Da internet entram só o escritório (`132.255.228.131`), o WireGuard dos ASNs e o ping deles.
  - Pela VPN: DNS (53, DoH 443, DoT 853) de todos; o resto só do escritório.
  - Clientes isolados entre si.

Painel do Technitium Cloud: `http://10.250.100.1:5380`, a partir do escritório. Mudanças no Advanced Blocking
são feitas pelo console ou pelo Technitium local: o console reenvia a configuração ao Cloud a cada minuto.

## Fase 0: Levantamento (antes de mexer)

1. **Identificar o site** no 2DRTR001 (peer em `wireguard_2D`):
   - **Número e túnel:** número N e IP do túnel antigo (`10.100.100.N`).
   - **Redes:** redes do `allowed-address`. Atenção às redes extras fora do padrão `10.N`, como a Cotrel
     (`192.168.x`) e a Moral PBS (`172.16.x`).
   - **IP público:** o `current-endpoint-address` do peer.
2. **Descobrir o ASN** do IP público: `https://stat.ripe.net/data/network-info/data.json?resource=<IP>`.
3. **Liberar o acesso** no roteador do cliente (feito por uma pessoa):
   - porta 22 liberada para o escritório;
   - chave `id_ed25519_mikrotik` importada no usuário `claude`:
     ```
     /file add name=claude-mikrotik.pub contents="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICCNU0mr+QpsMhKMVHXismgENEys0SQJg/CFlPUyD63S claude-mikrotik-20261103"
     /user ssh-keys import public-key-file=claude-mikrotik.pub user=claude
     ```
   - de preferência no grupo `full`: no grupo `write`, o `/export file=` não funciona (a exportação é salva
     pela tela, no PC).
4. **Ler a configuração** do roteador, sem alterar nada:
   - WireGuard, rotas, NAT, filtro, DHCP e `/ip dns`;
   - **masquerade sem interface de saída**: precisa da exceção para o túnel (Fase 3);
   - **faixa `10.250.100.0/24`** já em uso localmente;
   - **domínio AD local**, como `gd.local` ou `moderna.local`: precisa de encaminhamento FWD para o DC (Fase 5).
5. **DNS Guard:** conferir se a rede `10.N.0.0/16` está cadastrada numa empresa no console. Sem cadastro, o
   cliente cai no grupo `default`.

## Fase 1: VPS (preparação)

```bash
wg-asn add ASN "Provedor - NOME"
wg-asn list
nft get element inet filtro wg_v4 "{ IP_PUBLICO_DO_CLIENTE }"
```

Sem o ASN cadastrado, o WireGuard do cliente é barrado (e registrado como `wg-barrado:` no log do kernel).

## Fase 2: Túnel novo no roteador do cliente (sem mexer em rota)

1. **Salvar a exportação** no PC: `Documents\mikrotik-backups\NOME-antes-hub-novo-<data>.rsc`.
2. **Reversão automática em 10 min.** O script remove o que tem comentário "hub novo", devolve `distance=1` à
   rota antiga e desliga a `wg-vps-2d`. Troque `<rota antiga da 2D>` pelo comentário da rota atual:
   ```
   /system script add name=rollback-hub-novo source="/ip route remove [find comment~\"hub novo\"]; /ip route set [find comment=\"<rota antiga da 2D>\"] distance=1; /ip firewall nat remove [find comment~\"hub novo\"]; /interface wireguard disable [find name=wg-vps-2d]; /log warning \"hub novo: rollback executado\"; /system scheduler remove [find name=rollback-hub-novo]"
   /system scheduler add name=rollback-hub-novo interval=10m on-event="/system script run rollback-hub-novo"
   ```
3. **Criar o túnel:**
   ```
   /interface wireguard add name=wg-vps-2d listen-port=13232 mtu=1420 comment="hub novo: VPS 187.41.115.189"
   /interface wireguard peers add interface=wg-vps-2d name=VPS-2D public-key="iKud2SFrya0Ddqv8EJtq1Zf/Ig5CXADTWCSv1IX+CXk=" endpoint-address=187.41.115.189 endpoint-port=13231 allowed-address=10.250.100.0/24,10.100.0.0/16 persistent-keepalive=25s comment="hub novo"
   /ip address add address=10.250.100.N/24 interface=wg-vps-2d comment="hub novo: tunel VPS"
   /interface wireguard print where name=wg-vps-2d
   ```
4. **Cadastrar o site na VPS**, com a chave pública da `wg-vps-2d`:
   ```bash
   wg-site add N CHAVE "NOME"
   ```
5. **Testar o túnel antes de mexer em rotas:**
   - `ping 10.250.100.1` a partir do roteador;
   - `ping 10.250.100.N` a partir da VPS;
   - o handshake aparece em `wg show wg0`.

   O ping para `10.250.100.100` falha, e isso é esperado: o firewall da VPS isola os IPs de túnel entre si.

## Fase 3: Troca das rotas (os dois lados, em sequência)

Faça os dois lados um logo depois do outro. Com um lado só trocado, o tráfego fica assimétrico e a VPS
descarta as respostas (`ct state invalid`).

1. **Roteador do cliente:**
   ```
   /ip firewall nat add chain=srcnat out-interface=wg-vps-2d action=accept comment="hub novo: sem NAT no tunel da VPS" place-before=0
   /ip route add dst-address=10.100.0.0/16 gateway=10.250.100.1 distance=1 check-gateway=ping comment="hub novo: 2D via VPS"
   /ip route set [find comment="<rota antiga da 2D>"] distance=2
   ```
2. **2DRTR001 (escritório):**
   - **Reversão automática** própria:
     ```
     /system script add name=rollback-hub-novo-N source="/ip route remove [find comment~\"hub novo: NOME\"]; /ip route set [find comment=\"<rota antiga do site>\"] distance=1; /system scheduler remove [find name=rollback-hub-novo-N]"
     /system scheduler add name=rollback-hub-novo-N interval=10m on-event="/system script run rollback-hub-novo-N"
     ```
   - **Peer `VPS-2D`:** acrescentar `10.N.0.0/16` (e as redes extras do site) ao `allowed-address`.
   - **Rotas:**
     ```
     /ip route add dst-address=10.N.0.0/16 gateway=10.250.100.1 distance=1 check-gateway=ping comment="hub novo: NOME via VPS"
     /ip route set [find comment="<rota antiga do site>"] distance=2
     ```

O `check-gateway=ping` faz o failover automático: se a VPS cair, os dois lados voltam sozinhos para o túnel
antigo.

## Fase 4: Testes do túnel

- **Do roteador do cliente:** `/tool traceroute 10.100.10.4 src-address=<IP da LAN>`. O caminho esperado é
  `10.250.100.1` → `10.250.100.100` → `10.100.10.4`.
- **Do escritório:** ping para o IP da LAN do cliente, e SSH até o roteador por `10.N.x.1`.
- **Latência:** comparar com o túnel antigo (na AgenciaCanaa: 36 ms até a VPS contra 63 ms antes).
- **Encerrar:** **cancelar as duas reversões automáticas juntas**, a do cliente e a do escritório:
  ```
  /system scheduler remove [find name=rollback-hub-novo]
  /system scheduler remove [find name=rollback-hub-novo-N]
  ```
  O primeiro comando é no roteador do cliente, o segundo no 2DRTR001.

## Fase 5: DNS (padrão)

1. **Listas de endereços:**
   ```
   :foreach a in={"8.8.8.8";"8.8.4.4";"1.1.1.1";"1.0.0.1";"9.9.9.9";"149.112.112.112";"208.67.222.222";"208.67.220.220";"94.140.14.14";"94.140.15.15";"45.90.28.0/24"} do={ /ip firewall address-list add list=PUBLIC_DNS address=$a }
   /ip firewall address-list add list=INTERNAL_DNS address=10.250.100.1 comment=Technitium
   /ip firewall address-list add list=INTERNAL_DNS address=10.100.10.15 comment=Technitium
   ```
2. **Desvio de DNS** (origem = rede do site, destino = Technitium ativo). `FORCE_DNS` **sem** a exceção
   `INTERNAL_DNS`: os clientes recebem os IPs dos Technitium pelo DHCP, e sem o desvio eles não teriam
   failover.
   ```
   /ip firewall nat add chain=dstnat src-address=10.N.0.0/16 protocol=udp dst-port=53 action=dst-nat to-addresses=10.250.100.1 comment="FORCE_DNS_UDP (dns-failover)"
   /ip firewall nat add chain=dstnat src-address=10.N.0.0/16 protocol=tcp dst-port=53 action=dst-nat to-addresses=10.250.100.1 comment="FORCE_DNS_TCP (dns-failover)"
   /ip firewall nat add chain=dstnat src-address=10.N.0.0/16 protocol=tcp dst-port=853 action=dst-nat to-addresses=10.250.100.1 comment="FORCE_DOT (dns-failover)"
   /ip firewall nat add chain=dstnat src-address=10.N.0.0/16 protocol=tcp dst-port=443 dst-address-list=PUBLIC_DNS action=dst-nat to-addresses=10.250.100.1 comment="FORCE_DOH (dns-failover)"
   /ip firewall nat add chain=dstnat src-address=10.N.0.0/16 protocol=udp dst-port=443 dst-address-list=PUBLIC_DNS action=dst-nat to-addresses=10.250.100.1 comment="FORCE_QUIC (dns-failover)"
   ```
3. **Script `dns-failover`:**
   - **Ordem:** Cloud → local → `8.8.8.8` → `1.1.1.1`.
   - **Os dois Technitium fora:** troca também o `/ip dns servers` para `8.8.8.8,1.1.1.1`, e volta depois.
   - **Permissões:** `policy=read,write,test dont-require-permissions=yes`. Sem isso, o netwatch não consegue
     rodar o script e falha em silêncio.
   ```
   /system script add name=dns-failover policy=read,write,test dont-require-permissions=yes comment="DNS: Technitium Cloud > Technitium local > 8.8.8.8 > 1.1.1.1" source=":local c [/tool netwatch get [find comment=\"dns-cloud\"] status]; :local l [/tool netwatch get [find comment=\"dns-local\"] status]; :local p [/tool netwatch get [find comment=\"dns-publico\"] status]; :local alvo \"1.1.1.1\"; :local srv \"8.8.8.8,1.1.1.1\"; :if (\$c = \"up\") do={ :set alvo \"10.250.100.1\"; :set srv \"10.250.100.1,10.100.10.15\" } else={ :if (\$l = \"up\") do={ :set alvo \"10.100.10.15\"; :set srv \"10.250.100.1,10.100.10.15\" } else={ :if (\$p = \"up\") do={ :set alvo \"8.8.8.8\" } } }; :if ([:tostr [/ip dns get servers]] != [:tostr [:toarray \$srv]]) do={ /ip dns set servers=\$srv; /log warning (\"dns-failover: /ip dns servers=\" . \$srv) }; :local r [/ip firewall nat find comment~\"(dns-failover)\"]; :if ([:len \$r] = 0) do={ :return \"\" }; :local atual [/ip firewall nat get [:pick \$r 0] to-addresses]; :local off [/ip firewall nat get [:pick \$r 0] disabled]; :if (\$off or \$atual != \$alvo) do={ /ip firewall nat set \$r to-addresses=\$alvo disabled=no; /log warning (\"dns-failover: clientes no DNS \" . \$alvo) }"
   ```
4. **Netwatch.** No `type=dns`, `host` é o nome a resolver e `dns-server` é o servidor testado:
   ```
   /tool netwatch add type=dns host=google.com dns-server=10.250.100.1 record-type=A interval=15s timeout=3s comment=dns-cloud up-script="/system script run dns-failover" down-script="/system script run dns-failover"
   /tool netwatch add type=dns host=google.com dns-server=10.100.10.15 record-type=A interval=15s timeout=3s comment=dns-local up-script="/system script run dns-failover" down-script="/system script run dns-failover"
   /tool netwatch add type=dns host=google.com dns-server=8.8.8.8 record-type=A interval=15s timeout=3s comment=dns-publico up-script="/system script run dns-failover" down-script="/system script run dns-failover"
   ```
5. **Resolvedor do roteador e DHCP:**
   ```
   /ip dns set servers="10.250.100.1,10.100.10.15" allow-remote-requests=no
   :foreach n in=[/ip dhcp-server network find] do={ /ip dhcp-server network set $n dns-server="" }
   ```
   Com `dns-server` vazio, o DHCP entrega a lista do `/ip dns`. **Nunca** entregar o IP do roteador com o
   `allow-remote-requests` desligado: os clientes ficam sem internet.
6. **Cliente com AD.** Os nomes internos continuam resolvendo no failover público:
   ```
   /ip dns static add type=FWD name=<zona.local> match-subdomain=yes forward-to=<IP do DC>
   ```
7. **Testar o failover:**
   - apontar o `dns-server` dos netwatch para IPs inexistentes (ex.: `10.250.100.254`), um por vez;
   - conferir as cinco regras e o `/ip dns`:
     - Cloud fora: as cinco vão para o local;
     - os dois Technitium fora: vão para o `8.8.8.8`, e o `/ip dns` vira `8.8.8.8,1.1.1.1`;
     - o `8.8.8.8` também fora: vão para o `1.1.1.1`;
   - restaurar os três netwatch e conferir a volta ao Cloud.
8. **Validar com computadores reais** no log do Cloud. Na VPS:
   ```bash
   sqlite3 "/etc/dns/apps/Query Logs (Sqlite)/querylogs.db" "SELECT client_ip, count(*) FROM dns_logs WHERE client_ip LIKE '10.N.%' AND timestamp > datetime('now','-15 minutes') GROUP BY 1"
   ```
   Cada computador deve aparecer com o próprio IP. O lease do DHCP dura 1 h; quem não puder esperar roda
   `ipconfig /renew`. Os Logs do console do DNS Guard ainda não mostram essas consultas, porque leem só o
   Technitium local.

## Fase 6: Encerramento

- Exportar a configuração final do cliente e a do 2DRTR001 para `Documents\mikrotik-backups\`.
- Manter o túnel antigo alguns dias como reserva (`distance=2`). Depois, remover o peer do site em
  `wireguard_2D` e as rotas antigas dos dois lados.

## Armadilhas que já encontramos

| Problema | Como evitar |
|---|---|
| Faixa do túnel conflitando com rede local (a `10.100.200.0/24` era a `bridge-Lan` do escritório) | Conferir `/ip address` no levantamento |
| Masquerade sem interface de saída: o cliente aparece como IP do túnel e cai no grupo da 2D (`10.100.0.0/16`) | NAT `accept` para `wg-vps-2d` antes do masquerade |
| Rota trocada de um lado só: tráfego assimétrico, e a VPS descarta como pacote inválido | Fase 3 nos dois lados em sequência |
| `/tool fetch` termina sem erro mesmo sem conectar (falso "aberto") | Testar com `tcpdump` na VPS ou olhar o `status` do fetch |
| Netwatch não roda o script | `policy=read,write,test` + `dont-require-permissions=yes` |
| Chrome/Edge com `8.8.8.8` usam DoH e escapam do desvio da porta 53 | `FORCE_DOH` e `FORCE_QUIC` |
| DHCP entregando o roteador com `allow-remote-requests` desligado: sem internet | DHCP com `dns-server` vazio |
| `FORCE_DNS` com exceção `INTERNAL_DNS`: sem failover para quem consulta o Technitium direto | Sem a exceção nos sites |
| Usuário `claude` no grupo `write`: `/export file=` sem permissão | Exportar pela tela (`/export terse`) e salvar no PC |

## Pendências antes dos próximos clientes

1. **Redes extras no `wg-site`:** ensinar o `wg-site` a aceitar redes fora do padrão `10.N` (Cotrel, Moral PBS,
   Goiás, Semetra, Thibruma).
2. **Logs do Cloud no DNS Guard:** o analisador coleta logs só do Technitium local, então os clientes migrados
   somem do DNS Guard.
3. **Cadastro da AgenciaCanaa:** a rede `10.39.0.0/16` ainda não está numa empresa no console (cai no grupo
   `default`).
4. **Domínio no DHCP:** o DHCP da AgenciaCanaa entrega `domain=2d.local`. Revisar esse padrão nos próximos sites.
5. **DNS-over-QUIC no Cloud:** não sobe, porque falta a biblioteca `libmsquic` no AlmaLinux.

## Sites migrados

| Site | N | Data | Provedor (ASN) | Observações |
|---|---|---|---|---|
| Escritório 2D (2DRTR001) | 100 | 03/11/2026 | AS264512 | só a faixa do túnel e as rotas dos sites migrados |
| AgenciaCanaa (AGCRTR001) | 39 | 03/11/2026 | AS264525 Coelho Tecnologia | DNS no padrão; usuário `claude` no grupo `write` |
