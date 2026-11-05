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
- `wg-site add N CHAVE "NOME" [REDE_EXTRA ...]`: cadastra o peer do site (`10.250.100.N/32` + `10.N.0.0/16` + redes
  fora do padrão, ex.: `172.16.10.0/23` da Moral PBS), com as rotas na VPS. Cópia em `docs/scripts/wg-site.sh`.
- `wg-asn add ASN "nome"`: libera a porta 13231 para os prefixos do provedor (atualização semanal).
- `wg-status` (ou `wg-site list`): clientes conectados, como a tela de peers da Mikrotik — nome, IP do túnel,
  redes, endpoint, último handshake, tráfego e status (ATIVO = handshake nos últimos 3 min). `wg-status -w 5`
  atualiza a cada 5 s. O `wg show` puro mostra o mesmo, mas só com as chaves públicas.
- Firewall: `/etc/nftables/vpn.nft`.
  - Da internet entram só o escritório (`132.255.228.131`), o WireGuard dos ASNs e o ping deles.
  - Pela VPN: DNS (53, DoH 443, DoT 853) de todos; o resto só do escritório.
  - Clientes isolados entre si.

Painel do Technitium Cloud: `http://10.250.100.1:5380`, a partir do escritório. Mudanças no Advanced Blocking
são feitas pelo console ou pelo Technitium local: o console reenvia a configuração ao Cloud a cada minuto.

## Scripts

Em [`docs/scripts/`](scripts/), rodados do PC do escritório (chaves `id_ed25519_mikrotik` e `id_ed25519_vps`):

- `migra-tunel.sh N "Nome" IP_LAN "rota da 2D no site" "rota do site no escritório" ASN`: Fases 1 a 4 para um
  site sem par com outro site (`SEM_REVERSAO_SITE=1` para roteador sem scheduler; `EXTRAS="172.16.10.0/23"` para
  redes fora do `10.N`, que entram na VPS, no peer `VPS-2D` e nas rotas do escritório — a rota antiga de cada uma
  é achada pela rede + `gateway=10.100.100.N`). Backup vazio pelo SSH: busca o export gravado no roteador por `scp`. Para antes da troca se o túnel novo não pinga ou se a
  reversão automática não puder ser armada; cancela as reversões só se os testes passarem.
- `dns-padrao.sh IP_LAN 10.N.0.0/16 NOME`: Fase 5 completa, com o teste de failover. Sem regras `FORCE_*`, cria tudo.
  Com regras `FORCE_*` (inclusive desligadas), adapta: desliga o failover antigo (netwatch por ping), aponta as
  cinco regras para o Cloud e as reativa, tira a exceção de destino e o `to-ports`, e força a porta 443 no DoH.
  Para se não achar exatamente as cinco regras.
- `levanta.sh N "trecho do nome do peer"`: Fase 0 (só leitura) — peer, ASN, rotas, NAT, DNS, DHCP, netwatch, empresa no DNS Guard; avisa quando o escritório vê o peer com IP privado.
- `wg-site.sh`: cópia do `/usr/local/sbin/wg-site` da VPS.
- `wg-status.py`: cópia do `/usr/local/sbin/wg-status` da VPS.

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
6. **Mais de um link de internet** (ex.: Alencar, Coelho + Fibralink): o túnel novo sai pelo link ativo. Cadastre o ASN de
   todos os links com `wg-asn`; se o de reserva não estiver liberado, o `check-gateway` devolve o tráfego ao túnel
   antigo quando ele estiver em uso. ASN grande (ex.: AS18881 da Vivo, ~1.000 prefixos) é aceito, mas amplia bem a lista
   de liberados. Se o site tem failover de internet por netwatch no 8.8.8.8, o `dns-publico` pode ficar `down` com o
   principal fora (o desvio público cai no 1.1.1.1). IP público de um link específico: rota temporária `/32` para o `icanhazip.com`
   pelo link e `/tool fetch url="http://icanhazip.com" output=user`.
7. **Site sem DNS no padrão** (ex.: Alencar, que usava 8.8.8.8): aplicar o padrão faz o site passar a ser filtrado.
   Confirmar com o usuário e cadastrar a empresa no console. Entradas `/ip dns static` do roteador deixam de
   valer para os clientes.
8. **Sites da mesma empresa que conversam entre si** (rota para a rede do outro site pelo túnel antigo, como
   Economize ↔ Ice Beer): liberar o par na VPS e **migrar os sites na mesma janela**. Com só um deles na VPS, o
   tráfego entre eles quebra no meio (o escritório não pode repassar origem de outro site para a VPS).
   ```bash
   # na VPS, em /etc/nftables/vpn.nft, set pares_sites (os dois sentidos):
   #   elements = { 10.33.0.0/16 . 10.34.0.0/16, 10.34.0.0/16 . 10.33.0.0/16 }
   nft -c -f /etc/nftables/vpn.nft && nft -f /etc/nftables/vpn.nft
   ```
   No túnel novo do site, o `allowed-address` do peer `VPS-2D` inclui a rede do outro site, e a Fase 3 cria
   também a rota para ela.

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

**Ordem e acesso:**
1. Trocar primeiro o escritório.
2. Depois, os sites, pelo **IP do túnel antigo** (`10.100.100.N`). Com o escritório já trocado, o IP da LAN do
   site fica assimétrico até o site trocar, e o SSH por ele não abre.
3. A sessão SSH cai logo depois de o comando de troca ser executado no site (as respostas passam a sair pelo
   túnel novo). Por isso, rode cada troca com `timeout` (ex.: `timeout 15 ssh ...`), para uma sessão presa não
   travar a próxima troca.
4. Depois, acessar o site pelo IP da LAN.

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

**Site com AD no escritório** (ex.: Dom Bosco/Estácio, `fevi.local` no DC 10.100.10.6): depois do `dns-padrao.sh`, crie a
lista `DNS_AD` com os DCs e use-a como única exceção de destino nas `FORCE_DNS_UDP/TCP` (consultas diretas ao DC não são
desviadas; Technitium e o próprio roteador continuam desviados):
```
:foreach a in={"10.100.10.5";"10.100.10.6"} do={ /ip firewall address-list add list=DNS_AD address=$a comment="servidor AD" }
/ip firewall nat set [find comment~"FORCE_DNS_(UDP|TCP)"] dst-address-list=!DNS_AD
```
Limitação: com os DOIS Technitium fora, o desvio vai para o DNS público e o domínio AD não resolve pelos clientes (o
`/ip dns static type=FWD` só vale para o próprio roteador, que não atende os clientes).

**Site que já tem as regras `FORCE_*` do escritório** (Economize, Ice Beer): não crie regras novas. Nas
existentes:
- aponte para `10.250.100.1` e acrescente ` (dns-failover)` ao comentário;
- nas `FORCE_DNS_UDP`/`TCP`, tire a exceção de destino (`!dst-address-list`) e mantenha a de origem;
- acrescente `10.250.100.1` à lista `INTERNAL_DNS`;
- confira a porta do `FORCE_DOH` (no Ice Beer estava 8082 em vez de 443);
- se houver um failover antigo (netwatch por ping que liga e desliga as regras `FORCE_`), **desligue-o** antes:
  ele mexeria nas regras novas também.

Depois, siga a partir do passo 3 (script, netwatch, `/ip dns` e DHCP).

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
   - **Variáveis escapadas:** no comando abaixo, cada variável vai como `\$c`, `\$alvo`... Sem a barra, o
     RouterOS troca a variável por vazio ao gravar, e o script dá `syntax error` ao rodar. Confira depois com
     `/system script run dns-failover`.
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
6. **Cliente com AD.** Veja "Site com AD no escritório" acima. A entrada abaixo só faz o PRÓPRIO roteador resolver o
   domínio no failover público (os clientes são desviados para o DNS público e não a usam):
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
| Comando de verificação via SSH em IP novo sem `StrictHostKeyChecking=accept-new`: falha e o "0 pendentes" parece sucesso (quase deixou reversões armadas no Dom Bosco/Estácio) | Sempre `accept-new` e conferir a resposta do roteador, não a contagem do `grep` |
| Usuário `claude` no grupo `write`: `/export file=` sem permissão | Exportar pela tela (`/export terse`) e salvar no PC |
| IP do site sem acesso à Hostinger (ex.: Centro Cardio): o túnel novo não faz handshake | `migra-tunel.sh` para antes da troca; confirmar com `tcpdump -ni eth0 host <IP>` na VPS (vê antes do firewall) e abrir chamado na Hostinger/provedor |
| Rotas do escritório com o MESMO comentário (ex.: `ROTA G&D` para 10.70/71/72) | `migra-tunel.sh` localiza a rota do escritório pelo comentário E pela rede |
| Roteador sem `device-mode` com scheduler (G&D, Canaa Importados) | `SEM_REVERSAO_SITE=1 migra-tunel.sh ...`: segue só com a reversão do escritório (o `check-gateway` ainda protege) |
| Porta 13232 já usada por outro WireGuard do roteador (ex.: Locan): `wg-vps-2d` fica desligada (X) e nunca envia | `migra-tunel.sh` escolhe a primeira porta livre a partir da 13232 e reaproveita uma `wg-vps-2d` já criada |
| AD com DC dentro do site (ex.: Locan): o Cloud não resolve o domínio enquanto o site está no túnel antigo | Normal: a VPS só alcança a rede do site depois da migração; conferir `:resolve dominio server=10.250.100.1` no fim |
| Provedor do site sem internet real (só rede interna até o escritório, ex.: Haras GV) | Ver o IP com que o escritório enxerga o peer (privado = alerta); capturar `udp[8] = 1` na VPS; manter no túnel antigo |
| ASN sem resultado no RIPEstat (blocos da LACNIC) | Na VPS: `dig +short TXT <IP invertido>.origin.asn.cymru.com` |
| `device-mode home` (ex.: Canaa Importados): `/system scheduler` bloqueado, sem reversão automática no site | Conferir `/system device-mode print`; mudar o modo exige acesso físico ao roteador (botão). Netwatch e scripts funcionam |
| Ping vindo do túnel barrado na VPS: o `check-gateway=ping` das rotas novas falha | A VPS aceita `icmp echo-request` do `wg0` (já liberado) |
| Troca de rota disparada e a sessão SSH presa, sem a troca seguinte | `timeout` em cada SSH; sites pelo IP do túnel antigo (Fase 3) |
| Script gravado sem `\$`: `syntax error` e failover parado | Escapar as variáveis; rodar o script uma vez para conferir |
| Sites da mesma empresa migrados em janelas diferentes: o tráfego entre eles quebra | Par em `pares_sites` e migração na mesma janela |
| Failover antigo (netwatch por ping) mexendo nas regras `FORCE_` novas | Desligar o netwatch antigo antes do novo |
| Regra `FORCE_` duplicada (Tropical: duas `FORCE_DNS_UDP` iguais) ou só as de DNS (Barretos): o `dns-padrao.sh` para | Remover a cópia idêntica / completar as cinco antes de rodar |
| `FORCE_` antigas desligadas e incompletas (Goiás: só UDP/TCP para 10.100.50.202) | Remover e rodar no modo de criação |
| Modo de criação põe a `FORCE_DNS_UDP` no topo: passaria na frente dos `LIBERADOS` | Recriar as regras `LIBERADOS_*` (8.8.8.8 / accept) com `place-before` da primeira `FORCE_` |
| Rede `192.168.x` do site sem rota no escritório (Barretos, Goiás, Moral CAN): fora da VPS | Só funciona porque está em `LIBERADOS` (vai direto ao 8.8.8.8); se sair da lista, precisa de `EXTRAS` |
| Rota antiga numa tabela de política (Tropical `to_wan2`) aparece ativa no teste | Conferir `routing-table`; a do `main` é a que vale |
| Backup `/export terse` pelo SSH volta vazio ou cortado (roteador lento) | `/export file=` + `scp` (o script já faz quando sai vazio) |

## Pendências antes dos próximos clientes

1. **Redes extras:** feito (`wg-site ... REDE_EXTRA`, `EXTRAS=` no `migra-tunel.sh`; Moral PBS). Falta Cotrel (Semetra e
   Thibruma feitas em 05/11).
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
| Economize (EMZRTR001) | 33 | 03/11/2026 | AS264512 | par com o Ice Beer; já tinha `FORCE_*`; tem VPN própria de usuários (`wg-VPN`, `10.33.50.x`); rota antiga do galpão (`10.22.0.0/16`) ficou no túnel antigo |
| Economize - Ice Beer (EMZRTR003) | 34 | 03/11/2026 | AS264512 (CGNAT) | par com o Economize; `FORCE_DOH` corrigido (8082 → 443); netwatch antigo desligado |
| Alencar (ALCRTR001) | 25 | 04/11/2026 | AS264525 Coelho Tecnologia (link principal) | antes usava 8.8.8.8 sem filtro: passou a ser filtrado (política `default` até o cadastro); link reserva Fibralink (CGNAT) sem ASN cadastrado: se a Coelho cair, o `check-gateway` volta ao túnel antigo; nomes fixos ALCNOTURNO001/002 no roteador ficaram sem uso (decisão do usuário) |
| Boiadeiro (BOIRTR001) | 19 | 04/11/2026 | AS270996 Link Prime Tecnologia | DNS antes: 10.100.10.5 + 8.8.8.8 sem desvio; já tinha empresa no DNS Guard; nome fixo BOISRV001 ficou no roteador sem uso (decisão do usuário) |
| Canaa Importados (CIMRTR001) | 62 | 04/11/2026 | AS270240 | `device-mode home`: sem scheduler (reversão automática só do lado do escritório); DNS antes 8.8.8.8 sem filtro, política `default` até o cadastro |
| Churrascaria Tocantins (MikroTik) | 54 | 04/11/2026 | AS264257 Livre WiFi Telecom | ASN não aparece no RIPEstat (LACNIC): usar `dig TXT <ip-invertido>.origin.asn.cymru.com`; rede de convidados entregava 8.8.8.8 pelo DHCP e passou ao padrão |
| Clinica do Trabalhador (CDTRTR001) | 38 | 04/11/2026 | AS264512 (CGNAT) | unidade da Inclua Mais no DNS Guard; tinha `FORCE_*` todas desligadas (resolvia no 8.8.8.8) e `FORCE_DOH` com `to-ports=8082`: adaptadas pelo `dns-padrao.sh`; nome fixo SRVCONCENT ficou no roteador sem uso |
| Conexao Espetaria (CONRTR001) | 47 | 04/11/2026 | AS264512 (CGNAT) | DNS antes 8.8.8.8 sem filtro; no DNS Guard só a empresa automática "Rede 10.47.0.0/16"; roteador SEM nenhuma regra de filtro; nome fixo CX001 (PC caixa/servidor) ficou no roteador sem uso (decisão do usuário) |
| Dentista Facil (DFRTR001) | 41 | 04/11/2026 | AS264512 | DNS antes 8.8.8.8 sem filtro; sem empresa no DNS Guard (política `default`); roteador SEM regras de filtro; listas de endereços antigas sem uso (DOH_SERVERS, TRUSTED_DNS) |
| Disneylandia (DLARTR001) | 48 | 04/11/2026 | AS18881 Vivo/Telefônica (link reserva, em uso) + AS264525 Coelho (principal, fora do ar na migração) | dois links com failover próprio por netwatch no 8.8.8.8 (o `dns-publico` fica `down` com a Coelho fora: no failover público os clientes vão p/ o 1.1.1.1); sem regras de entrada no firewall; sem empresa no DNS Guard; relógio do roteador 1 h atrasado |
| Dom Bosco (FVRTR001) | 28 | 04/11/2026 | AS264512 Gigabyte (principal, CGNAT) + AS264525 Coelho (reserva) | par com a Estácio (os dois conversavam pelo escritório); AD `fevi.local` no DC 10.100.10.6 do escritório: lista `DNS_AD` (10.100.10.5/6) como única exceção de destino nas FORCE_DNS; usuário `claude` estava no grupo `read`; redes 10.1.x.x por um equipamento local (10.28.200.241), fora da VPN |
| Estácio (ESTRTR001) | 29 | 04/11/2026 | AS264512 | par com o Dom Bosco; mesma empresa (unidade) e mesmo AD `fevi.local`; failover antigo desligado; `/ip dns` tinha o DC como 2ª opção |
| G&D Matriz (GDRTR001) | 70 | 04/11/2026 | AS264512 (CGNAT) | `device-mode` sem scheduler; AD `gd.local` no DC 10.100.10.20 (lista `DNS_AD`); usuário `claude` estava desativado |
| G&D Reman (S11DREMAN) | 71 | 04/11/2026 | AS14593 Starlink | AD `gd.local` (`DNS_AD`); rede extra 10.10.10.0/23 no DHCP, sem dispositivos |
| G&D Operação (S11DOP) | 72 | 04/11/2026 | AS14593 Starlink | `device-mode` sem scheduler; AD `gd.local`; aceitava 10.70 no túnel, mas Matriz e Operação se falam pela internet (sem par) |
| G&D Infra (S11DINFRA) | 73 | 04/11/2026 | AS14593 Starlink | `device-mode` sem scheduler; AD `gd.local` |
| Hotel Lancaster (HLCRTR001) | 56 | 04/11/2026 | AS264512 (CGNAT) | DHCP entregava 8.8.8.8 em todas as redes; já tinha empresa no DNS Guard; sem regras de filtro |
| Imperio (IMPRTR001) | 16 | 04/11/2026 | AS264525 Coelho | DNS antes 8.8.8.8; nomes fixos SERVIDOR/servidor.2d.local ficaram no roteador sem uso; redirecionamentos da internet p/ 10.16.200.200 mantidos |
| Inclua Mais (MK Clinica Inclua Mais) | 24 | 04/11/2026 | AS264512 | `DNS_AD` 10.100.10.5 (domínio 2d.local); redes extras 192.168.0.0/24 e 192.168.18.0/24 só com 1 equipamento cada; sem par com a Clínica (38) |
| Lebom (LEBRTR001) | 26 | 04/11/2026 | AS264512 | masquerade sem out-interface; DNS antes 8.8.8.8; sem empresa no DNS Guard; rede 192.168.18.0/24 vazia |
| Madá (MHCRTR001) | 43 | 04/11/2026 | AS264525 Coelho | `DNS_AD` 10.100.10.5; netwatch de log no 1.1.1.1 mantido; 1ª rodada não leu a chave (script agora repete a leitura) |
| Locan (LOCRTR001) | 17 | 04/11/2026 | AS264512 | AD próprio `locan.local` (DC locad001 10.17.10.5, `DNS_AD` 10.17.10.5 + 10.100.10.5): o Cloud só resolve o domínio depois da migração; túnel direto `wireguard-Haras` (porta 13232) com o Haras GV, fora do hub → `wg-vps-2d` na 13233; o AD tem registros antigos de `locan.local` (10.0.10.5 e .54) |
| Posto ISO (ISORTR001) | 65 | 04/11/2026 | AS270996 Link Prime | `DNS_AD` 10.100.10.5 (domínio 2D.local); rede 192.168.0.0/24 na LAN sem DHCP |
| Norte e Sul I (SNSRTR001) | 51 | 04/11/2026 | AS264512 | túnel direto `wg-NorteSul` com a unidade II (10.52), fora do hub; DNS antes 8.8.8.8 (sem FORCE_*) |
| Norte e Sul II (SNSRTR002) | 52 | 04/11/2026 | AS264512 | túnel direto `wg-norteSul` com a unidade I, fora do hub; DNS antes 8.8.8.8 (sem FORCE_*); sem regras de filtro |
| Talisma (TLMRTR001) | 8 | 04/11/2026 | AS264512 | DNS antes 8.8.x sem desvio e `allow-remote` ligado; sem empresa no DNS Guard (política `default`) |
| Vila da Mata (VLMRTR001) | 61 | 04/11/2026 | AS61851 Garra Fibra (principal) | DHCP entregava 8.8.8.8; reserva LivreWifi (CGNAT, ASN não cadastrado): com ela, volta ao túnel antigo pelo `check-gateway` |
| Tropical (TPCRTR001) | 11 | 04/11/2026 | AS264512 | já tinha `FORCE_*` (uma `FORCE_DNS_UDP` duplicada removida); rota da 2D também na tabela `to_wan2` (respostas do link reserva) |
| Moral CAN (MORAL-CANAA) | 58 | 04/11/2026 | AS264496 Fibralink | túnel direto `wg-matriz` com a PBS (10.57 e 172.16.10.0/23), fora do hub; 192.168.11.0/24 em `LIBERADOS`; SEM regras de filtro e a `pppoe-fibra-link` fora da lista `WAN` |
| Moral PBS (MORAL-MATRIZ-N) | 57 | 04/11/2026 | AS266568 MBG Tecnologia | 1ª com rede extra: `172.16.10.0/23` (maioria das máquinas) via `EXTRAS=`; túnel direto `wg-Filiais` com a CAN; `FORCE_DOH` corrigido (8082 → 443) |
| Barretos (SBRTR001) | 9 | 04/11/2026 | AS264525 Coelho (principal) | AD próprio `barretos.local` (DC sbad001 10.9.10.5, `DNS_AD`); 192.168.0.0/24 em `LIBERADOS` (8.8.8.8), sem rota no escritório; reserva via 192.168.18.1 |
| Goiás (GOIRTR001) | 27 | 04/11/2026 | AS264525 Coelho | DNS antes 8.8.8.8 sem desvio (FORCE_ antigas desligadas, removidas); `LIBERADOS` (celulares + "REDE ANTIGA" 192.168.1.0/24) recriados antes das `FORCE_` |
| Semetra (SMTRTR001) | 7 | 05/11/2026 | AS264512 (principal) + Coelho PPPoE (reserva, CGNAT) | rede extra `192.168.10.0/24` ("rede legada", ~15 equipamentos) via `EXTRAS=`; AD próprio `semetra.local` (DC mtad001 10.7.10.5, `DNS_AD` 10.7.10.5 + 10.100.10.5, FWD no roteador); `FORCE_*` existentes adaptadas (exceção de origem `!INTERNAL_DNS` mantida); failover antigo por netwatch no 10.100.10.15 desligado; `10.0.40.0/24` (Raio-X) não tem rota no escritório nem antes nem agora; filtro aceita `new` no forward vindo do WAN (regras 0/1, não mexidas) |
| Moderna (MHCRTR001) | 35 | 05/11/2026 | AS264512 (PPPoE Gigabyte) | AD próprio `moderna.local` (DC mhcad001 10.35.10.5, `DNS_AD` 10.35.10.5 + 10.100.10.5, FWD no roteador); `192.168.50/51.0/24` (servidores com redirecionamento de portas) ficam FORA da VPS: estão em `LIBERADOS` (8.8.8.8) e o escritório já usa `192.168.50.0/24` para a Cotrel; `FORCE_*` existentes adaptadas; mesma identidade (MHCRTR001) registrada para a Madá; **filtro de entrada só na `ether1-UPLINK`, mas o IP público está na `pppoe-out_Gigabyte`: entrada pela internet sem filtro (não mexido)** |
| Casa Nova (CNRTR001) | 23 | 05/11/2026 | AS264512 | AD próprio `casanova.local` (DC cnad002 10.23.10.5, `DNS_AD` + FWD); `192.168.2.0/23` e `10.0.x` configuradas mas sem nenhum lease (fora da VPS); Chiquinho (10.23.101) e Apartamentos (10.23.102) seguem sem filtro (exceção de origem em `INTERNAL_DNS`) |
| Thibruma (TKLRTR001) | 36 | 05/11/2026 | AS264525 Coelho | empresa "TKL" no DNS Guard; rede extra `192.168.11.0/24` (servidores/DVR com redirecionamento de portas; rota `ROTA TESTE` no escritório) via `EXTRAS=`; mesmo bloco 138.0.54.x da Centro Cardio, mas alcança a Hostinger normalmente |
| **Casa Nova - Fazenda** | 21 | **pendente** | AS264525 Coelho (138.0.54.224) | sem SSH pelo túnel antigo (peer com comentário "SEM ACESSO"): precisa liberar a porta 22 e importar a chave do `claude` |
| **Haras GV (RTR001-GILVA01)** | 45 | **pendente** | ? (provedor com rede privada 10.24.x) | o provedor só dá acesso ao escritório (o escritório o vê como 10.24.3.170), não à internet: ping/HTTPS falham, DNS funciona (interceptado), nenhum handshake chega à VPS. `wg-vps-2d` criada e DESLIGADA; segue no túnel antigo. Túnel direto `wg-Locan` com a Locan (10.17), fora do hub |
| **Centro Cardio (CTORTR001)** | 55 | **pendente** | AS264525 Coelho Tecnologia | `138.0.54.128` não alcança a Hostinger (nenhum pacote chega à VPS, em nenhuma porta); túnel novo criado e parado, rotas e DNS intactos; aguarda liberação Hostinger/Coelho. Rota do site ganhou o comentário `ROTA 2D` |
