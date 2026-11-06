# BGP em produção (estrela VPS + escritório) — desde 05/11/2026

Pedido do usuário: "migrar os demais clientes para OSPF". O OSPF foi testado e descartado (ver
[OSPF-TESTE-BARRETOS.md](OSPF-TESTE-BARRETOS.md)): nele todos os roteadores veem as redes de todos os clientes. O
modelo usado é o **BGP** testado em [BGP-TESTE.md](BGP-TESTE.md), que faz o mesmo papel (failover automático e
simétrico) mantendo os clientes isolados.

## Como funciona

| Quem | AS | router-id | Sessões |
|---|---|---|---|
| VPS 187.41.115.189 (FRR, `/etc/frr/frr.conf`) | 65250 | 10.250.100.1 | escritório + todos os sites, pelo `wg0` (`10.250.100.x`) |
| Escritório 2DRTR001 | 65100 | 10.100.30.1 | VPS (`bgp-vps`) + uma sessão direta por site pelo `wireguard_2D` (`bgp-<nome>`) |
| Site N | 65000+N | 10.250.100.N | VPS (`bgp-vps`, reserva) + escritório direto pelo túnel antigo (`bgp-escritorio`, principal) |

- **Escritório ↔ site:** o túnel antigo direto é o principal (`local-pref 150`), e a VPS é a reserva (100).
  - Latência típica: de ~65 ms (duas pernas pela VPS) para a de um túnel só (2–35 ms).
  - Se o túnel direto cair, os dois lados passam para a VPS em ~10 s (keepalive 3 s, hold 9 s), sem perda nos testes.
- **Par (matriz ↔ filial):**
  - Dom Bosco ↔ Estácio **deixou de ser par em 05/11** (o usuário informou que não usam nada entre eles):
    - nos dois roteadores, saíram as rotas de um para o outro e a /16 do outro no `allowed-address` do `VPS-2D`;
    - na VPS, saíram do `pares_sites` (backup `vpn.nft.antes-tirar-par-28-29`) e da tabela.
  - Economize ↔ Ice Beer tem túnel direto com BGP (`local-pref 200`) e a VPS como reserva.
  - Norte e Sul I ↔ II e Moral PBS ↔ CAN seguem nos túneis diretos próprios, com rotas estáticas, fora do BGP.
- **Isolamento:**
  - Cada site anuncia só as próprias redes e recebe só o escritório (e o par).
  - A VPS filtra os dois sentidos por vizinho (`DE-SITEn` / `PARA-SITEn`).
  - O escritório aceita de cada sessão só a rede daquele site.
- **A VPS não instala rotas** (`ip protocol bgp route-map NAO-INSTALA`). Ela encaminha pelos AllowedIPs do `wg0`,
  como sempre; o BGP dela só decide o que cada um aprende.
- **Rede de segurança:** as rotas estáticas `hub novo` (a /16 de cada site pela VPS, e a 10.100.0.0/16 nos sites)
  continuam. Elas são menos específicas que as /24 do BGP.
  - As redes extras (192.168.x / 172.16.10.0/23) têm estática /24 no escritório. Essas passaram para `distance=30`,
    para o BGP (20) ganhar.
- **Nos Mikrotiks:**
  - tudo do BGP tem comentário `bgp-2d`;
  - o `/system note` (Winbox: System → Note) explica a montagem em cada roteador;
  - o peer do túnel antigo no escritório ganhou `| bgp-2d: tunel direto = caminho principal (nao desativar)` no
    comentário.

## Fonte da verdade e gerador

- **`docs/scripts/bgp-sites.txt`:** uma linha por site, com o N, o nome, a interface do túnel antigo, as redes
  anunciadas (incluindo as extras), o par e as observações.
- **`docs/scripts/bgp-gera.py`:** gera tudo a partir da tabela.

| Comando | Gera |
|---|---|
| `bgp-gera.py frr` | o `frr.conf` inteiro da VPS |
| `bgp-gera.py escritorio N` | 2DRTR001: reativa e marca o peer antigo, cria os filtros `bgp-in-N` e `bgp-in-vps`, a sessão direta e a `distance=30` das extras |
| `bgp-gera.py site N` | roteador do site: instância, `BGP_REDES`, filtros, NAT `accept` no túnel antigo, as duas sessões, a nota e a reversão automática (`rollback-bgp`, 10 min) |
| `bgp-gera.py confirma N` | cancela a reversão |
| `bgp-gera.py escritorio-prep` | refaz a chain `bgp-in-vps` (uma regra por site + `reject` no fim); só foi usado uma vez |
| `bgp-gera.py nota-escritorio` | a nota do 2DRTR001 |

**Aplicar na VPS** (depois de mudar a tabela):
```
python docs/scripts/bgp-gera.py frr > frr.conf.novo
scp frr.conf.novo root@187.41.115.189:/root/
python3 /usr/libexec/frr/frr-reload.py --test /root/frr.conf.novo     # mostra o que muda
python3 /usr/libexec/frr/frr-reload.py --reload /root/frr.conf.novo && vtysh -c "write memory"
```

O script do site deve rodar **pelo IP da LAN** (ex. `10.N.20.1`), não pelo IP do túnel: quando a sessão direta
sobe, o IP de túnel `10.250.100.N` deixa de responder ao escritório (ida pela VPS, volta direta).

### Site novo (ou rede nova)

1. Acrescente a linha em `bgp-sites.txt` (ou a rede no campo de redes).
2. Gere e aplique o `frr`.
3. Rode `escritorio N` no 2DRTR001.
4. Rode `site N` no site, pelo IP da LAN.
5. Confira e rode `confirma N`.

Para só acrescentar uma rede num site que já tem BGP:
- no site: `/ip firewall address-list add list=BGP_REDES address=... comment="bgp-2d: redes do site (anunciadas)"`;
- se a rede for fora da 10.N, ela também entra nos filtros `bgp-out` (site) e `bgp-in-N` / `bgp-in-vps` (escritório).

## Firewall

- **VPS:** `vpn.nft` aceita `tcp dport 179` só de `10.250.100.0/24` vindo do `wg0`. Backup em `vpn.nft.antes-bgp-producao`.
- **2DRTR001, entrada:** não filtra a entrada pelos túneis, só a que vem de `in-interface-list=WAN`.
- **2DRTR001, isolamento (05/11, pedido do usuário):** a regra de forward
  `isolamento: site -> site pelo escritorio BLOQUEADO` faz `drop` de `connection-state=new` com
  `in-interface=wireguard_2D` **e** `out-interface=wireguard_2D`. O log tem o prefixo `SITE-SITE`.
  - Fica antes do `jump bloqueio-vpn` e depois de `ESTABELECIDAS E RELACIONADAS`.
  - É uma 2ª barreira: nos sites, o peer do túnel antigo já só aceita `10.100.0.0/16`. O teste
    Barretos → Semetra com rota forçada nem saiu do roteador ("host unreachable").
  - 2D Fazenda (10.4) e 2D Condomínio (10.5) também ficam só com o escritório (decisão do usuário).
  - Escritório → sites, usuários da VPN (`wireguard-VPN`) e k3s → sites continuam liberados.
  - Os pares usam a VPS (`pares_sites`) ou um túnel direto próprio.
  - Backup: `2DRTR001-antes-isolamento-*.rsc`.

## Conferir

| Onde | Comando |
|---|---|
| VPS | `vtysh -c "show bgp summary"` (prefixos recebidos/enviados por vizinho) |
| Escritório | `/routing bgp session print`; `/ip route print where bgp and dst-address in 10.N.0.0/16` (ativa = `gateway=10.100.100.N`) |
| Site | `/routing bgp session print`; `/ip route print where bgp` |

## Desfazer

**Num site:**
```
/routing bgp connection remove [find comment~"bgp-2d"]; /routing bgp instance remove [find comment~"bgp-2d"]
/routing filter rule remove [find comment~"bgp-2d"]; /ip firewall address-list remove [find comment~"bgp-2d"]
/ip firewall nat remove [find comment~"bgp-2d"]
```

**No escritório, para um site:**
```
/routing bgp connection remove [find name=bgp-<nome>]; /routing filter rule remove [find chain=bgp-in-N]
```

**Tudo:** na VPS, `systemctl disable --now frr`. Isso tira as rotas da VPS dos dois lados; o direto continua até
remover também as sessões diretas. Sem BGP, o tráfego volta às estáticas `hub novo`, pela VPS.

## Rollout (05/11/2026, ~16:45–17:25)

**Antes:**
- 2DRTR001 atualizado para o RouterOS 7.25.1.
- VPS: `frr.conf` gerado com os 39 sites. Backup: `/etc/frr/frr.conf.antes-producao-*`.
- VPS: porta 179 aberta para `10.250.100.0/24`.
- Escritório: `escritorio-prep` e a nota.

**Por site** (`bgp-lote.sh` no rascunho da sessão, um site por vez):
1. Lado do escritório.
2. Esperar o handshake do túnel antigo.
3. Export de backup (`~/Documents/mikrotik-backups/<site>-antes-bgp-*.rsc`).
4. Script do site, pelo IP da LAN.
5. Conferir: as duas sessões estabelecidas, rotas diretas no escritório, ping do PC do escritório e ping do k3s.
6. Cancelar a reversão.

**Resultado:**
- **39 sites no BGP:** os 3 do teste mais 36 novos.
  - 7, 8, 11, 12, 14, 16, 17, 19, 23–29, 35, 36, 38, 39, 41, 43, 47, 48, 51, 52, 54, 56–58, 61, 62, 65, 70–73.
  - Todos com as duas sessões e conferidos. Nenhuma reversão disparou.
- **Escritório:** 39 sessões diretas + a VPS, com 171 rotas /24 pelo túnel direto.
- **VPS:** todos os vizinhos estabelecidos.
- **Acesso:** o k3s alcança os 39 sites.
- **Latência do escritório até o roteador do site:** caiu de ~65 ms para 2–4 ms na maioria. Nos sites de outros
  provedores ficou em 30–35 ms, e nos sites Starlink (G&D 71–73), ~110 ms.
- **Failover testado na Semetra** (sessão direta desligada no escritório, ping do PC para o DC 10.7.10.5): **60/60, sem
  perda**. Foi de 2–4 ms para ~66 ms pela VPS e voltou ao direto sozinho ao religar.
- **Par Dom Bosco ↔ Estácio:** pela VPS com BGP (~65 ms, como antes). Um túnel direto, como o da Economize ↔ Ice Beer,
  baixaria a latência, se for o caso.
- **Sem reversão automática:** 62, 70, 72 e 73 (`device-mode` sem scheduler) foram feitos por último.

- **Mais tarde (05/11, depois da migração para a VPS):**
  - Moura (6) e Atacadão Peba (31) entraram no BGP.
  - No Peba só se anuncia a `192.168.2.0/24`, a rede real; a `10.31.20.1` está desativada.
  - `escritorio N` agora também acrescenta as redes extras ao `allowed-address` do peer antigo. Sem isso, o
    WireGuard do escritório descarta o caminho direto.
  - Centro Cardio (55) entrou no BGP em 06/11, a pedido do usuário, **só com a sessão direta**: a Coelho segue
    barrando o caminho até a VPS (o traceroute morre depois de `10.250.0.74`; houve um único handshake às 13:30 de 06/11).
    A sessão `bgp-vps` fica `Idle` e sobe sozinha se o caminho abrir; o vizinho já está no `frr.conf`. A rede de
    segurança dela é a estática `ROTA 2D` pelo túnel antigo, não a `hub novo`. Na tabela: obs `vps-bloqueada`.
  - Map Elite (15) entrou em 06/11, logo depois da migração para a VPS e da atualização para o 7.25.1.

**Fora do BGP:**

| Site | Motivo |
|---|---|
| Fazenda Casa Nova (21) | Sem SSH. |
| Haras GV (45) | Provedor sem internet; só pelo túnel antigo. |

**Quedas durante o dia, sem relação com o BGP:**
- Boiadeiro (19) ficou fora das ~09:20 às ~17:00. Ao voltar, foi atualizado para o 7.25.1 e entrou no BGP.
- Imperio (16) ficou fora ~15 min por volta das 16:45, até no IP público. Entrou no BGP depois.
