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
  - Dom Bosco ↔ Estácio vai pela VPS: a VPS manda a rede de um para o outro.
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
- **2DRTR001:** não filtra entrada pelos túneis (só `in-interface-list=WAN`).

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

## Situação por site

Veja a seção "Rollout" abaixo. As exceções são registradas lá.
