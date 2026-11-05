# Teste de roteamento dinâmico (OSPF) com Barretos — 05/11/2026

**Objetivo:** failover automático e simétrico entre o caminho pela VPS e o túnel direto antigo (escritório ↔ site),
inclusive quando só o túnel de UM site com a VPS cai (o `check-gateway=ping` só cobre a VPS inteira).

## Montagem (temporária, com reversão automática)

| Onde | O quê |
|---|---|
| VPS (FRR 10.4.4) | `/etc/frr/frr.conf`: `wg0` NBMA, prioridade 255 (DR), vizinhos unicast `10.250.100.100` e `10.250.100.9`; `ip protocol ospf route-map NAO-INSTALA` (a VPS **não instala** rotas: encaminha pelos AllowedIPs, como sempre) |
| 2DRTR001 | instância `ospf-2d` (router-id 10.100.30.1), NBMA em `wg-vps-2d` (custo 10, prioridade 0) e em `wireguard_2D` (custo 100, DR do segmento); LANs passivas; filtro de entrada só `10.9.0.0/16` |
| SBRTR001 | instância `ospf-2d`, NBMA nos dois túneis (prioridade 0); anuncia `10.9.0.0/16` (o `192.168.0.0/24` fica fora); filtro de entrada só `10.100.0.0/16` |

- Hello 5 s / dead 20 s. O WireGuard com vários peers não repassa multicast: por isso NBMA com vizinhos estáticos.
- As rotas /24 do OSPF ficam por cima das estáticas /16 (`hub novo`), que continuam como rede de segurança.
- O peer antigo de Barretos no `wireguard_2D` do escritório estava desativado (o usuário desativou os peers dos sites
  migrados): foi reativado para o teste. No NBMA, com o vizinho de prioridade 0 fora, o hello sai a cada `poll-interval`
  (120 s): a adjacência direta demora até 2 min para subir.

## Resultado

- Caminho normal: os dois lados pela VPS (`10.250.100.9` / `10.250.100.100` como próximo salto).
- Falha simulada sem perda (OSPF de Barretos bloqueado na VPS, dados seguindo): **convergência em ~20 s, nos dois
  lados, 0 pacote perdido em 100 e em 70**; volta sozinha ~30 s depois do desbloqueio.
- Durante a falha, acesso ao IP de **túnel** do site (`10.250.100.9`) falha (ida pela VPS, volta direta): gerenciar pelo
  IP da LAN.
- Correção feita junto (fica): a VPS aceita como origem o IP de túnel do escritório (`10.250.100.100`), senão o próprio
  2DRTR001 não pingava os sites migrados sem `src-address`.

## Por que não seguir com OSPF

No OSPF todos os roteadores de uma área têm o mapa inteiro (todas as redes de todos os clientes) e cada um decide
sozinho o que instalar. Para o modelo da 2D — o escritório fala com todos, os clientes isolados, só alguns pares
(matriz ↔ filial) conversam — o controle precisa ficar nos hubs. Ver a recomendação de BGP na conversa/roteiro.

## Reversão

Schedulers `rollback-ospf` nos dois Mikrotiks e `rollback-ospf2` na VPS (para o FRR; `frr` desabilitado no boot).
Restos que ficam: regra OSPF no `vpn.nft`, `frr.conf`, peer de Barretos reativado no `wireguard_2D`.
