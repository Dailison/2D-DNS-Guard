# Teste de BGP em estrela (hubs VPS + escritório) — 05/11/2026

Sucessor do [teste de OSPF](OSPF-TESTE-BARRETOS.md). **Por que BGP:** o escritório fala com todos, os clientes ficam
isolados e só alguns pares (matriz ↔ filial) conversam. No BGP a política fica nos dois hubs: cada site recebe só o
que o hub manda e só consegue anunciar a própria rede. Os sites têm configuração igual (dois vizinhos, "anuncio a
minha /16").

## Montagem (temporária, com reversão automática)

| Quem | AS | Sessões |
|---|---|---|
| VPS (FRR 10.4.4, `/etc/frr/frr.conf`) | 65250 | escritório, Barretos, Economize, Ice Beer (`10.250.100.x`) |
| 2DRTR001 | 65100 | VPS (principal) + direto pelo `wireguard_2D` com cada site (reserva, `local-pref 50`) |
| Barretos SBRTR001 | 65009 | VPS + escritório direto |
| Economize EMZRTR001 | 65033 | VPS + escritório direto |
| Ice Beer EMZRTR003 | 65034 | VPS + escritório direto (rota `10.100.100.1/32` pelo `wg_2D`, que tem endereço /32) |

- **Política da VPS:** de cada site aceita só `10.N.0.0/16` (até /24); do escritório só `10.100.0.0/16`.
  - Para o escritório: todos os sites.
  - Para Barretos: só o escritório.
  - Para a Economize: escritório + Ice Beer; para a Ice Beer: escritório + Economize.
  - `ip protocol bgp route-map NAO-INSTALA`: a VPS não instala rotas e encaminha pelos AllowedIPs, como sempre.
- **Escritório e sites:** filtro de saída "só as próprias redes" (ninguém repassa o que aprendeu) e filtro de entrada por
  vizinho; sessão direta com `local-pref 50`, para a VPS ser o caminho principal.
- **Temporizadores:** keepalive 3 s, hold 9 s.
- **RouterOS 7.23/7.25:** o AS e o router-id ficam em `/routing bgp instance` (a conexão usa `instance=`).
- **Anúncios:** as redes /24 vêm do `address-list BGP_REDES`. Ficam por cima das estáticas /16 (`hub novo`), que
  continuam como rede de segurança.
- **Peers:** os peers antigos da Economize e da Ice Beer no escritório foram reativados (junto com o de Barretos, do teste
  de OSPF). Isso também religa a rota do galpão da Economize (`10.22`), que usa o túnel antigo.
- **Firewall da VPS:** `tcp dport 179` só dos quatro vizinhos (`vpn.nft`).

## Resultado

- **Estado normal:** tudo pela VPS. Barretos sem nenhuma rota para 10.33/10.34 (ping Barretos → Economize falha:
  isolado); Economize ↔ Ice Beer conversam pela VPS.
- **Falha simulada sem perda** (BGP da Economize bloqueado na VPS, dados seguindo):
  - convergência em ~10 s, nos dois lados: escritório → Economize direto, Economize → escritório direto;
  - volta em ~3 s depois do desbloqueio;
  - **0 perda**: 90/90 do PC e 80/80 Ice Beer → Economize.
  - Na falha, o par usou a estática /16 pela VPS.

## Limites que faltam resolver para produção

1. **Par sem reserva:** com o túnel da Economize com a VPS realmente fora, o tráfego Economize ↔ Ice Beer para. O
   escritório não repassa entre sites, e a VPS só aceita do peer do escritório origem `10.100.0.0/16`. Se quiser reserva
   para pares, o escritório precisa repassar as redes do par e liberar o encaminhamento entre os dois túneis.
2. **Isolamento no caminho direto:** o firewall do 2DRTR001 não barra site → site pelo `wireguard_2D`. O BGP não dá a
   rota, mas uma estática no site ainda passaria. Falta o equivalente ao `pares_sites` no escritório.
3. **Escala:**
   - a política dos hubs deve ser gerada de uma tabela única (site, redes, par), por exemplo estendendo o `wg-site` para
     gravar o vizinho e as listas no FRR e no 2DRTR001;
   - os peers antigos de todos os sites migrados precisam voltar a ficar ativos, porque o túnel direto é a reserva.

## Situação: mantido em produção (05/11, 13:39, pedido do usuário)

As reversões automáticas foram canceladas, e o `frr` está habilitado no boot da VPS. Os peers antigos de Barretos,
Economize e Ice Beer seguem ativos no escritório.

Para desfazer à mão, por roteador:
```
/routing bgp connection remove [find comment~"bgp-2d"]; /routing bgp instance remove [find comment~"bgp-2d"]
/routing filter rule remove [find comment~"bgp-2d"]; /ip firewall address-list remove [find comment~"bgp-2d"]; /ip route remove [find comment~"bgp-2d"]
```
Na VPS: `systemctl disable --now frr`.

**Latência:** Barretos → escritório pela VPS ~68 ms (duas pernas de ~34 ms: site → VPS → escritório); pelo túnel
direto ~34 ms.

**Preferência invertida (05/11, 13:45, pedido do usuário):** o tráfego escritório ↔ site agora prefere o túnel direto
(`local-pref 150` nas sessões diretas, no escritório `bgp-in-9/33/34` e nos sites `bgp-in-direto`), e a VPS vira a
reserva. O DNS do Cloud, o k3s e o par Economize ↔ Ice Beer continuam pela VPS.

| Site → `10.100.20.1` | Pela VPS | Direto |
|---|---|---|
| Barretos | 68 ms | 34 ms |
| Economize | ~65 ms | 3 ms |
| Ice Beer | ~65 ms | 3 ms |

- Failover no sentido novo (sessão direta da Economize bloqueada no escritório): os dois lados para a VPS em ~8 s,
  volta em ~1 s, **0/60 perdidos**.
- **Cuidado ao mudar a preferência:** troque os dois lados juntos. Ao inverter só o escritório, o acesso pela rede local
  dos sites caiu (ida direta, volta pela VPS = assimétrico; a VPS descarta) até os sites serem trocados pelo IP de túnel.
- **Efeito colateral:** o IP de túnel desses sites (`10.250.100.N`) não responde mais a partir do escritório (ida pela
  VPS, volta direta). Use o IP da rede local para gerenciar. Os scripts `migra-tunel.sh`/`levanta.sh` usam o túnel só
  na migração.
- No RouterOS 7.23/7.25, `/routing bgp session refresh` exige `afi=ip`; trocar a regra do filtro já reaplica sozinho.
