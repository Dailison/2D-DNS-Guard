#!/bin/bash
# bgp-lote.sh N[:IP_LAN]...: BGP em produção, um site por vez (escritório -> handshake -> site -> confere -> cancela reversão)
# IP_LAN: IP do roteador na LAN (padrão 10.N.20.1). Precisa do ros.sh ao lado. Ver docs/BGP-PRODUCAO.md.
S=$(dirname "$0"); G=$S/bgp-gera.py; T=${TMPDIR:-/tmp}/bgp-lote; mkdir -p $T
R() { bash "$S/ros.sh" "$@"; }
for A in "$@"; do N=${A%%:*}; LAN=${A#*:}; [ "$LAN" = "$A" ] && LAN=10.$N.20.1
  t0=$(date +%s)
  NOME=$(grep -E "^$N +\|" ${G%/*}/bgp-sites.txt | cut -d'|' -f2 | xargs)
  # já tem BGP?
  J=$(R $LAN ':put [:len [/routing bgp connection find]]' | tail -1)
  [ "$J" != "0" ] && { echo "$N $NOME: PULADO (connections=$J; resposta: $J)"; continue; }
  python $G escritorio $N > "$T/esc-$N.rsc"; python $G site $N > "$T/site-$N.rsc"
  R 10.100.30.1 "$T/esc-$N.rsc" > "$T/l-$N.txt"
  HS=""; for i in $(seq 1 12); do
    HS=$(R 10.100.30.1 ":foreach p in=[/interface wireguard peers find where interface=wireguard_2D] do={ :if ([:typeof [:find [:tostr [/interface wireguard peers get \$p allowed-address]] \"10.100.100.$N/32\"]] != \"nil\") do={ :put [/interface wireguard peers get \$p last-handshake] } }" | tail -1)
    [ -n "$HS" ] && break; sleep 5; done
  [ -z "$HS" ] && { echo "$N $NOME: FALHOU — túnel antigo sem handshake em 60 s (lado do escritório aplicado, sessão parada; site não mexido)"; continue; }
  timeout 90 ssh -i ~/.ssh/id_ed25519_mikrotik -o BatchMode=yes -o IdentitiesOnly=yes claude@$LAN '/export terse' 2>/dev/null | tr -d '\r' > ~/Documents/mikrotik-backups/$(echo $NOME | tr ' &' '__')-antes-bgp-$(date +%Y%m%d-%H%M).rsc
  R $LAN "$T/site-$N.rsc" 90 >> "$T/l-$N.txt"
  sleep 15
  ST=$(R $LAN ':foreach s in=[/routing bgp session find] do={ :put ([/routing bgp session get $s name] . "=" . [/routing bgp session get $s established] . "/" . [/routing bgp session get $s prefix-count]) }' | tr '\n' ' ')
  RT=$(R 10.100.30.1 ":put [:len [/ip route find where bgp and active and dst-address in 10.$N.0.0/16 and gateway=10.100.100.$N]]" | tail -1)
  P=$(ping -n 4 $LAN | grep -oE "(M.dia|Average) = [0-9]+ms" | grep -oE "[0-9]+ms")
  K=$(ssh -i ~/.ssh/id_ed25519_k3s -o BatchMode=yes root@10.100.50.202 "ping -c3 -q -W2 $LAN | grep -oE '[0-9]+ received'")
  if echo "$ST" | grep -q "escritorio-1=true" && echo "$ST" | grep -q "vps-1=true" && [ "${RT:-0}" -gt 0 ] && [ -n "$P" ] && echo "$K" | grep -q "^[1-9]"; then
    grep -q "rollback-bgp" "$T/site-$N.rsc" && R $LAN '/system scheduler remove [find name=rollback-bgp]' >/dev/null
    echo "$N $NOME: OK | $ST| escritório: $RT rotas diretas | PC->$LAN $P | k3s $K | $(( $(date +%s) - t0 ))s"
  else
    echo "$N $NOME: CONFERIR (reversão em 10 min continua armada) | $ST| rotas diretas=$RT | PC ping=$P | k3s=$K"
  fi
done
