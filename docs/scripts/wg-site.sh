#!/bin/bash
# Cadastra/atualiza/remove o Mikrotik de um site no WireGuard da 2D.
#   wg-site add N CHAVE_PUBLICA "Nome" [REDE_EXTRA ...]   site N -> 10.250.100.N/32 + 10.N.0.0/16 (N=100: escritório,
#                                        10.100.0.0/16) + redes fora do padrão (ex.: 172.16.10.0/23 da Moral PBS)
#   wg-site del N
#   wg-site list
set -euo pipefail
CONF=/etc/wireguard/wg0.conf
acao=${1:-list}
if [ "$acao" = list ]; then exec /usr/local/sbin/wg-status; fi
n=${2:?número do site (1-254)}
[[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 2 ] && [ "$n" -le 254 ] || { echo "site inválido: $n" >&2; exit 1; }
tunel="10.250.100.$n/32"
if [ "$n" = 100 ]; then rede="10.100.0.0/16"; else rede="10.$n.0.0/16"; fi
# tira o bloco antigo deste site (se houver) do arquivo
remover() { awk -v id="# site $n " "BEGIN{p=1} /^# site /{p=(index(\$0,id)!=1)} /^\[Interface\]/{p=1} p" "$CONF" > "$CONF.tmp" && cat "$CONF.tmp" > "$CONF" && rm -f "$CONF.tmp"; }
antiga=$(awk -v id="# site $n " "index(\$0,id)==1{f=1} f&&/^PublicKey/{print \$3; exit}" "$CONF")
case "$acao" in
  add)
    chave=${3:?chave pública do Mikrotik}; nome=${4:-site $n}
    extras=(); [ $# -gt 4 ] && extras=("${@:5}")
    permitidos="$tunel,$rede"
    for e in "${extras[@]}"; do
      [[ "$e" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || { echo "rede extra inválida: $e" >&2; exit 1; }
      permitidos="$permitidos,$e"
    done
    [ "$(printf %s "$chave" | base64 -d 2>/dev/null | wc -c)" = 32 ] || { echo "chave pública inválida" >&2; exit 1; }
    cp -p "$CONF" "$CONF.bak"
    remover
    printf "\n# site %s — %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n" "$n" "$nome" "$chave" "${permitidos//,/, }" >> "$CONF"
    [ -n "$antiga" ] && [ "$antiga" != "$chave" ] && wg set wg0 peer "$antiga" remove
    wg set wg0 peer "$chave" allowed-ips "$permitidos" persistent-keepalive 25
    ip route replace "$rede" dev wg0
    for e in "${extras[@]}"; do ip route replace "$e" dev wg0; done
    echo "ok: site $n ($nome) -> ${permitidos//,/, }";;
  del)
    extras=$(awk -v id="# site $n " "index(\$0,id)==1{f=1} f&&/^AllowedIPs/{sub(/^AllowedIPs *= */,\"\"); print; exit}" "$CONF" | tr ',' '\n' | tr -d ' ' | grep -vxF -e "$tunel" -e "$rede" || true)
    cp -p "$CONF" "$CONF.bak"; remover
    [ -n "$antiga" ] && wg set wg0 peer "$antiga" remove
    ip route del "$rede" dev wg0 2>/dev/null || true
    for e in $extras; do ip route del "$e" dev wg0 2>/dev/null || true; done
    echo "removido: site $n";;
  *) echo "uso: wg-site add|del|list" >&2; exit 1;;
esac
