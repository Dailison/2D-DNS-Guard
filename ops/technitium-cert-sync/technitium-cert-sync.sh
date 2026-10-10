#!/bin/sh
# Roda no nó do k3s (usuário claude, cron semanal): leva o certificado 2dtecnologia.com do cert-manager
# (secret 2d-sites/2dtecnologia-tls) para o Technitium (DoT, DoH e console), que não renova sozinho.
# A chave ~/.ssh/technitium_cert_sync só consegue, no servidor, rodar o instalador (comando forçado).
set -eu
umask 077
DNS=${TECHNITIUM_HOST:-10.100.10.15}
CHAVE=${TECHNITIUM_CERT_KEY:-$HOME/.ssh/technitium_cert_sync}
K="sudo -n /usr/local/bin/k3s kubectl"
D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
$K -n 2d-sites get secret 2dtecnologia-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > "$D/tls.crt"
$K -n 2d-sites get secret 2dtecnologia-tls -o jsonpath='{.data.tls\.key}' | base64 -d > "$D/tls.key"
openssl pkcs12 -export -in "$D/tls.crt" -inkey "$D/tls.key" -passout pass: -out "$D/cert.pfx"
printf '%s ' "$(date '+%F %T')"
ssh -T -i "$CHAVE" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 root@"$DNS" < "$D/cert.pfx"
