#!/bin/bash
# upg.sh HOST N NOME: backup, confere 7.25.1 no stable, instala (reinicia) e espera voltar
H=$1; N=$2; NOME=$3
K=~/.ssh/id_ed25519_mikrotik
S() { local o; o=$(SS "$@"); if echo "$o" | grep -q "Host key verification failed"; then ssh-keygen -R $H >/dev/null 2>&1; o=$(SS "$@"); fi; echo "$o"; }
SS() { timeout ${2:-40} ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 claude@$H "$1" 2>&1 | tr -d '\r' | grep -v "^$\|post-quantum\|store now\|upgraded\|Permanently"; }
t0=$(date +%s)
timeout 90 ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes claude@$H '/export terse' 2>/dev/null | tr -d '\r' > ~/Documents/mikrotik-backups/$NOME-antes-7.25.1-$(date +%Y%m%d-%H%M).rsc
V0=$(S ':put [/system resource get version]' | tail -1)
case "$V0" in 7.25.1*) echo "$N $NOME: já estava em $V0"; exit 0;; esac
L=$(S '/system package update set channel=stable; /system package update check-for-updates once; :delay 10s; :put [/system package update get latest-version]' 60 | tail -1 | tr -d ' ')
[ "$L" = "7.25.1" ] || { echo "$N $NOME: FALHOU — stable oferece '$L' (esperado 7.25.1), nada instalado"; exit 1; }
S '/system package update install' 120 >/dev/null
sleep 40
# se ainda responde com a versão antiga depois de 3 min, o install não reiniciou (ex.: falta de espaço)
for i in $(seq 1 48); do
  V=$(S ':put ([/system resource get version] . " up=" . [/system resource get uptime])' 15 | tail -1)
  case "$V" in 7.25.1*) break;; esac
  if [ $i -ge 14 ] && [ -n "$V" ] && echo "$V" | grep -qv "timed out\|refused\|closed\|No route"; then
    ST=$(S ':put [/system package update get status]' 15 | tail -1); echo "$N $NOME: FALHOU — não reiniciou (versão $V; status: $ST)"; exit 1; fi
  sleep 10
done
case "$V" in 7.25.1*) ;; *) echo "$N $NOME: FALHOU — não voltou em ~9 min (último: $V)"; exit 1;; esac
P=$(S '/ping 10.250.100.1 count=3' | grep -oE 'received=[0-9]+' | tail -1)
echo "$N $NOME: OK $V0 -> $V | VPS $P | $(( $(date +%s) - t0 ))s"
