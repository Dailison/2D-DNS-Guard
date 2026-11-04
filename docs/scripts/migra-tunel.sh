#!/bin/bash
# Fases 2-4 do roteiro (docs/MIGRACAO-HUB-VPS.md) para UM site com UMA rede 10.N.0.0/16 e sem par com outro site.
#   migra-tunel.sh N "Nome" IP_LAN_DO_ROTEADOR "comentário da rota da 2D no site" "comentário da rota do site no escritório" ASN
#   ex.: migra-tunel.sh 62 "Canaa Importados (CIMRTR001)" 10.62.20.1 "ROTA 2D" "ROTA CANAA IMPORTADOS" 270240
set -u
N=$1; NOME=$2; LAN=$3; RSITE=$4; RESC=$5; ASN=$6
VELHO=10.100.100.$N; NOVO=10.250.100.$N; REDE=10.$N.0.0/16; TAG=$(echo "$NOME" | cut -d' ' -f1)
K=~/.ssh/id_ed25519_mikrotik; V=~/.ssh/id_ed25519_vps
S() { timeout ${3:-25} ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -o ServerAliveInterval=3 -o ServerAliveCountMax=2 claude@$1 "$2" 2>&1 | tr -d '\r' | grep -v "WARNING\|session may\|upgraded\|pq.html\|^$"; }

echo "## VPS: ASN $ASN"; ssh -i $V -o BatchMode=yes root@187.41.115.189 "wg-asn add $ASN \"$NOME\" | tail -1"
echo "## Fase 2: backup e túnel novo"
F=~/Documents/mikrotik-backups/$(echo "$NOME" | tr -d '()' | tr ' ' '_')-antes-hub-novo-$(date +%Y%m%d-%H%M).rsc
timeout 40 ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes claude@$VELHO '/export terse' 2>/dev/null | tr -d '\r' > "$F"; echo "backup no PC: $(wc -l < "$F") linhas"
S $VELHO '/export file=antes-hub-novo'
S $VELHO "/interface wireguard add name=wg-vps-2d listen-port=13232 mtu=1420 comment=\"hub novo: VPS 187.41.115.189\"; /interface wireguard peers add interface=wg-vps-2d name=VPS-2D public-key=\"iKud2SFrya0Ddqv8EJtq1Zf/Ig5CXADTWCSv1IX+CXk=\" endpoint-address=187.41.115.189 endpoint-port=13231 allowed-address=10.250.100.0/24,10.100.0.0/16 persistent-keepalive=25s comment=\"hub novo\"; /ip address add address=$NOVO/24 interface=wg-vps-2d comment=\"hub novo: tunel VPS\""
KEY=$(S $VELHO ':put [/interface wireguard get [find name=wg-vps-2d] public-key]' | tail -1 | tr -d ' ')
ssh -i $V -o BatchMode=yes root@187.41.115.189 "wg-site add $N '$KEY' '$NOME'; sleep 8; wg-status | grep -E '^$N '"
P=$(S $VELHO '/ping 10.250.100.1 count=3' | grep -oE "received=[0-9]+"); echo "site -> VPS: $P"
[ "$P" = "received=3" ] || { echo "ABORTADO: túnel novo sem ping"; exit 1; }

echo "## Fase 3: reversões + troca (escritório, depois o site pelo IP do túnel antigo)"
S $VELHO "/system script add name=rollback-hub-novo source=\"/ip route remove [find comment~\\\"hub novo\\\"]; /ip route set [find comment=\\\"$RSITE\\\"] distance=1; /ip firewall nat remove [find comment~\\\"hub novo\\\"]; /interface wireguard disable [find name=wg-vps-2d]; /log warning \\\"hub novo: rollback executado\\\"; /system scheduler remove [find name=rollback-hub-novo]\"; /system scheduler add name=rollback-hub-novo interval=10m on-event=\"/system script run rollback-hub-novo\""
S 10.100.30.1 "/system script add name=rollback-hub-novo-$N source=\"/ip route remove [find comment~\\\"hub novo: $TAG\\\"]; /ip route set [find comment=\\\"$RESC\\\"] distance=1; /log warning \\\"hub novo: rollback $TAG\\\"; /system scheduler remove [find name=rollback-hub-novo-$N]\"; /system scheduler add name=rollback-hub-novo-$N interval=10m on-event=\"/system script run rollback-hub-novo-$N\""
for h in $VELHO 10.100.30.1; do echo "$h reversão: $(S $h '/system scheduler print without-paging terse where name~"rollback"' | grep -oE 'next-run=[^ ]+ [^ ]+')"; done
RS=$(S $VELHO '/system scheduler print without-paging terse where name~"rollback"' | grep -c next-run); RE=$(S 10.100.30.1 '/system scheduler print without-paging terse where name~"rollback"' | grep -c next-run)
if [ "$RS" = 0 ] || [ "$RE" = 0 ]; then echo "ABORTADO antes da troca: reversão não armada (site=$RS escritório=$RE) — ex.: device-mode bloqueia o scheduler"; S 10.100.30.1 "/system scheduler remove [find name=rollback-hub-novo-$N]"; exit 1; fi
AL=$(S 10.100.30.1 ':put [:tostr [/interface wireguard peers get [find name=VPS-2D] allowed-address]]' | tail -1 | tr ';' ',')
echo "$AL" | grep -q "$REDE" || S 10.100.30.1 "/interface wireguard peers set [find name=VPS-2D] allowed-address=$AL,$REDE"
S 10.100.30.1 "/ip route add dst-address=$REDE gateway=10.250.100.1 distance=1 check-gateway=ping comment=\"hub novo: $TAG via VPS\"; /ip route set [find comment=\"$RESC\"] distance=2" 15
S $VELHO "/ip firewall nat add chain=srcnat out-interface=wg-vps-2d action=accept comment=\"hub novo: sem NAT no tunel da VPS\" place-before=0; /ip route add dst-address=10.100.0.0/16 gateway=10.250.100.1 distance=1 check-gateway=ping comment=\"hub novo: 2D via VPS\"; /ip route set [find comment=\"$RSITE\"] distance=2" 15
sleep 6

echo "## Fase 4: testes"
echo "site:       $(S $NOVO '/ip route print without-paging terse where dst-address=10.100.0.0/16' | grep -oE '^ *[0-9]+ +[A-Za-z]+|gateway=[^ ]+' | paste -sd' ')"
echo "escritório: $(S 10.100.30.1 "/ip route print without-paging terse where dst-address=$REDE" | grep -oE '^ *[0-9]+ +[A-Za-z]+|gateway=[^ ]+' | paste -sd' ')"
R=$(S $NOVO "/ping 10.100.10.4 src-address=$LAN count=4" | grep -oE "received=[0-9]+"); echo "site -> analisador: $R"
echo "escritório -> site: $(ping -n 3 -w 2000 $LAN | grep -oE 'Recebidos = [0-9]+')"; echo "SSH pela LAN: $(S $LAN ':put [/system identity get name]' | tail -1)"
if [ "$R" = "received=4" ] || [ "$R" = "received=3" ]; then
  S $NOVO '/system scheduler remove [find name=rollback-hub-novo]'; S 10.100.30.1 "/system scheduler remove [find name=rollback-hub-novo-$N]"
  echo "reversões canceladas: site=$(S $NOVO '/system scheduler print without-paging terse where name~"rollback"' | grep -c next-run) escritório=$(S 10.100.30.1 '/system scheduler print without-paging terse where name~"rollback"' | grep -c next-run) (0 = canceladas)"
else echo "FALHOU: reversões MANTIDAS (voltam sozinhas em 10 min)"; exit 1; fi
