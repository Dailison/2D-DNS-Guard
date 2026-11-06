#!/bin/bash
# Troca a ordem do failover de DNS de um site que já tem o padrão (dns-padrao.sh):
#   dns-ordem.sh IP_DO_ROTEADOR NOME_PARA_BACKUP local   -> Technitium local > Cloud > 8.8.8.8 > 1.1.1.1
#   dns-ordem.sh IP_DO_ROTEADOR NOME_PARA_BACKUP cloud   -> Technitium Cloud > local > 8.8.8.8 > 1.1.1.1 (padrão)
# "local" é para os sites no mesmo provedor do escritório (Gigabyte, AS264512): chegam ao 10.100.10.15 pelo túnel
# direto (BGP) em 3-9 ms, contra ~33 ms até o Cloud. Ver docs/MIGRACAO-HUB-VPS.md.
set -u
H=$1; NOME=$2; ORDEM=$3
K=~/.ssh/id_ed25519_mikrotik
S() { timeout 30 ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 claude@$H "$1" 2>&1 | tr -d '\r' | grep -v "WARNING\|session may\|upgraded\|pq.html\|^$"; }

case $ORDEM in
  local) A=l; B=c; IA=10.100.10.15; IB=10.250.100.1; DESC="DNS: Technitium local > Technitium Cloud > 8.8.8.8 > 1.1.1.1 (mesmo provedor do escritorio)";;
  cloud) A=c; B=l; IA=10.250.100.1; IB=10.100.10.15; DESC="DNS: Technitium Cloud > Technitium local > 8.8.8.8 > 1.1.1.1";;
  *) echo "ordem: local | cloud"; exit 1;;
esac

[ "$(S ':put [:len [/system script find name=dns-failover]]' | tail -1)" = "1" ] || { echo "ABORTADO: sem o script dns-failover (rodar dns-padrao.sh antes)"; exit 1; }

mkdir -p ~/Documents/mikrotik-backups
F=~/Documents/mikrotik-backups/$NOME-antes-dns-ordem-$(date +%Y%m%d-%H%M).rsc
timeout 40 ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes claude@$H '/export terse' 2>/dev/null | tr -d '\r' > "$F"; echo "backup: $(wc -l < "$F") linhas em $F"

SCRIPT=':local c [/tool netwatch get [find comment=\"dns-cloud\"] status]; :local l [/tool netwatch get [find comment=\"dns-local\"] status]; :local p [/tool netwatch get [find comment=\"dns-publico\"] status]; :local alvo \"1.1.1.1\"; :local srv \"8.8.8.8,1.1.1.1\"; :if (\$'$A' = \"up\") do={ :set alvo \"'$IA'\"; :set srv \"'$IA','$IB'\" } else={ :if (\$'$B' = \"up\") do={ :set alvo \"'$IB'\"; :set srv \"'$IB','$IA'\" } else={ :if (\$p = \"up\") do={ :set alvo \"8.8.8.8\" } } }; :if ([:tostr [/ip dns get servers]] != [:tostr [:toarray \$srv]]) do={ /ip dns set servers=\$srv; /log warning (\"dns-failover: /ip dns servers=\" . \$srv) }; :local r [/ip firewall nat find comment~\"(dns-failover)\"]; :if ([:len \$r] = 0) do={ :return \"\" }; :local atual [/ip firewall nat get [:pick \$r 0] to-addresses]; :local off [/ip firewall nat get [:pick \$r 0] disabled]; :if (\$off or \$atual != \$alvo) do={ /ip firewall nat set \$r to-addresses=\$alvo disabled=no; /log warning (\"dns-failover: clientes no DNS \" . \$alvo) }'
S "/system script set [find name=dns-failover] comment=\"$DESC\" source=\"$SCRIPT\""
S '/system script run dns-failover'
S ':local s ""; :foreach r in=[/ip firewall nat find comment~"(dns-failover)"] do={ :set s ($s . [/ip firewall nat get $r to-addresses] . " ") }; :put ([/system identity get name] . " | regras: " . $s . "| /ip dns=" . [:tostr [/ip dns get servers]] . " | netwatch cloud=" . [/tool netwatch get [find comment=dns-cloud] status] . " local=" . [/tool netwatch get [find comment=dns-local] status] . " | resolve via local: " . [:resolve google.com server=10.100.10.15])'
