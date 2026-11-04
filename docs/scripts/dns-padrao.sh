#!/bin/bash
# Aplica o padrão de DNS (Technitium Cloud > local > 8.8.8.8 > 1.1.1.1) num roteador que ainda NÃO tem as regras FORCE_*.
#   dns-padrao.sh IP_DO_ROTEADOR REDE_DO_SITE NOME_PARA_BACKUP     ex.: dns-padrao.sh 10.19.20.1 10.19.0.0/16 BOIRTR001
set -u
H=$1; NET=$2; NOME=$3
K=~/.ssh/id_ed25519_mikrotik
S() { timeout 30 ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 claude@$H "$1" 2>&1 | tr -d '\r' | grep -v "WARNING\|session may\|upgraded\|pq.html\|^$"; }

F=~/Documents/mikrotik-backups/$NOME-antes-dns-$(date +%Y%m%d-%H%M).rsc
timeout 40 ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes claude@$H '/export terse' 2>/dev/null | tr -d '\r' > "$F"; echo "backup: $(wc -l < "$F") linhas em $F"
ADAPTA=0
if [ "$(S ':put [:len [/ip firewall nat find comment~"FORCE_"]]' | tail -1)" != "0" ]; then
  ADAPTA=1; echo "regras FORCE_* existentes: adaptando (failover antigo desligado, destino Cloud, sem exceção de destino, DoH na 443)"
  S '/tool netwatch set [find type=simple and up-script~"FORCE_"] disabled=yes comment="ANTIGO - substituido pelo dns-failover"'
  S ':foreach c in={"FORCE_DNS_UDP";"FORCE_DNS_TCP";"FORCE_DOT";"FORCE_DOH";"FORCE_QUIC"} do={ :local r [/ip firewall nat find comment=$c]; :if ([:len $r] = 1) do={ /ip firewall nat set $r to-addresses=10.250.100.1 !to-ports disabled=no comment=($c . " (dns-failover)") } else={ :put ("ATENCAO: " . $c . " encontrada " . [:len $r] . " vezes") } }'
  S '/ip firewall nat set [find comment~"FORCE_DNS_(UDP|TCP)"] !dst-address-list; /ip firewall nat set [find comment~"FORCE_DOH"] dst-port=443'
  S ':if ([:len [/ip firewall address-list find list=INTERNAL_DNS address=10.250.100.1]] = 0) do={ /ip firewall address-list add list=INTERNAL_DNS address=10.250.100.1 comment="Technitium Cloud" }'
  F5=$(S ':put [:len [/ip firewall nat find comment~"(dns-failover)"]]' | tail -1); [ "$F5" = "5" ] || { echo "ABORTADO: esperava 5 regras (dns-failover), achei $F5"; exit 1; }
fi

[ $ADAPTA = 1 ] || S ':foreach a in={"8.8.8.8";"8.8.4.4";"1.1.1.1";"1.0.0.1";"9.9.9.9";"149.112.112.112";"208.67.222.222";"208.67.220.220";"94.140.14.14";"94.140.15.15";"45.90.28.0/24"} do={ :if ([:len [/ip firewall address-list find list=PUBLIC_DNS address=$a]] = 0) do={ /ip firewall address-list add list=PUBLIC_DNS address=$a } }; :foreach a in={"10.250.100.1";"10.100.10.15"} do={ :if ([:len [/ip firewall address-list find list=INTERNAL_DNS address=$a]] = 0) do={ /ip firewall address-list add list=INTERNAL_DNS address=$a comment="Technitium" } }'
[ $ADAPTA = 1 ] || S "/ip firewall nat add chain=dstnat src-address=$NET protocol=udp dst-port=53 action=dst-nat to-addresses=10.250.100.1 comment=\"FORCE_DNS_UDP (dns-failover)\" place-before=0"
[ $ADAPTA = 1 ] || S "/ip firewall nat add chain=dstnat src-address=$NET protocol=tcp dst-port=53 action=dst-nat to-addresses=10.250.100.1 comment=\"FORCE_DNS_TCP (dns-failover)\""
[ $ADAPTA = 1 ] || S "/ip firewall nat add chain=dstnat src-address=$NET protocol=tcp dst-port=853 action=dst-nat to-addresses=10.250.100.1 comment=\"FORCE_DOT (dns-failover)\""
[ $ADAPTA = 1 ] || S "/ip firewall nat add chain=dstnat src-address=$NET protocol=tcp dst-port=443 dst-address-list=PUBLIC_DNS action=dst-nat to-addresses=10.250.100.1 comment=\"FORCE_DOH (dns-failover)\""
[ $ADAPTA = 1 ] || S "/ip firewall nat add chain=dstnat src-address=$NET protocol=udp dst-port=443 dst-address-list=PUBLIC_DNS action=dst-nat to-addresses=10.250.100.1 comment=\"FORCE_QUIC (dns-failover)\""
SCRIPT=':local c [/tool netwatch get [find comment=\"dns-cloud\"] status]; :local l [/tool netwatch get [find comment=\"dns-local\"] status]; :local p [/tool netwatch get [find comment=\"dns-publico\"] status]; :local alvo \"1.1.1.1\"; :local srv \"8.8.8.8,1.1.1.1\"; :if (\$c = \"up\") do={ :set alvo \"10.250.100.1\"; :set srv \"10.250.100.1,10.100.10.15\" } else={ :if (\$l = \"up\") do={ :set alvo \"10.100.10.15\"; :set srv \"10.250.100.1,10.100.10.15\" } else={ :if (\$p = \"up\") do={ :set alvo \"8.8.8.8\" } } }; :if ([:tostr [/ip dns get servers]] != [:tostr [:toarray \$srv]]) do={ /ip dns set servers=\$srv; /log warning (\"dns-failover: /ip dns servers=\" . \$srv) }; :local r [/ip firewall nat find comment~\"(dns-failover)\"]; :if ([:len \$r] = 0) do={ :return \"\" }; :local atual [/ip firewall nat get [:pick \$r 0] to-addresses]; :local off [/ip firewall nat get [:pick \$r 0] disabled]; :if (\$off or \$atual != \$alvo) do={ /ip firewall nat set \$r to-addresses=\$alvo disabled=no; /log warning (\"dns-failover: clientes no DNS \" . \$alvo) }'
S "/system script add name=dns-failover policy=read,write,test dont-require-permissions=yes comment=\"DNS: Technitium Cloud > Technitium local > 8.8.8.8 > 1.1.1.1\" source=\"$SCRIPT\""
for n in "dns-cloud 10.250.100.1" "dns-local 10.100.10.15" "dns-publico 8.8.8.8"; do set -- $n; S "/tool netwatch add type=dns host=google.com dns-server=$2 record-type=A interval=15s timeout=3s comment=$1 up-script=\"/system script run dns-failover\" down-script=\"/system script run dns-failover\""; done
S '/ip dns set servers="10.250.100.1,10.100.10.15" allow-remote-requests=no; :foreach n in=[/ip dhcp-server network find] do={ /ip dhcp-server network set $n dns-server="" }'
sleep 25; S '/system script run dns-failover'
S ':local s ""; :foreach r in=[/ip firewall nat find comment~"(dns-failover)"] do={ :set s ($s . [/ip firewall nat get $r to-addresses] . " ") }; :put ("regras: " . $s); :put ("netwatch: cloud=" . [/tool netwatch get [find comment=dns-cloud] status] . " local=" . [/tool netwatch get [find comment=dns-local] status] . " publico=" . [/tool netwatch get [find comment=dns-publico] status]); :put ("/ip dns=" . [:tostr [/ip dns get servers]] . " allow-remote=" . [/ip dns get allow-remote-requests]); :put ("script ok: " . ([:len [:find [/system script get [find name=dns-failover] source] "\$alvo"]] > 0)); :put ("roteador resolve: " . [:resolve google.com])'

# teste do failover (netwatch apontado para IPs inexistentes e de volta)
d() { S ':local s ""; :foreach r in=[/ip firewall nat find comment~"(dns-failover)"] do={ :set s ($s . [/ip firewall nat get $r to-addresses] . " ") }; :put ($s . "| /ip dns=" . [:tostr [/ip dns get servers]])'; }
nw() { S "/tool netwatch set [find comment=$1] dns-server=$2"; }
nw dns-cloud 10.250.100.254; sleep 25; echo "teste cloud fora:     $(d)"
nw dns-local 10.250.100.253; sleep 25; echo "teste os dois fora:   $(d)"
nw dns-local 10.100.10.15; nw dns-cloud 10.250.100.1; sleep 30; echo "teste de volta:       $(d)"
