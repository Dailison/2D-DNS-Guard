#!/bin/bash
# Fase 0 (só leitura) de um site do túnel antigo: levanta.sh N "trecho do nome do peer no escritório"
N=$1; PEER=$2
K=~/.ssh/id_ed25519_mikrotik; V=~/.ssh/id_ed25519_vps
O() { timeout 30 ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes claude@10.100.30.1 "$1" 2>/dev/null | tr -d '\r'; }
T() { timeout 30 ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 claude@10.100.100.$N "$1" 2>&1 | tr -d '\r' | grep -v "WARNING\|session may\|upgraded\|pq.html\|^$"; }
echo "############ site $N ($PEER)"
O ":foreach p in=[/interface wireguard peers find where interface=wireguard_2D and name~\"$PEER\"] do={:put ([/interface wireguard peers get \$p name] . \" | \" . [:tostr [/interface wireguard peers get \$p allowed-address]] . \" | IP=\" . [/interface wireguard peers get \$p current-endpoint-address] . \" | hs=\" . [:tostr [/interface wireguard peers get \$p last-handshake]])}"
O "/ip route print without-paging terse where gateway=10.100.100.$N" | grep -oE "comment=[^=]*dst-address=[^ ]+" | sed 's/ dst-address/| dst-address/; s/^/escritório: /'
IP=$(O ":put [/interface wireguard peers get [find where interface=wireguard_2D and allowed-address~\"10.100.100.$N/32\"] current-endpoint-address]" | tr -d ' ')
R=$(echo $IP | awk -F. '{print $4"."$3"."$2"."$1}')
ssh -i $V -o BatchMode=yes root@187.41.115.189 "A=\$(dig +short TXT $R.origin.asn.cymru.com | head -1 | tr -d '\"' | cut -d' ' -f1); echo \"IP $IP -> \$(dig +short TXT AS\$A.asn.cymru.com | tr -d '\"' | cut -d'|' -f1,5) | \$(nft get element inet filtro wg_v4 '{ $IP }' >/dev/null 2>&1 && echo liberado || echo NAO-LIBERADO)\""
case "$IP" in 10.*|172.1[6-9].*|172.2*|172.3[01].*|192.168.*|100.6[4-9].*|100.[7-9]*|100.1[01]*|100.12[0-7].*) echo "ALERTA: o escritório vê este peer com IP PRIVADO ($IP) — ver se o site tem internet real";; esac
T ':put ([/system identity get name] . " | " . [/system resource get board-name] . " | RouterOS " . [/system resource get version] . " | grupo: " . [/user get [find name=claude] group] . " | scheduler: " . [/system device-mode get scheduler])'
echo "wg: $(T '/interface wireguard peers print without-paging terse' | grep -oE 'interface=[^ ]+|name=[^ ]+|allowed-address=[^ ]+' | paste -sd' ' | sed 's/ interface=/\n    interface=/g')"
echo "endereços: $(T '/ip address print without-paging terse' | grep -oE ' address=[^ ]+ | interface=[^ ]+' | paste - - | tr -s ' \t' ' ' | paste -sd';')"
echo "rotas: $(T '/ip route print without-paging terse where static' | grep -oE '^ *[0-9]+ +[A-Za-z]+|comment=[^=]*dst-address=[^ ]+|dst-address=[^ ]+|gateway=[^ ]+|distance=[0-9]+' | paste -sd' ' | sed -E 's/ ([0-9]+ +[A-Z])/\n    \1/g')"
echo "nat: $(T '/ip firewall nat print without-paging terse' | grep -oE '^ *[0-9]+ +X?|comment=[^=]+chain|action=[^ ]+|out-interface=[^ ]+|to-addresses=[^ ]+|dst-address=[^ ]+' | paste -sd' ' | sed -E 's/ ([0-9]+ +X? )/\n    \1/g')"
echo "filtro: $(T ':put [:len [/ip firewall filter find]]' | tail -1) regras | listas de interface: $(T '/interface list member print without-paging terse' | grep -oE 'list=[^ ]+|interface=[^ ]+' | paste - - | paste -sd' ')"
echo "dns: $(T ':put ("servers=" . [:tostr [/ip dns get servers]] . " allow-remote=" . [/ip dns get allow-remote-requests])' | tail -1) | static: $(T '/ip dns static print without-paging terse' | grep -oE 'name=[^ ]+' | paste -sd' ')"
echo "dhcp: $(T '/ip dhcp-server network print without-paging terse' | grep -oE 'address=[^ ]+|dns-server=[^ ]*|domain=[^ ]+' | paste -sd' ')"
echo "INTERNAL_DNS: $(T '/ip firewall address-list print without-paging terse where list=INTERNAL_DNS' | grep -oE 'address=[^ ]+' | paste -sd' ')"
echo "netwatch: $(T '/tool netwatch print without-paging terse' | cut -c1-150)"
echo "links: $(T '/interface pppoe-client print without-paging terse' | grep -oE 'name=[^ ]+' | paste -sd' ') | leases: $(T '/ip dhcp-server lease print without-paging terse where status=bound' | grep -c 'address=') | internet do roteador: $(T '/ping 8.8.8.8 count=2' | grep -oE 'received=[0-9]+')"
# banco do analisador no k3s desde 04/11 (docs/MIGRACAO-ANALISADOR-K3S.md)
ssh -i ~/.ssh/id_ed25519_k3s -o BatchMode=yes root@10.100.50.202 "kubectl -n dns-guard exec analyzer-db-0 -- psql -U dnsanalyzer -d dnsanalyzer -At -F' | ' -c \"SELECT 'DNS Guard: ' || t.id || ' ' || t.name || ' ' || n.cidr || ' ' || coalesce(n.unit,'') FROM tenant_networks n JOIN tenants t ON t.id = n.tenant_id WHERE n.cidr::cidr && '10.$N.0.0/16'::cidr\""
