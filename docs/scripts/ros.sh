#!/bin/bash
# ros.sh HOST ARQUIVO|- : roda um script RouterOS (mesmo texto que se colaria no terminal) por ssh
H=$1; F=$2; K=~/.ssh/id_ed25519_mikrotik
if [ "$F" = "-" ]; then C=$(cat); elif [ -f "$F" ]; then C=$(grep -v "^#" "$F"); else C="$F"; fi
o=$(timeout ${3:-60} ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 claude@$H "$C" 2>&1)
if echo "$o" | grep -q "Host key verification failed"; then ssh-keygen -R $H >/dev/null 2>&1; o=$(timeout ${3:-60} ssh -i $K -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 claude@$H "$C" 2>&1); fi
echo "$o" | tr -d '\r' | grep -v "^$\|post-quantum\|store now\|upgraded\|Permanently added"
