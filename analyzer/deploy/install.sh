#!/usr/bin/env bash
# Instalação/atualização idempotente do 2D DNS Analyzer (Debian 13). Rodar como root
# a partir da pasta analyzer/ copiada para a VM:  sudo bash deploy/install.sh
set -euo pipefail

APP_DIR=/opt/2d-dnsanalyzer
ENV_FILE=/etc/2d-dnsanalyzer/analyzer.env
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo ">> pacotes"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq postgresql python3-venv python3-pip rsync curl >/dev/null

echo ">> usuário e diretórios"
id dnsanalyzer >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin dnsanalyzer
install -d -o root -g root -m 755 "$APP_DIR"
install -d -o dnsanalyzer -g dnsanalyzer -m 750 /var/log/2d-dnsanalyzer /var/lib/2d-dnsanalyzer
install -d -o root -g dnsanalyzer -m 750 /etc/2d-dnsanalyzer

echo ">> código"
rsync -a --delete --exclude '__pycache__' --exclude '.pytest_cache' --exclude '.env' \
  "$SRC_DIR"/ "$APP_DIR/app/"
chown -R root:root "$APP_DIR/app"

echo ">> venv"
[ -x "$APP_DIR/venv/bin/python" ] || python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/app/requirements.txt"

if [ ! -f "$ENV_FILE" ]; then
  echo ">> primeira instalação: banco e $ENV_FILE"
  PGPASS="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
  APITOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
  sudo -u postgres psql -qtc "SELECT 1 FROM pg_roles WHERE rolname='dnsanalyzer'" | grep -q 1 \
    || sudo -u postgres psql -qc "CREATE ROLE dnsanalyzer LOGIN PASSWORD '$PGPASS'"
  sudo -u postgres psql -qc "ALTER ROLE dnsanalyzer PASSWORD '$PGPASS'"
  sudo -u postgres psql -qtc "SELECT 1 FROM pg_database WHERE datname='dnsanalyzer'" | grep -q 1 \
    || sudo -u postgres createdb -O dnsanalyzer dnsanalyzer
  sed -e "s#TROQUE_A_SENHA#$PGPASS#" -e "s#^API_TOKEN=.*#API_TOKEN=$APITOKEN#" \
    "$APP_DIR/app/.env.example" > "$ENV_FILE"
  echo "   !! preencha TECHNITIUM_TOKEN em $ENV_FILE"
fi
chown root:dnsanalyzer "$ENV_FILE"
chmod 640 "$ENV_FILE"

echo ">> wrapper de operação: /usr/local/bin/dnsanalyzer"
cat > /usr/local/bin/dnsanalyzer <<EOF
#!/bin/sh
# Executa comandos do analisador como o usuário do serviço, lendo $ENV_FILE.
cd $APP_DIR/app && exec sudo -u dnsanalyzer env DNSANALYZER_ENV=$ENV_FILE \\
  TLDEXTRACT_CACHE=/var/lib/2d-dnsanalyzer/tldextract $APP_DIR/venv/bin/python -m dnsanalyzer "\$@"
EOF
chmod 755 /usr/local/bin/dnsanalyzer

echo ">> migrações"
/usr/local/bin/dnsanalyzer migrate

echo ">> systemd"
install -m 644 "$APP_DIR/app/deploy/systemd/"dnsanalyzer-*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable dnsanalyzer-api dnsanalyzer-collector dnsanalyzer-classifier >/dev/null
if [ "$(sudo -u postgres psql -d dnsanalyzer -Atc 'SELECT count(*) FROM tenants')" = "0" ]; then
  # sem tenants a coleta auto-criaria "Rede 10.x" para tudo: importe antes de ligar
  echo "   !! nenhum tenant cadastrado: rode 'dnsanalyzer import-tenants deploy/tenants.2d.json'"
  echo "      e depois: systemctl start dnsanalyzer-collector dnsanalyzer-classifier"
  systemctl restart dnsanalyzer-api
else
  systemctl restart dnsanalyzer-api dnsanalyzer-collector dnsanalyzer-classifier
fi
systemctl --no-pager --lines=0 status dnsanalyzer-api dnsanalyzer-collector dnsanalyzer-classifier || true
echo ">> ok"
