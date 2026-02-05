#!/usr/bin/env bash
set -euo pipefail

# CpAgent Barbican environment setup - GOLD MASTER
GREEN="\033[0;32m"; RED="\033[0;31m"; NC="\033[0m"; YELLOW="\033[1;33m"
log() { echo -e "${GREEN}[ok]${NC} $1"; }
err() { echo -e "${RED}[err]${NC} $1"; }
warn() { echo -e "${YELLOW}[..]${NC} $1"; }

REAL_USER=${SUDO_USER:-$USER}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CPAGENT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Absolute Paths
VENV_DIR="$CPAGENT_ROOT/barbican-env"
CONFIG_DST_DIR="/etc/barbican"
DATA_DIR="/var/lib/barbican"
SQLITE_DB="$DATA_DIR/barbican.sqlite"
VTPM_PLUGIN_PATH="/home/adminuser/work/INCUBATIONS/poc/barbican-vtpm-crypto"
MASTER_HANDLE="0x81010002"

log "Executing full deployment sequence..."

# 1. System Dependencies
sudo apt update -qq
sudo apt install -y python3 python3-venv python3-dev build-essential \
    libssl-dev libffi-dev pkg-config libtss2-dev tpm2-tools sqlite3 \
    rabbitmq-server > /dev/null

# 2. Filesystem Preparation
sudo mkdir -p "$CONFIG_DST_DIR" "$DATA_DIR" /var/log/barbican
sudo chown -R "$REAL_USER":"$REAL_USER" "$CONFIG_DST_DIR" "$DATA_DIR" /var/log/barbican

# --- TPM Hardware & Handle Provisioning ---
log "Step: Provisioning TPM Master Key..."

# קביעת ה-Device הנכון (מעדיף tpmrm0 - Resource Manager)
if [ -e /dev/tpmrm0 ]; then
    TPM_DEV="/dev/tpmrm0"
elif [ -e /dev/tpm0 ]; then
    TPM_DEV="/dev/tpm0"
else
    err "No TPM device found! Check if vTPM is enabled."
    exit 1
fi

# הגדרת TCTI כדי שכל הפקודות הבאות ידעו לאן לפנות
export TPM2TOOLS_TCTI="device:$TPM_DEV"
export TPM2_TCTI="device:$TPM_DEV"

# הרשאות גישה
sudo chmod 666 "$TPM_DEV"
log "Using TPM device: $TPM_DEV with full permissions."

# בדיקה אם ה-Handle כבר קיים, אם לא - יוצר אותו
if tpm2_readpublic -c "$MASTER_HANDLE" > /dev/null 2>&1; then
    log "Master Key already exists at $MASTER_HANDLE"
else
    warn "Master Key not found. Creating persistent handle $MASTER_HANDLE..."
    tpm2_createprimary -C o -c primary.ctx -G ecc256
    tpm2_create -C primary.ctx -G ecc256:ecdh -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt" -u key.pub -r key.priv
    tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
    tpm2_evictcontrol -C o -c key.ctx "$MASTER_HANDLE"
    rm -f primary.ctx key.pub key.priv key.ctx
    log "Master Key successfully created."
fi
# ------------------------------------------

# 3. Virtualenv & Python Packages
if [ -d "$VENV_DIR" ]; then rm -rf "$VENV_DIR"; fi
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"
pip install -U pip setuptools wheel > /dev/null
pip install barbican gunicorn oslo.messaging oslo.middleware oslo.policy \
    keystonemiddleware PasteDeploy repoze.profile > /dev/null

# 4. vTPM Plugin Integration
if [ -d "$VTPM_PLUGIN_PATH" ]; then
    log "Integrating vTPM plugin from local source..."
    pip install -e "$VTPM_PLUGIN_PATH" > /dev/null
fi

# 5. Generate barbican.conf
cat > "$CONFIG_DST_DIR/barbican.conf" <<CONF
[DEFAULT]
transport_url = rabbit://guest:guest@127.0.0.1:5672/
host_href = http://127.0.0.1:9311
debug = True
log_file = /var/log/barbican/barbican.log

[database]
connection = sqlite:////$SQLITE_DB

[crypto]
enabled_crypto_plugins = vtpm

[crypto:vtpm]
plugin_class = barbican_vtpm_crypto.plugin.VtpmCryptoPlugin

[vtpm_plugin]
master_key_handle = $MASTER_HANDLE
timeout = 30
CONF

# 6. Generate barbican-api-paste.ini (As before)
cat > "$CONFIG_DST_DIR/barbican-api-paste.ini" <<PASTE
[composite:main]
use = egg:Paste#urlmap
/: barbican_version
/healthcheck: healthcheck
/v1: barbican_api

[pipeline:barbican_api]
pipeline = cors request_id http_proxy_to_wsgi unauthenticated-context microversion apiapp

[app:apiapp]
paste.app_factory = barbican.api.app:create_main_app

[filter:unauthenticated-context]
paste.filter_factory = barbican.api.middleware.context:UnauthenticatedContextMiddleware.factory

[filter:microversion]
paste.filter_factory = barbican.api.middleware.microversion:MicroversionMiddleware.factory

[filter:cors]
paste.filter_factory = oslo_middleware.cors:filter_factory
oslo_config_project = barbican

[filter:request_id]
paste.filter_factory = oslo_middleware.request_id:RequestId.factory

[filter:http_proxy_to_wsgi]
paste.filter_factory = oslo_middleware:HTTPProxyToWSGI.factory

[app:healthcheck]
paste.app_factory = oslo_middleware:Healthcheck.app_factory
backends = disable_by_file
disable_by_file_path = /etc/barbican/healthcheck_disable

[pipeline:barbican_version]
pipeline = cors request_id http_proxy_to_wsgi microversion versionapp

[app:versionapp]
paste.app_factory = barbican.api.app:create_version_app
PASTE

# 7. Additional Support Files
touch "$CONFIG_DST_DIR/api_audit_map.conf"
touch "$CONFIG_DST_DIR/healthcheck_disable"
echo '{}' > "$CONFIG_DST_DIR/policy.json"

# 8. Database Migrations
log "Initializing database..."
export BARBICAN_SETTINGS="$CONFIG_DST_DIR/barbican.conf"
"$VENV_DIR/bin/barbican-manage" --config-file "$CONFIG_DST_DIR/barbican.conf" --log-file /dev/null db upgrade

# 9. Final Validation & Execution
if sqlite3 "$SQLITE_DB" ".tables" | grep -q "secrets"; then
    log "SUCCESS: Barbican environment is ready."
    log "Starting Barbican with TCTI export..."
    
    # הבטחה שהמשתנים האלו עוברים ל-Gunicorn
    export TPM2TOOLS_TCTI="device:$TPM_DEV"
    export TPM2_TCTI="device:$TPM_DEV"
    
    # הרצה
    gunicorn -b 127.0.0.1:9311 barbican.api.app:create_main_app
else
    err "Database table validation failed."
    exit 1
fi