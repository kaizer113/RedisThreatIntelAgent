#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SOURCE_ENV_FILE="${THREAT_INTEL_VM_ENV_FILE:-.env}"
if [[ ! -f "$SOURCE_ENV_FILE" ]]; then
  echo "$SOURCE_ENV_FILE is required."
  exit 1
fi

read_env() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$SOURCE_ENV_FILE"
}

PROJECT_ID="$(read_env GOOGLE_CLOUD_PROJECT)"
REGION="$(read_env THREAT_INTEL_DEPLOY_REGION)"
ZONE="$(read_env THREAT_INTEL_VM_ZONE)"
VM_NAME="$(read_env THREAT_INTEL_VM_NAME)"
PROJECT_ID="${PROJECT_ID:?Set GOOGLE_CLOUD_PROJECT}"
REGION="${REGION:-us-east4}"
ZONE="${ZONE:-us-east4-c}"
VM_NAME="${VM_NAME:-valuewholesale-demo}"
CONTAINER_NAME="redis-threat-intelligence-agent"
HOST_PORT=8082
CONTAINER_PORT=8082
REPOSITORY="redis-threat-intelligence"
IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY/$CONTAINER_NAME:latest"
OWNER_LABEL="$(read_env THREAT_INTEL_OWNER_LABEL)"
SKIP_DELETION_LABEL="$(read_env THREAT_INTEL_SKIP_DELETION_LABEL)"
OWNER_LABEL="${OWNER_LABEL:-lionel_giavelli}"
SKIP_DELETION_LABEL="${SKIP_DELETION_LABEL:-yes}"
LABELS="app=redis-threat-intelligence,environment=demo,owner=$OWNER_LABEL,skip_deletion=$SKIP_DELETION_LABEL"
FIREWALL_RULE="redis-threat-intelligence-allow-8082"
NETWORK_TAG="valuewholesale-web"

command -v gcloud >/dev/null 2>&1 || { echo "gcloud is required"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required"; exit 1; }

gcloud config set project "$PROJECT_ID" >/dev/null
gcloud compute instances describe "$VM_NAME" --zone "$ZONE" >/dev/null

if ! gcloud artifacts repositories describe "$REPOSITORY" --location "$REGION" >/dev/null 2>&1; then
  gcloud artifacts repositories create "$REPOSITORY" \
    --repository-format docker \
    --location "$REGION" \
    --labels "$LABELS"
fi

if ! gcloud compute firewall-rules describe "$FIREWALL_RULE" >/dev/null 2>&1; then
  NETWORK="$(gcloud compute instances describe "$VM_NAME" --zone "$ZONE" \
    --format='value(networkInterfaces[0].network.basename())')"
  gcloud compute firewall-rules create "$FIREWALL_RULE" \
    --network "$NETWORK" \
    --direction INGRESS \
    --action ALLOW \
    --rules "tcp:$HOST_PORT" \
    --source-ranges 0.0.0.0/0 \
    --target-tags "$NETWORK_TAG" \
    --description "Redis Threat Intelligence Agent on port 8082"
fi

gcloud builds submit --tag "$IMAGE" .

RUNTIME_ENV_FILE="$(mktemp /tmp/redis-threat-intelligence-env.XXXXXX)"
trap 'rm -f "$RUNTIME_ENV_FILE"' EXIT
chmod 600 "$RUNTIME_ENV_FILE"

while IFS= read -r line; do
  key="${line%%=*}"
  case "$key" in
    APP_NAME|PORT|LOG_LEVEL|GOOGLE_*|REDIS_KEY_PREFIX|EMBEDDING_*|SEMANTIC_*|CTX_MCP_URL|CTX_SURFACE_ID|MCP_AGENT_KEY|CONTEXT_*|LANGCACHE_*|AGENT_MEMORY_*|ANALYST_ID|AGENT_TIMEOUT_SECONDS)
      printf '%s\n' "$line" >> "$RUNTIME_ENV_FILE"
      ;;
  esac
done < "$SOURCE_ENV_FILE"

VM_REDIS_URL="$(read_env VM_REDIS_URL)"
if [[ -z "$VM_REDIS_URL" ]]; then
  echo "VM_REDIS_URL is required"
  exit 1
fi
printf 'REDIS_URL=%s\n' "$VM_REDIS_URL" >> "$RUNTIME_ENV_FILE"
printf 'PORT=%s\n' "$CONTAINER_PORT" >> "$RUNTIME_ENV_FILE"

gcloud compute scp "$RUNTIME_ENV_FILE" "$VM_NAME:~/$CONTAINER_NAME.env" \
  --zone "$ZONE" --quiet
gcloud compute ssh "$VM_NAME" --zone "$ZONE" --quiet --command "
  set -e
  sudo install -o root -g root -m 600 ~/$CONTAINER_NAME.env /etc/$CONTAINER_NAME.env
  rm -f ~/$CONTAINER_NAME.env
  token=\$(curl -fsS -H 'Metadata-Flavor: Google' \
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"access_token\"])')
  printf '%s' \"\$token\" | sudo docker login -u oauth2accesstoken --password-stdin \
    https://$REGION-docker.pkg.dev
  sudo docker pull '$IMAGE'
  sudo docker rm -f '$CONTAINER_NAME' >/dev/null 2>&1 || true
  sudo docker run -d \
    --name '$CONTAINER_NAME' \
    --restart unless-stopped \
    --env-file '/etc/$CONTAINER_NAME.env' \
    -e WEB_CONCURRENCY=2 \
    -p '$HOST_PORT:$CONTAINER_PORT' \
    '$IMAGE'
"

PUBLIC_IP="$(gcloud compute instances describe "$VM_NAME" --zone "$ZONE" \
  --format='value(networkInterfaces[0].accessConfigs[0].natIP)')"
PUBLIC_URL="http://$PUBLIC_IP:$HOST_PORT"

for _ in $(seq 1 30); do
  if curl -fsS "$PUBLIC_URL/api/health" >/dev/null 2>&1; then
    echo "$PUBLIC_URL"
    exit 0
  fi
  sleep 2
done

echo "Deployment did not become healthy. Existing containers were not modified except this app."
exit 1
