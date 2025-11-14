#!/usr/bin/env bash

set -euo pipefail

GCP_PROJECT="${1:-}"
CONFIG_FILE="${2:-}"
ZONE="${3:-us-central1-a}"
INSTANCE="${4:-bastion}"
WG_CONFIG_PATH="/etc/wireguard/wg0.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_usage() {
    echo "Usage: $0 <gcp-project-id> <config-file-path> [zone] [instance-name]"
    echo ""
    echo "Arguments:"
    echo "  gcp-project-id    GCP project ID"
    echo "  config-file-path  Path to WireGuard config file"
    echo "  zone              (Optional) GCP zone (default: us-central1-a)"
    echo "  instance-name     (Optional) Instance name (default: bastion)"
    echo ""
    echo "Example:"
    echo "  $0 my-project-dev generated/mesh/bastion-dev.conf"
    echo "  $0 my-project-prod generated/mesh/bastion-prod.conf us-west1-a bastion-gw"
}

check_prerequisites() {
    if [ -z "$GCP_PROJECT" ] || [ -z "$CONFIG_FILE" ]; then
        log_error "Missing required arguments"
        echo ""
        show_usage
        exit 1
    fi

    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI not found. Please install Google Cloud SDK."
        exit 1
    fi

    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Config file not found: $CONFIG_FILE"
        exit 1
    fi

    log_info "Prerequisites check passed"
}

deploy_config() {
    log_info "Deploying to project: $GCP_PROJECT"
    log_info "Using config file: $CONFIG_FILE"
    echo ""

    log_info "Uploading new config..."
    gcloud compute scp \
        --zone "$ZONE" \
        --project "$GCP_PROJECT" \
        --tunnel-through-iap \
        "$CONFIG_FILE" \
        "${INSTANCE}:/tmp/wg0.conf"

    log_info "Installing config and restarting WireGuard..."
    gcloud compute ssh \
        --zone "$ZONE" \
        --project "$GCP_PROJECT" \
        --tunnel-through-iap \
        "$INSTANCE" \
        --command "sudo mv /tmp/wg0.conf $WG_CONFIG_PATH && \
                   sudo chmod 600 $WG_CONFIG_PATH && \
                   sudo systemctl restart wg-quick@wg0 && \
                   sudo systemctl status wg-quick@wg0 --no-pager"

    echo ""
    log_info "Deployment completed successfully!"
}

main() {
    check_prerequisites
    deploy_config
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main
fi
