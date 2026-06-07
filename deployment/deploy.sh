#!/usr/bin/env bash
# ============================================================
# ThreatLens AI — Production Deployment Script
# Author: Muhammad Usman
# Usage: ./deployment/deploy.sh [--reset-db]
# ============================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
success() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── Variables ─────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESET_DB=false

# ── Parse args ────────────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --reset-db) RESET_DB=true;;
    --help)
      echo "Usage: $0 [--reset-db]"
      echo "  --reset-db    Drop and recreate all database volumes (DATA LOSS!)"
      exit 0;;
  esac
done

# ── Pre-flight checks ─────────────────────────────────────
info "ThreatLens AI Production Deployment"
echo "======================================"

cd "$PROJECT_DIR"

command -v docker >/dev/null 2>&1 || error "Docker is not installed"
command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 || error "Docker Compose v2 is not installed"

[[ -f ".env" ]] || error ".env file not found. Run: cp .env.example .env and configure it."

# ── Validate .env ─────────────────────────────────────────
info "Validating environment configuration..."

SECRET_KEY=$(grep "^SECRET_KEY=" .env | cut -d= -f2 | tr -d '"' | tr -d "'")
if [[ ${#SECRET_KEY} -lt 32 ]]; then
  error "SECRET_KEY must be at least 32 characters. Please update .env"
fi

POSTGRES_PASS=$(grep "^POSTGRES_PASSWORD=" .env | cut -d= -f2 | tr -d '"')
if [[ "$POSTGRES_PASS" == "threatlens_secure_pass_change_me" ]]; then
  error "Default POSTGRES_PASSWORD detected. Please change it in .env before deploying."
fi

success "Environment configuration validated"

# ── Reset DB if requested ─────────────────────────────────
if [[ "$RESET_DB" == "true" ]]; then
  warn "Resetting database — ALL DATA WILL BE LOST!"
  read -p "Are you sure? Type 'yes' to confirm: " CONFIRM
  [[ "$CONFIRM" == "yes" ]] || { info "Cancelled."; exit 0; }
  docker compose down -v
  success "Database volumes removed"
fi

# ── Pull latest images ────────────────────────────────────
info "Building Docker images..."
docker compose build --no-cache
success "Images built"

# ── Start services ────────────────────────────────────────
info "Starting services..."
docker compose up -d
success "Services started"

# ── Wait for health ───────────────────────────────────────
info "Waiting for services to be healthy..."
MAX_WAIT=120
ELAPSED=0
INTERVAL=5

while [[ $ELAPSED -lt $MAX_WAIT ]]; do
  if curl -sf "http://localhost/health" >/dev/null 2>&1; then
    success "ThreatLens AI is healthy!"
    break
  fi
  echo -n "."
  sleep $INTERVAL
  ELAPSED=$((ELAPSED + INTERVAL))
done

if [[ $ELAPSED -ge $MAX_WAIT ]]; then
  error "Services did not become healthy within ${MAX_WAIT}s. Check: docker compose logs"
fi

# ── Print summary ─────────────────────────────────────────
echo ""
echo "======================================"
success "Deployment complete!"
echo ""
echo -e "  🌐 Dashboard:     ${GREEN}http://localhost${NC}"
echo -e "  📡 API Docs:      ${GREEN}http://localhost/api/docs${NC}"
echo -e "  📊 Health Check:  ${GREEN}http://localhost/health${NC}"
echo ""
echo -e "  Logs:   ${BLUE}docker compose logs -f${NC}"
echo -e "  Stop:   ${BLUE}docker compose down${NC}"
echo "======================================"
