# ThreatLens AI — Developer Makefile
# Usage: make <target>

.PHONY: help up down build restart logs test lint clean shell-backend shell-db

# Default target
help:
	@echo ""
	@echo "ThreatLens AI — Available Commands"
	@echo "======================================"
	@echo "  make up           Start all services (detached)"
	@echo "  make up-build     Rebuild images and start all services"
	@echo "  make down         Stop all services"
	@echo "  make down-v       Stop all services and remove volumes (data reset)"
	@echo "  make restart      Restart all services"
	@echo "  make logs         Tail all service logs"
	@echo "  make logs-api     Tail backend logs only"
	@echo "  make build        Build Docker images without starting"
	@echo "  make test         Run full test suite"
	@echo "  make test-unit    Run unit tests only"
	@echo "  make test-api     Run API tests only"
	@echo "  make test-int     Run integration tests only"
	@echo "  make lint         Run linters (flake8, black check)"
	@echo "  make migrate      Run database migrations"
	@echo "  make shell-back   Open bash shell in backend container"
	@echo "  make shell-db     Open psql in database container"
	@echo "  make clean        Remove build artifacts and caches"
	@echo "  make backup-db    Backup PostgreSQL database"
	@echo "  make setup        Copy .env.example to .env (first-time setup)"
	@echo ""

# ── Setup ─────────────────────────────────────────────────────────────────
setup:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✅ .env created from .env.example — please edit before running."; \
	else \
		echo "⚠️  .env already exists, skipping."; \
	fi

# ── Docker Compose ─────────────────────────────────────────────────────────
up:
	docker compose up -d

up-build:
	docker compose up -d --build

down:
	docker compose down

down-v:
	docker compose down -v

restart:
	docker compose restart

build:
	docker compose build

# ── Logs ──────────────────────────────────────────────────────────────────
logs:
	docker compose logs -f

logs-api:
	docker compose logs -f backend

logs-front:
	docker compose logs -f frontend

logs-db:
	docker compose logs -f postgres

# ── Tests ─────────────────────────────────────────────────────────────────
test:
	@echo "🧪 Running full test suite..."
	docker compose exec backend pytest /app/../tests/ -v \
		--cov=app --cov-report=term-missing --cov-fail-under=80

test-local:
	@echo "🧪 Running tests locally..."
	cd backend && pytest ../tests/ -v --cov=app --cov-report=term-missing

test-unit:
	cd backend && pytest ../tests/unit/ -v

test-api:
	cd backend && pytest ../tests/api/ -v

test-int:
	cd backend && pytest ../tests/integration/ -v

test-cov:
	cd backend && pytest ../tests/ --cov=app --cov-report=html
	@echo "Coverage report: backend/htmlcov/index.html"

# ── Linting ───────────────────────────────────────────────────────────────
lint:
	@echo "🔍 Running linters..."
	docker compose exec backend flake8 app/ --max-line-length=120 --extend-ignore=E501,W503

lint-local:
	cd backend && python -m flake8 app/ --max-line-length=120 --extend-ignore=E501,W503

format:
	cd backend && python -m black app/ tests/
	cd backend && python -m isort app/ tests/

# ── Database ──────────────────────────────────────────────────────────────
migrate:
	docker compose exec backend alembic upgrade head

migrate-local:
	cd backend && alembic upgrade head

shell-db:
	docker compose exec postgres psql -U threatlens threatlens_db

backup-db:
	@mkdir -p backups
	docker compose exec postgres pg_dump -U threatlens threatlens_db \
		> backups/backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "✅ Database backed up to backups/"

restore-db:
	@echo "Usage: cat backup.sql | make restore-db-pipe"

# ── Shells ────────────────────────────────────────────────────────────────
shell-back:
	docker compose exec backend bash

shell-front:
	docker compose exec frontend sh

# ── Cleanup ───────────────────────────────────────────────────────────────
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleaned build artifacts"

clean-all: clean
	docker compose down -v --remove-orphans
	docker system prune -f
	@echo "✅ Full cleanup complete"

# ── Health Check ──────────────────────────────────────────────────────────
health:
	@curl -sf http://localhost/health && echo "\n✅ ThreatLens AI is healthy" || echo "\n❌ Service not responding"

# ── Demo ──────────────────────────────────────────────────────────────────
demo-register:
	@curl -s -X POST http://localhost/api/v1/auth/register \
		-H "Content-Type: application/json" \
		-d '{"username":"demo_analyst","email":"demo@soc.com","password":"DemoPass1","full_name":"Demo Analyst"}' \
		| python3 -m json.tool

demo-login:
	@curl -s -X POST http://localhost/api/v1/auth/login \
		-H "Content-Type: application/json" \
		-d '{"username":"demo_analyst","password":"DemoPass1"}' \
		| python3 -m json.tool
