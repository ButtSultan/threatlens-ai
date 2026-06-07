# ThreatLens AI — Technical Architecture

## Overview

ThreatLens AI is a **layered, service-oriented web application** built around a FastAPI backend, React frontend, and PostgreSQL database. All components run as Docker containers orchestrated by Docker Compose, with Nginx as the edge proxy.

---

## System Architecture

```
Internet / Browser
        │
        ▼
┌───────────────────────────────────────────────────────┐
│                    NGINX (Port 80/443)                │
│          Reverse Proxy · Rate Limiting · SSL          │
└────────────────┬──────────────────┬───────────────────┘
                 │                  │
       ┌─────────▼──────┐  ┌────────▼───────────┐
       │ React Frontend  │  │  FastAPI Backend    │
       │  Port 3000      │  │  Port 8000          │
       │  (nginx SPA)    │  │  (uvicorn async)    │
       └─────────────────┘  └────────┬────────────┘
                                     │
             ┌───────────────────────┼──────────────────┐
             │                       │                  │
    ┌────────▼────────┐   ┌──────────▼──────┐  ┌───────▼──────┐
    │   PostgreSQL 16  │   │    Redis 7       │  │ File System  │
    │   Port 5432      │   │    Port 6379     │  │  /uploads    │
    │   Primary store  │   │    Rate limits   │  │  /reports    │
    └──────────────────┘   └─────────────────┘  └──────────────┘
```

---

## Backend Architecture

The backend follows **Clean Architecture** principles with clear separation between layers.

```
backend/app/
│
├── main.py                     # FastAPI application factory
│                                 Middleware: CORS, GZip, Security headers
│                                 Rate limiting via slowapi
│
├── api/v1/                     # Presentation Layer (HTTP)
│   ├── router.py               # Aggregates all route modules
│   └── endpoints/
│       ├── auth.py             # JWT auth: login, register, refresh
│       ├── logs.py             # Log ingestion: file upload + API
│       ├── alerts.py           # Alert CRUD + status management
│       ├── incidents.py        # Incident lifecycle management
│       ├── dashboard.py        # Aggregated analytics queries
│       ├── reports.py          # PDF generation + download
│       ├── search.py           # Cross-entity full-text search
│       └── users.py            # User management (admin only)
│
├── core/                       # Application Core
│   ├── config.py               # Settings via pydantic-settings + .env
│   ├── security.py             # JWT creation/validation, bcrypt hashing
│   ├── dependencies.py         # FastAPI Depends: get_current_user, etc.
│   └── logging.py              # Structured JSON logging via python-json-logger
│
├── db/                         # Data Access Layer
│   ├── base.py                 # SQLAlchemy DeclarativeBase
│   └── session.py              # Async engine + session factory
│
├── models/                     # Domain Models (SQLAlchemy ORM)
│   └── models.py               # 7 entities + enums + portable UUIDType
│
├── schemas/                    # Data Transfer Objects (Pydantic v2)
│   └── schemas.py              # Request/Response validation schemas
│
├── services/                   # Business Logic Layer
│   ├── detection_engine.py     # 7 threat detection algorithms
│   ├── ai_analysis.py          # Threat summarization + recommendations
│   ├── log_parser.py           # JSON/CSV/TXT parser + field normalizer
│   └── report_service.py       # fpdf2-based PDF generation
│
└── utils/
    ├── helpers.py              # Pure utility functions
    └── seed.py                 # DB seeder for admin user + demo data
```

---

## Database Schema

### Entity Relationship Diagram

```
users (1) ──────────────────── (*) log_entries
  id (UUID PK)                       id (UUID PK)
  username (UNIQUE)                  source_file
  email (UNIQUE)                     log_type (enum)
  hashed_password                    raw_data (TEXT)
  role (admin|analyst|viewer)        parsed_data (JSON)
  is_active                          source_ip
  created_at                         username
                                     batch_id
                                     uploaded_by → users.id

log_entries (1) ──────────── (*) threat_detections
                                   id (UUID PK)
                                   detection_type
                                   severity (enum)
                                   confidence_score (0.0-1.0)
                                   source_ips (JSON[])
                                   affected_users (JSON[])
                                   event_count

threat_detections (1) ───────── (1) alerts
                                    id (UUID PK)
                                    title
                                    severity (enum)
                                    status (open→in_progress→resolved→closed)
                                    ai_summary (TEXT)
                                    ai_recommendations (JSON[])

threat_detections (1) ───────── (*) mitre_mappings
                                    technique_id (T1110, etc.)
                                    technique_name
                                    tactic
                                    url

alerts (1) ──────────────────── (1) incidents
                                     incident_number (INC-YYYYMMDD-XXXXXX)
                                     status (new→investigating→contained→...)
                                     root_cause
                                     lessons_learned

incidents (1) ───────────────── (*) reports
                                     report_type (incident|executive|summary)
                                     file_path

users (1) ───────────────────── (*) audit_logs
                                     action
                                     ip_address
                                     success
```

---

## Threat Detection Engine

The detection engine (`services/detection_engine.py`) implements **6 detection algorithms** that run on every log batch ingestion:

| Detector | Algorithm | MITRE Technique |
|----------|-----------|-----------------|
| **Brute Force** | Count failed logins per source IP in window. Threshold: ≥5 failures | T1110 |
| **Password Spray** | Count failed logins per user from ≥3 distinct IPs | T1110.003 |
| **Impossible Travel** | Count distinct /16 subnet blocks per user; flag if ≥3 | T1078 |
| **Privilege Escalation** | Keyword scan: sudo, runas, net localgroup, getsystem, bypassuac | T1068 |
| **Suspicious PowerShell** | PowerShell present + encoded/download/bypass/mimikatz keywords | T1059.001 |
| **Credential Dumping** | Keywords: mimikatz, lsass, ntds.dit, procdump, secretsdump | T1003 |
| **Reconnaissance** | Count distinct destination ports per IP; flag if ≥10 ports | T1046 |

### Detection Pipeline

```
Log Batch (JSON/CSV/TXT)
        │
        ▼
LogParserService.parse()
  - Normalizes vendor-specific field names
  - Extracts: source_ip, username, hostname, event_type
        │
        ▼
ThreatDetectionEngine.analyze()
  - Groups logs by source_ip and username
  - Runs all 6 detectors in parallel (same thread)
  - Returns List[DetectionResult]
        │
        ▼
AIAnalysisService.analyze_detection()
  - Generates threat_summary string
  - Looks up attack_explanation from knowledge base
  - Returns prioritized recommended_actions[]
        │
        ▼
Database persistence:
  ThreatDetection record
  MITREMapping records (one per technique)
  Alert record (auto-created, status=OPEN)
```

---

## Authentication & Authorization

### JWT Flow

```
POST /auth/login
  │ username + password
  ▼
verify_password (bcrypt)
  │
  ▼ success
create_access_token (HS256, 30min)
create_refresh_token (HS256, 7 days)
  │
  ▼
Client stores tokens in localStorage

Subsequent requests:
Authorization: Bearer <access_token>
  │
  ▼
HTTPBearer → decode_token → get_current_user(db)
  │
  ▼
User object injected into endpoint
```

### Role-Based Access Control

| Role | Register | Read | Create Alerts | Manage Incidents | Admin Panel |
|------|----------|------|---------------|-----------------|-------------|
| `admin` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `analyst` | ✅ | ✅ | ✅ | ✅ | ❌ |
| `viewer` | ✅ | ✅ | ❌ | ❌ | ❌ |

---

## Frontend Architecture

```
frontend/src/
│
├── App.js                  # BrowserRouter + route definitions
│                             PrivateRoute: requires isAuthenticated
│                             PublicRoute: redirects if authenticated
│
├── store/
│   └── authStore.js        # Zustand store (persisted to localStorage)
│                             login(), logout(), fetchMe()
│
├── utils/
│   └── api.js              # Axios instance with:
│                             - Auto-attach Bearer token
│                             - 401 → auto-refresh token → retry
│                             - Fallback: clear storage + redirect /login
│
├── components/
│   ├── common/
│   │   ├── AppLayout.js    # Sidebar + topbar shell (Outlet)
│   │   ├── Modal.js        # Reusable dialog with backdrop
│   │   ├── Pagination.js   # Page navigation with totals
│   │   ├── SeverityBadge.js # Color-coded severity + status chips
│   │   ├── Loaders.js      # Spinner, PageLoader, SkeletonRow
│   │   └── EmptyState.js   # Zero-state placeholder
│   └── dashboard/
│       ├── StatCard.js     # Metric card with icon + trend
│       └── Charts.js       # SeverityDonut, DetectionTrend, MITREBar
│
└── pages/
    ├── LoginPage.js        # Auth form with branding
    ├── RegisterPage.js     # New account form
    ├── DashboardPage.js    # Live stats + charts + recent alerts
    ├── AlertsPage.js       # Table + detail modal + quick-actions
    ├── LogsPage.js         # Drag-drop upload + results banner
    ├── IncidentsPage.js    # Lifecycle management + create/edit modals
    ├── ReportsPage.js      # PDF generation + download
    ├── SearchPage.js       # Unified logs + alerts search
    └── UsersPage.js        # Admin user management table
```

---

## API Design Principles

- **RESTful** resource naming: `/alerts/{id}`, `/incidents/{id}`
- **Pydantic v2** for all request/response validation
- **Async SQLAlchemy 2.0** with `selectinload` for related data
- **Pagination** on all list endpoints: `page`, `page_size`, `total`, `pages`
- **Structured errors**: `{"detail": "Human-readable message"}`
- **Rate limiting**: `slowapi` with per-IP limits (30 req/s general, 10 req/min auth)
- **Security headers** on every response via middleware

---

## Security Architecture

| Layer | Mechanism |
|-------|-----------|
| **Transport** | HTTPS via Nginx (TLS 1.2/1.3) |
| **Authentication** | JWT HS256, short-lived access tokens (30min) |
| **Password storage** | bcrypt with random salt (via passlib) |
| **SQL injection** | SQLAlchemy ORM — no raw SQL |
| **Rate limiting** | slowapi per-IP limits on all endpoints |
| **CORS** | Configured to specific allowed origins |
| **Input validation** | Pydantic v2 on all endpoints |
| **Audit trail** | Every login, upload, status change logged to `audit_logs` |
| **Security headers** | X-Frame-Options, X-Content-Type-Options, XSS-Protection |
| **File upload** | Extension whitelist, 50MB limit, UTF-8 decode with error handling |

---

## Deployment Architecture

```
Production deployment with docker compose up --build:

1. postgres (PostgreSQL 16)
   - Volume: postgres_data
   - Health: pg_isready

2. redis (Redis 7)
   - Volume: redis_data
   - Health: redis-cli ping

3. backend (FastAPI)
   depends_on: postgres (healthy), redis (healthy)
   - Runs: alembic upgrade head → seed.py → uvicorn
   - Health: GET /health → {"status":"healthy"}

4. frontend (React/nginx)
   depends_on: backend
   - Static files served by nginx
   - React Router handled by try_files / index.html fallback

5. nginx (reverse proxy)
   depends_on: backend, frontend
   - Port 80 exposed to host
   - Routes /api/* → backend:8000
   - Routes /* → frontend:3000
   - Rate limiting zones configured
```

---

## Testing Strategy

```
tests/
├── unit/test_services.py        # Pure service logic, no DB
│   Tests: password hashing, JWT, log parsing, all 7 detectors, AI analysis
│
├── api/test_endpoints.py        # FastAPI TestClient + SQLite in-memory DB
│   Tests: all 26 routes, auth flows, error cases, pagination
│
└── integration/test_workflows.py # End-to-end scenarios
    Tests: full SOC workflow, auth enforcement, search, dashboard aggregation
```

### Test Isolation Strategy
- **SQLite in-memory** database (no PostgreSQL required)
- **StaticPool** ensures single connection reused across async tests
- **Unique username/email per test** via UUID suffix (prevents `UniqueConstraint` failures)
- **Rollback after each test** via session fixture

---

## Performance Considerations

- **Async everywhere**: FastAPI + SQLAlchemy asyncio + asyncpg (PostgreSQL driver)
- **Connection pooling**: `pool_size=10, max_overflow=20`
- **GZip middleware**: Compresses responses > 1KB
- **Nginx caching**: Static assets cached with `immutable` for 1 year
- **Indexed columns**: `source_ip`, `username`, `severity`, `status`, `created_at`
- **Selectinload**: Avoids N+1 queries on related data (detection → mitre_mappings)

---

*Author: Muhammad Usman | ThreatLens AI v1.0*
