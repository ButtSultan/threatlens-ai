# 🛡️ ThreatLens AI — Intelligent SOC Analyst Assistant

<div align="center">

![ThreatLens AI](https://img.shields.io/badge/ThreatLens-AI-0ea5e9?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776ab?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61dafb?style=for-the-badge&logo=react&logoColor=black)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=for-the-badge&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ed?style=for-the-badge&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A production-grade, AI-powered Security Operations Center (SOC) platform for intelligent threat detection, incident management, and automated security analysis.**

[Features](#-features) • [Architecture](#-architecture) • [Quick Start](#-quick-start) • [API Docs](#-api-documentation) • [Screenshots](#-screenshots) • [Roadmap](#-roadmap)

</div>

---

## 📋 Overview

**ThreatLens AI** is a full-stack cybersecurity platform that empowers SOC analysts with AI-assisted threat detection, automated MITRE ATT&CK mapping, and professional incident reporting — all in a modern dark-mode dashboard.

Built by **Muhammad Usman** as a comprehensive cybersecurity portfolio project demonstrating:
- Production-grade backend architecture (FastAPI + PostgreSQL + Redis)
- AI-powered threat analysis engine with 7 detection algorithms
- Complete incident lifecycle management
- Professional PDF report generation
- 80%+ test coverage with pytest

---

## ✨ Features

### 🔍 Threat Detection Engine
- **Brute-Force Detection** — Identifies repeated failed authentication attempts
- **Password Spraying** — Detects low-and-slow credential attacks across accounts
- **Impossible Travel** — Flags geographically impossible login sequences
- **Privilege Escalation** — Detects sudo/runas abuse and admin group modifications
- **Suspicious PowerShell** — Identifies encoded commands and download cradles
- **Credential Dumping** — Detects Mimikatz, LSASS access, and SAM database attacks
- **Reconnaissance** — Identifies port scanning and network enumeration

### 🤖 AI Analysis Module
- Automated threat summaries with severity classification
- Step-by-step attack explanation for every detection type
- Prioritized remediation recommendations
- Analyst investigation notes and context

### 🗺️ MITRE ATT&CK Mapping
- Automatic technique mapping for all detections
- Technique ID, name, tactic, and ATT&CK URL
- Tactic distribution visualization on dashboard

### 📊 SOC Dashboard
- Real-time metrics: logs, alerts, incidents
- Severity distribution donut chart
- 7-day detection trend area chart
- MITRE tactic distribution bar chart
- Live recent alerts feed

### 🚨 Alert Management
- Full alert lifecycle: Open → In Progress → Resolved → Closed
- AI-generated summaries and recommendations per alert
- Analyst notes and false-positive marking
- Severity and status filtering

### 📁 Log Ingestion
- **JSON** (array and NDJSON), **CSV**, **TXT/Syslog** formats
- Drag-and-drop file upload UI
- Batch ingestion API endpoint
- Automatic field normalization from vendor-specific formats

### 📄 Report Generation
- **Incident Reports** — Full forensic analysis PDF
- **Executive Summaries** — C-suite security posture overview
- Professionally formatted with ThreatLens branding

### 🔐 Security
- JWT authentication with refresh token rotation
- bcrypt password hashing
- Role-based access control (Admin / Analyst / Viewer)
- Rate limiting on all endpoints
- SQL injection protection via SQLAlchemy ORM
- Security headers on all responses
- Full audit trail for all user actions

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         NGINX (Port 80)                         │
│              Reverse Proxy + Rate Limiting + SSL                │
└───────────────────┬────────────────────┬────────────────────────┘
                    │                    │
          ┌─────────▼──────┐    ┌────────▼────────┐
          │  React Frontend │    │  FastAPI Backend │
          │  (TailwindCSS)  │    │   (Port 8000)   │
          │   Port 3000     │    │                 │
          └─────────────────┘    └────────┬────────┘
                                          │
                    ┌─────────────────────┼──────────────────┐
                    │                     │                  │
          ┌─────────▼──────┐    ┌─────────▼──────┐  ┌──────▼──────┐
          │   PostgreSQL   │    │     Redis       │  │  File Store │
          │   (Port 5432)  │    │  (Port 6379)   │  │  /uploads   │
          └────────────────┘    └────────────────┘  └─────────────┘

Backend Service Architecture:
┌─────────────────────────────────────────────────────┐
│                    FastAPI App                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │   Auth   │  │   CRUD   │  │    Detection     │  │
│  │ Endpoints│  │Endpoints │  │     Engine       │  │
│  └──────────┘  └──────────┘  └────────┬─────────┘  │
│  ┌────────────────────────────────────▼──────────┐  │
│  │              Service Layer                    │  │
│  │  LogParser | AIAnalysis | ReportService       │  │
│  └────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────┐  │
│  │          SQLAlchemy ORM + Alembic             │  │
│  └────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.12, FastAPI, SQLAlchemy 2.0 (async) |
| **Frontend** | React 18, TailwindCSS 3, Recharts, Zustand |
| **Database** | PostgreSQL 16 |
| **Cache** | Redis 7 |
| **ORM** | SQLAlchemy + Alembic migrations |
| **Auth** | JWT (python-jose) + bcrypt (passlib) |
| **Reports** | fpdf2 |
| **Containerization** | Docker + Docker Compose |
| **Reverse Proxy** | Nginx |
| **Testing** | pytest + pytest-asyncio + pytest-cov |
| **CI/CD** | GitHub Actions |

---

## 🚀 Quick Start

### Prerequisites
- **Docker** 24+ and **Docker Compose** v2+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/muhammadus/threatlens-ai.git
cd threatlens-ai
```

### 2. Configure Environment
```bash
cp .env.example .env
```

Edit `.env` with your settings (change all passwords!):
```bash
# Critical values to change before production deployment:
POSTGRES_PASSWORD=your_strong_database_password
REDIS_PASSWORD=your_strong_redis_password
SECRET_KEY=your_32_character_minimum_secret_key
```

### 3. Launch with Docker Compose
```bash
docker compose up --build
```

This will:
- Build backend and frontend Docker images
- Start PostgreSQL and Redis
- Run Alembic database migrations automatically
- Start all services behind Nginx

### 4. Access the Platform
| Service | URL |
|---------|-----|
| **ThreatLens AI Dashboard** | http://localhost |
| **API Documentation (Swagger)** | http://localhost/api/docs |
| **API Documentation (ReDoc)** | http://localhost/api/redoc |

### 5. Create Your First Account
Navigate to http://localhost/register and create an analyst account.

> **First user tip:** To create an admin account, register normally then manually update the role in the database, or use the register API with `"role": "admin"`.

---

## 🧪 Testing Your Setup

### Upload Sample Logs
1. Log in at http://localhost
2. Navigate to **Logs** page
3. Upload one of the sample files from `docs/sample-logs/`:
   - `security_events.json` — Contains brute-force, privilege escalation, PowerShell, credential dumping, and port scanning
   - `auth_logs.csv` — Authentication events with credential dumping
   - `syslog_sample.txt` — Linux syslog with mixed attack patterns

4. Watch the dashboard populate with alerts and detections!

### Run Backend Tests
```bash
cd backend
pip install -r requirements.txt
pytest ../tests/ -v --cov=app --cov-report=term-missing
```

### Run via Docker
```bash
docker compose exec backend pytest /app/../tests/ -v
```

---

## 🐳 Docker Deployment

### Production Deployment Checklist

1. **Update `.env`** with strong, unique credentials
2. **Enable HTTPS** by adding SSL certificates to Nginx config
3. **Set `ENVIRONMENT=production`** in `.env`
4. **Configure CORS_ORIGINS** to your actual domain
5. **Set up database backups** for the PostgreSQL volume

### Service Management
```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f backend
docker compose logs -f frontend

# Stop all services
docker compose down

# Rebuild after code changes
docker compose up --build -d

# Reset database (WARNING: deletes all data)
docker compose down -v
docker compose up --build -d

# Scale backend workers
docker compose up -d --scale backend=3
```

### Database Backup
```bash
# Backup
docker compose exec postgres pg_dump -U threatlens threatlens_db > backup.sql

# Restore
cat backup.sql | docker compose exec -T postgres psql -U threatlens threatlens_db
```

---

## 📡 API Documentation

Full API reference: [`docs/api.md`](docs/api.md)

### Quick Examples

**Login:**
```bash
curl -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst01", "password": "SecurePass1"}'
```

**Upload Logs:**
```bash
curl -X POST http://localhost/api/v1/logs/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@docs/sample-logs/security_events.json"
```

**List Alerts:**
```bash
curl http://localhost/api/v1/alerts/?severity=critical \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Get Dashboard:**
```bash
curl http://localhost/api/v1/dashboard/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Ingest Logs via API:**
```bash
curl -X POST http://localhost/api/v1/logs/ingest \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"source_ip":"10.0.0.1","username":"admin","message":"Failed password for admin"}]'
```

---

## 📁 Project Structure

```
threatlens-ai/
│
├── backend/                        # FastAPI backend
│   ├── app/
│   │   ├── api/v1/endpoints/       # REST API endpoints
│   │   │   ├── auth.py             # Login, register, refresh
│   │   │   ├── logs.py             # Log ingestion
│   │   │   ├── alerts.py           # Alert management
│   │   │   ├── incidents.py        # Incident lifecycle
│   │   │   ├── dashboard.py        # Analytics
│   │   │   ├── reports.py          # PDF generation
│   │   │   ├── search.py           # Full-text search
│   │   │   └── users.py            # User management
│   │   ├── core/                   # Config, security, logging
│   │   ├── db/                     # Database session
│   │   ├── models/                 # SQLAlchemy ORM models
│   │   ├── schemas/                # Pydantic validation schemas
│   │   └── services/               # Business logic
│   │       ├── detection_engine.py # 7 threat detectors
│   │       ├── ai_analysis.py      # AI threat analysis
│   │       ├── log_parser.py       # JSON/CSV/TXT parser
│   │       └── report_service.py   # PDF report generator
│   ├── alembic/                    # Database migrations
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                       # React frontend
│   ├── src/
│   │   ├── pages/                  # 8 full pages
│   │   ├── components/             # Reusable UI components
│   │   ├── store/                  # Zustand state management
│   │   └── utils/                  # API client
│   ├── package.json
│   └── Dockerfile
│
├── tests/                          # Test suite (80%+ coverage)
│   ├── unit/test_services.py       # Service unit tests
│   ├── api/test_endpoints.py       # API integration tests
│   └── integration/test_workflows.py # End-to-end workflow tests
│
├── docs/
│   ├── api.md                      # API reference
│   └── sample-logs/                # Demo log files
│       ├── security_events.json
│       ├── auth_logs.csv
│       └── syslog_sample.txt
│
├── docker/nginx/                   # Nginx config
├── database/init.sql               # DB initialization
├── .github/workflows/              # CI/CD pipelines
│   ├── ci.yml                      # Lint, test, build, security
│   └── cd.yml                      # Build & push Docker images
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## 🗄️ Database Schema

```
users ──────────────────────────────────────────────┐
  id, username, email, hashed_password,              │
  role (admin|analyst|viewer), is_active             │
                                                     │
log_entries ────────────────────────────────────────┤
  id, source_file, log_type, raw_data,               │
  source_ip, username, event_type, batch_id          │uploaded_by → users
                                                     │
threat_detections ──────────────────────────────────┤
  id, detection_type, description, severity,         │log_entry_id → log_entries
  confidence_score, source_ips[], affected_users[]  │
                                                     │
mitre_mappings ─────────────────────────────────────┤
  id, technique_id, technique_name, tactic          │detection_id → threat_detections
                                                     │
alerts ─────────────────────────────────────────────┤
  id, title, description, severity, status,          │detection_id → threat_detections
  ai_summary, ai_recommendations[], analyst_notes    │assigned_to → users
                                                     │
incidents ──────────────────────────────────────────┤
  id, incident_number, title, severity, status,      │alert_id → alerts
  root_cause, lessons_learned, timeline[]            │
                                                     │
reports ─────────────────────────────────────────────┤
  id, title, report_type, file_path                 │incident_id → incidents
                                                     │
audit_logs ─────────────────────────────────────────┘
  id, user_id, action, resource_type, ip_address    → users
```

---

## 🔐 MITRE ATT&CK Coverage

| Detection | Technique ID | Technique | Tactic |
|-----------|-------------|-----------|--------|
| Brute Force | T1110 | Brute Force | Credential Access |
| Password Spraying | T1110.003 | Password Spraying | Credential Access |
| Impossible Travel | T1078 | Valid Accounts | Defense Evasion |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| Suspicious PowerShell | T1059.001 | PowerShell | Execution |
| Credential Dumping | T1003 | OS Credential Dumping | Credential Access |
| Reconnaissance | T1046 | Network Service Discovery | Discovery |

---

## 📸 Screenshots

> **Dashboard** — Real-time SOC metrics with severity distribution, detection trends, and MITRE ATT&CK tactic mapping

> **Alerts Page** — Full alert management with AI-powered analysis and MITRE technique display

> **Log Ingestion** — Drag-and-drop file upload with instant threat detection results

> **Incidents** — Full incident lifecycle from detection through closure with root cause analysis

> **Reports** — One-click PDF generation for incident reports and executive summaries

*Screenshot files would be placed in `/screenshots/` directory.*

---

## 🧪 Test Coverage

```
tests/
├── unit/test_services.py         # 35 unit tests
│   ├── TestPasswordHashing       # 4 tests
│   ├── TestPasswordStrength      # 5 tests
│   ├── TestJWT                   # 4 tests
│   ├── TestLogParser             # 7 tests
│   ├── TestThreatDetectionEngine # 11 tests
│   └── TestAIAnalysisService     # 6 tests
│
├── api/test_endpoints.py         # 40 API tests
│   ├── TestAuthEndpoints         # 11 tests
│   ├── TestLogIngestion          # 8 tests
│   ├── TestAlertEndpoints        # 8 tests
│   ├── TestIncidentEndpoints     # 5 tests
│   ├── TestDashboardEndpoint     # 3 tests
│   ├── TestSearchEndpoints       # 4 tests
│   └── TestUserEndpoints         # 4 tests
│
└── integration/test_workflows.py # 22 integration tests
    ├── TestFullSOCWorkflow        # 4 workflow tests
    ├── TestSearchWorkflow         # 4 tests
    ├── TestAuthorizationWorkflow  # 5 tests
    ├── TestDashboardAggregation   # 3 tests
    └── TestDataValidation         # 6 tests

Total: 97 tests | Target coverage: ≥80%
```

Run tests:
```bash
cd backend && pytest ../tests/ -v --cov=app --cov-fail-under=80
```

---

## 🔄 CI/CD Pipeline

**GitHub Actions Workflows:**

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | Push/PR to main/develop | Lint, Test, Frontend Build, Security Scan, Docker Build |
| `cd.yml` | Push to main, version tags | Build & Push to GHCR, Create GitHub Release |

---

## 🗺️ Roadmap

### Version 1.1
- [ ] Real LLM integration (OpenAI / local Ollama)
- [ ] SIEM connector (Elastic, Splunk)
- [ ] Webhook alerting (Slack, Teams, PagerDuty)
- [ ] Email notifications for critical alerts

### Version 1.2
- [ ] Multi-tenant support
- [ ] Threat intelligence feed integration (VirusTotal, AbuseIPDB)
- [ ] Custom detection rule builder (YARA-like)
- [ ] Timeline visualization for incidents

### Version 2.0
- [ ] Machine learning anomaly detection
- [ ] SOAR playbook automation
- [ ] Network topology mapping
- [ ] Active Directory integration
- [ ] Compliance reporting (ISO 27001, NIST, SOC2)

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/awesome-detection`
3. Write tests for your changes
4. Ensure all tests pass: `pytest ../tests/ -v`
5. Submit a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Muhammad Usman**

> *"Built to demonstrate production-grade cybersecurity engineering — from threat detection algorithms to AI-powered analysis to a professional SOC dashboard."*

---

<div align="center">

⭐ **If this project helped you, please give it a star!** ⭐

Made with ❤️ and a lot of ☕ by Muhammad Usman

</div>
