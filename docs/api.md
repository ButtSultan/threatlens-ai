# ThreatLens AI — REST API Documentation

**Base URL:** `http://localhost/api/v1`  
**Interactive Docs:** `http://localhost/api/docs` (Swagger UI)  
**ReDoc:** `http://localhost/api/redoc`

---

## Authentication

All endpoints except `/auth/login` and `/auth/register` require a Bearer token.

```http
Authorization: Bearer <access_token>
```

Tokens expire in **30 minutes**. Use the refresh endpoint to obtain a new access token.

---

## Endpoints

### 🔐 Auth

#### POST `/auth/register`
Register a new user account.

**Request:**
```json
{
  "username": "analyst01",
  "email": "analyst01@soc.com",
  "password": "SecurePass1",
  "full_name": "SOC Analyst",
  "role": "analyst"
}
```

**Response `201`:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "analyst01",
  "email": "analyst01@soc.com",
  "full_name": "SOC Analyst",
  "role": "analyst",
  "is_active": true,
  "last_login": null,
  "created_at": "2024-01-15T08:00:00Z"
}
```

---

#### POST `/auth/login`
Authenticate and receive JWT tokens.

**Request:**
```json
{
  "username": "analyst01",
  "password": "SecurePass1"
}
```

**Response `200`:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": { "username": "analyst01", "role": "analyst" }
}
```

---

#### POST `/auth/refresh`
Refresh access token using a valid refresh token.

**Request:**
```json
{ "refresh_token": "eyJhbGci..." }
```

---

#### GET `/auth/me`
Get current authenticated user profile.

---

### 📋 Logs

#### POST `/logs/upload`
Upload a log file for ingestion and analysis. Accepts JSON, CSV, or TXT files.

**Request:** `multipart/form-data`
- `file`: The log file (`.json`, `.csv`, or `.txt`)

**Response `200`:**
```json
{
  "batch_id": "a1b2c3d4e5f6",
  "logs_processed": 150,
  "logs_stored": 150,
  "detections_created": 3,
  "alerts_created": 3,
  "message": "Successfully ingested 150 log entries..."
}
```

**Errors:**
- `400` — Unsupported file format or no valid entries found
- `413` — File exceeds 50MB limit

---

#### POST `/logs/ingest`
Ingest logs directly via API (JSON array).

**Request:**
```json
[
  {
    "source_ip": "192.168.1.100",
    "username": "admin",
    "event_type": "authentication_failure",
    "message": "Failed password for admin"
  }
]
```

---

#### GET `/logs/`
List all log entries with pagination.

**Query params:** `page`, `page_size`, `source_ip`, `username`

**Response `200`:**
```json
{
  "items": [ { "id": "...", "source_ip": "...", "username": "..." } ],
  "total": 1250,
  "page": 1,
  "page_size": 50,
  "pages": 25
}
```

---

### 🚨 Alerts

#### GET `/alerts/`
List alerts with optional filters.

**Query params:** `page`, `page_size`, `severity` (`critical|high|medium|low|info`), `status` (`open|in_progress|resolved|closed`)

---

#### GET `/alerts/{alert_id}`
Get full alert details including detection and MITRE mappings.

---

#### POST `/alerts/`
Manually create an alert.

**Request:**
```json
{
  "title": "Suspicious PowerShell Activity",
  "description": "Encoded PowerShell command detected on WORKSTATION-05",
  "severity": "high",
  "tags": ["powershell", "execution"]
}
```

---

#### PATCH `/alerts/{alert_id}`
Update alert status, notes, or assignment.

**Request:**
```json
{
  "status": "in_progress",
  "analyst_notes": "Investigating — isolated workstation",
  "false_positive": false
}
```

**Valid statuses:** `open` → `in_progress` → `resolved` → `closed`

---

#### DELETE `/alerts/{alert_id}`
Delete an alert.

---

### 🔥 Incidents

#### GET `/incidents/`
List incidents with optional `status` and `severity` filters.

---

#### POST `/incidents/`
Create a new security incident.

**Request:**
```json
{
  "title": "Ransomware on DESKTOP-01",
  "description": "User reported files encrypted, ransom note found",
  "severity": "critical",
  "alert_id": "550e8400-...",
  "affected_assets": ["DESKTOP-01", "10.0.0.55"]
}
```

**Response `201`:**
```json
{
  "id": "...",
  "incident_number": "INC-20240115-A1B2C3",
  "title": "Ransomware on DESKTOP-01",
  "status": "new",
  "severity": "critical"
}
```

---

#### PATCH `/incidents/{incident_id}`
Update incident status, root cause, and lessons learned.

**Request:**
```json
{
  "status": "investigating",
  "root_cause": "Phishing email with malicious attachment",
  "containment_actions": ["Isolated host", "Reset passwords"],
  "lessons_learned": "Implement email filtering rules"
}
```

**Valid statuses:** `new` → `investigating` → `contained` → `eradicated` → `recovered` → `closed`

---

### 📊 Dashboard

#### GET `/dashboard/`
Get complete SOC dashboard statistics.

**Response `200`:**
```json
{
  "stats": {
    "total_logs": 15240,
    "total_alerts": 87,
    "open_alerts": 12,
    "high_severity_alerts": 8,
    "critical_alerts": 3,
    "total_incidents": 5,
    "active_incidents": 2,
    "detections_today": 14,
    "logs_today": 1200
  },
  "severity_distribution": [
    { "severity": "critical", "count": 3 },
    { "severity": "high", "count": 8 }
  ],
  "detection_trends": [
    { "date": "2024-01-15", "severity": "high", "count": 5 }
  ],
  "mitre_distribution": [
    { "tactic": "Credential Access", "count": 12 }
  ],
  "recent_alerts": [ ... ]
}
```

---

### 📄 Reports

#### POST `/reports/generate`
Generate a PDF report.

**Request:**
```json
{
  "title": "January 2024 Security Report",
  "report_type": "executive",
  "incident_id": null
}
```

**`report_type` values:** `incident`, `executive`, `summary`

---

#### GET `/reports/{report_id}/download`
Download a generated PDF report as binary stream.

---

### 🔍 Search

#### GET `/search/alerts`
Full-text search across alerts.

**Query params:** `q`, `severity`, `status`, `start_date`, `end_date`, `page`, `page_size`

---

#### GET `/search/logs`
Full-text search across log entries.

**Query params:** `q`, `source_ip`, `username`, `event_type`, `start_date`, `end_date`, `page`, `page_size`

---

### 👥 Users (Admin Only)

#### GET `/users/`
List all users. **Requires admin role.**

#### PATCH `/users/{user_id}`
Update user profile (full_name, email).

#### DELETE `/users/{user_id}`
Deactivate a user account. **Requires admin role.**

---

## Error Responses

All errors return a standard format:

```json
{ "detail": "Human-readable error message" }
```

| Code | Meaning |
|------|---------|
| `400` | Bad Request — invalid input |
| `401` | Unauthorized — invalid/expired token |
| `403` | Forbidden — insufficient permissions |
| `404` | Not Found |
| `413` | Payload Too Large |
| `422` | Unprocessable Entity — validation error |
| `429` | Too Many Requests — rate limited |
| `500` | Internal Server Error |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `POST /auth/login` | 10 requests/minute per IP |
| All other endpoints | 30 requests/second per IP |
