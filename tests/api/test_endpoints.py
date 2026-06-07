"""
API Integration Tests for ThreatLens AI endpoints.
Tests cover authentication, log ingestion, alert management,
incident management, and dashboard statistics.
"""
import io
import json
import pytest

from fastapi.testclient import TestClient


# ═══════════════════════════════════════════════════════
# Auth Endpoint Tests
# ═══════════════════════════════════════════════════════

class TestAuthEndpoints:
    def test_register_new_user(self, client: TestClient):
        resp = client.post("/api/v1/auth/register", json={
            "username": "newanalyst",
            "email": "newanalyst@soc.com",
            "password": "SecurePass99",
            "role": "analyst",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["username"] == "newanalyst"
        assert data["email"] == "newanalyst@soc.com"
        assert data["role"] == "analyst"
        assert "hashed_password" not in data

    def test_register_duplicate_username(self, client: TestClient, test_analyst):
        resp = client.post("/api/v1/auth/register", json={
            "username": test_analyst.username,
            "email": "another_unique@test.com",
            "password": "SecurePass99",
        })
        assert resp.status_code == 400
        assert "already registered" in resp.json()["detail"].lower()

    def test_register_duplicate_email(self, client: TestClient, test_analyst):
        resp = client.post("/api/v1/auth/register", json={
            "username": "brandnew_unique",
            "email": test_analyst.email,
            "password": "SecurePass99",
        })
        assert resp.status_code == 400

    def test_register_weak_password(self, client: TestClient):
        resp = client.post("/api/v1/auth/register", json={
            "username": "weakuser",
            "email": "weak@test.com",
            "password": "short",  # too short + no uppercase/digit
        })
        assert resp.status_code == 422

    def test_login_success(self, client: TestClient, test_analyst):
        resp = client.post("/api/v1/auth/login", json={
            "username": test_analyst.username,
            "password": "TestPass123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["username"] == test_analyst.username

    def test_login_wrong_password(self, client: TestClient, test_analyst):
        resp = client.post("/api/v1/auth/login", json={
            "username": test_analyst.username,
            "password": "WrongPassword99",
        })
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client: TestClient):
        resp = client.post("/api/v1/auth/login", json={
            "username": "nobody",
            "password": "SomePass123",
        })
        assert resp.status_code == 401

    def test_get_me_authenticated(self, client: TestClient, analyst_headers):
        resp = client.get("/api/v1/auth/me", headers=analyst_headers)
        assert resp.status_code == 200
        assert resp.json()["username"] == test_analyst.username

    def test_get_me_unauthenticated(self, client: TestClient):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 403  # HTTPBearer returns 403 when no credentials

    def test_refresh_token(self, client: TestClient, test_analyst):
        login_resp = client.post("/api/v1/auth/login", json={
            "username": test_analyst.username,
            "password": "TestPass123",
        })
        refresh_token = login_resp.json()["refresh_token"]
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_refresh_with_invalid_token(self, client: TestClient):
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "invalid.token.here"})
        assert resp.status_code == 401


# ═══════════════════════════════════════════════════════
# Log Ingestion Tests
# ═══════════════════════════════════════════════════════

class TestLogIngestion:
    def test_upload_json_file(self, client: TestClient, analyst_headers, sample_json_logs):
        file_bytes = sample_json_logs.encode()
        resp = client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("security_events.json", io.BytesIO(file_bytes), "application/json")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["logs_stored"] > 0
        assert data["batch_id"] is not None
        assert len(data["batch_id"]) > 0

    def test_upload_csv_file(self, client: TestClient, analyst_headers, sample_csv_logs):
        file_bytes = sample_csv_logs.encode()
        resp = client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("logs.csv", io.BytesIO(file_bytes), "text/csv")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["logs_stored"] >= 5

    def test_upload_txt_file(self, client: TestClient, analyst_headers, sample_txt_logs):
        file_bytes = sample_txt_logs.encode()
        resp = client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("syslog.txt", io.BytesIO(file_bytes), "text/plain")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["logs_stored"] > 0

    def test_upload_creates_detections_and_alerts(self, client: TestClient, analyst_headers, sample_json_logs):
        resp = client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("bf_events.json", io.BytesIO(sample_json_logs.encode()), "application/json")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["detections_created"] >= 1
        assert data["alerts_created"] >= 1

    def test_upload_unsupported_format_rejected(self, client: TestClient, analyst_headers):
        resp = client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("file.pdf", io.BytesIO(b"fake pdf"), "application/pdf")},
        )
        assert resp.status_code == 400

    def test_upload_requires_auth(self, client: TestClient, sample_json_logs):
        resp = client.post(
            "/api/v1/logs/upload",
            files={"file": ("test.json", io.BytesIO(sample_json_logs.encode()), "application/json")},
        )
        assert resp.status_code == 403

    def test_ingest_via_api(self, client: TestClient, analyst_headers):
        logs = [
            {"source_ip": "10.0.0.1", "username": "admin", "message": "Failed password for admin"},
            {"source_ip": "10.0.0.1", "username": "admin", "message": "Failed password for admin"},
            {"source_ip": "10.0.0.1", "username": "admin", "message": "Failed password for admin"},
        ]
        resp = client.post("/api/v1/logs/ingest", json=logs, headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["logs_stored"] == 3

    def test_list_logs_paginated(self, client: TestClient, analyst_headers, sample_csv_logs):
        # Ensure some logs exist
        client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("data.csv", io.BytesIO(sample_csv_logs.encode()), "text/csv")},
        )
        resp = client.get("/api/v1/logs/?page=1&page_size=10", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "pages" in data


# ═══════════════════════════════════════════════════════
# Alert Management Tests
# ═══════════════════════════════════════════════════════

class TestAlertEndpoints:
    def _ensure_alert(self, client, headers):
        """Upload logs to generate at least one alert, return its id."""
        logs = [
            {"source_ip": "10.9.9.9", "username": "admin",
             "message": "Failed password for admin from 10.9.9.9", "event_type": "auth_failure"}
            for _ in range(8)
        ]
        client.post("/api/v1/logs/ingest", json=logs, headers=headers)
        resp = client.get("/api/v1/alerts/?page=1&page_size=5", headers=headers)
        items = resp.json().get("items", [])
        return items[0]["id"] if items else None

    def test_list_alerts_returns_paginated(self, client, analyst_headers):
        resp = client.get("/api/v1/alerts/", headers=analyst_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert isinstance(body["items"], list)

    def test_create_alert_manually(self, client, analyst_headers):
        resp = client.post("/api/v1/alerts/", json={
            "title": "Manual Test Alert",
            "description": "Created during automated testing",
            "severity": "medium",
        }, headers=analyst_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Manual Test Alert"
        assert data["status"] == "open"

    def test_get_alert_by_id(self, client, analyst_headers):
        create_resp = client.post("/api/v1/alerts/", json={
            "title": "Fetch Me Alert",
            "description": "For get test",
            "severity": "low",
        }, headers=analyst_headers)
        alert_id = create_resp.json()["id"]

        resp = client.get(f"/api/v1/alerts/{alert_id}", headers=analyst_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == alert_id

    def test_update_alert_status(self, client, analyst_headers):
        create_resp = client.post("/api/v1/alerts/", json={
            "title": "Status Update Test",
            "description": "Will be updated",
            "severity": "high",
        }, headers=analyst_headers)
        alert_id = create_resp.json()["id"]

        resp = client.patch(f"/api/v1/alerts/{alert_id}", json={
            "status": "in_progress",
            "analyst_notes": "Investigating now",
        }, headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "in_progress"
        assert data["analyst_notes"] == "Investigating now"

    def test_resolve_alert_sets_resolved_at(self, client, analyst_headers):
        create_resp = client.post("/api/v1/alerts/", json={
            "title": "Resolve Me",
            "description": "Test resolution",
            "severity": "medium",
        }, headers=analyst_headers)
        alert_id = create_resp.json()["id"]

        resp = client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "resolved"}, headers=analyst_headers)
        assert resp.status_code == 200
        assert resp.json()["resolved_at"] is not None

    def test_filter_alerts_by_severity(self, client, analyst_headers):
        # Create a critical alert
        client.post("/api/v1/alerts/", json={
            "title": "Critical Test",
            "description": "Critical severity",
            "severity": "critical",
        }, headers=analyst_headers)

        resp = client.get("/api/v1/alerts/?severity=critical", headers=analyst_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(a["severity"] == "critical" for a in items)

    def test_delete_alert(self, client, analyst_headers):
        create_resp = client.post("/api/v1/alerts/", json={
            "title": "Delete Me",
            "description": "Will be deleted",
            "severity": "info",
        }, headers=analyst_headers)
        alert_id = create_resp.json()["id"]

        del_resp = client.delete(f"/api/v1/alerts/{alert_id}", headers=analyst_headers)
        assert del_resp.status_code == 204

        get_resp = client.get(f"/api/v1/alerts/{alert_id}", headers=analyst_headers)
        assert get_resp.status_code == 404

    def test_get_nonexistent_alert_404(self, client, analyst_headers):
        resp = client.get("/api/v1/alerts/00000000-0000-0000-0000-000000000000", headers=analyst_headers)
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════
# Incident Endpoint Tests
# ═══════════════════════════════════════════════════════

class TestIncidentEndpoints:
    def test_create_incident(self, client, analyst_headers):
        resp = client.post("/api/v1/incidents/", json={
            "title": "Ransomware Detected",
            "description": "Ransomware activity on DESKTOP-01",
            "severity": "critical",
            "affected_assets": ["DESKTOP-01", "192.168.1.100"],
        }, headers=analyst_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Ransomware Detected"
        assert data["incident_number"].startswith("INC-")
        assert data["status"] == "new"

    def test_list_incidents(self, client, analyst_headers):
        client.post("/api/v1/incidents/", json={
            "title": "Test Inc",
            "description": "For list test",
            "severity": "medium",
        }, headers=analyst_headers)
        resp = client.get("/api/v1/incidents/", headers=analyst_headers)
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_update_incident_status(self, client, analyst_headers):
        create_resp = client.post("/api/v1/incidents/", json={
            "title": "Update Inc",
            "description": "Will update status",
            "severity": "high",
        }, headers=analyst_headers)
        inc_id = create_resp.json()["id"]

        resp = client.patch(f"/api/v1/incidents/{inc_id}", json={
            "status": "investigating",
            "root_cause": "Phishing email opened by user",
        }, headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "investigating"
        assert data["root_cause"] == "Phishing email opened by user"

    def test_close_incident_sets_closed_at(self, client, analyst_headers):
        create_resp = client.post("/api/v1/incidents/", json={
            "title": "Close Me Inc",
            "description": "Will be closed",
            "severity": "low",
        }, headers=analyst_headers)
        inc_id = create_resp.json()["id"]

        resp = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "closed"}, headers=analyst_headers)
        assert resp.status_code == 200
        assert resp.json()["closed_at"] is not None

    def test_incident_number_unique(self, client, analyst_headers):
        nums = []
        for i in range(3):
            resp = client.post("/api/v1/incidents/", json={
                "title": f"Inc {i}",
                "description": f"Description {i}",
                "severity": "low",
            }, headers=analyst_headers)
            nums.append(resp.json()["incident_number"])
        assert len(set(nums)) == 3  # all unique


# ═══════════════════════════════════════════════════════
# Dashboard Tests
# ═══════════════════════════════════════════════════════

class TestDashboardEndpoint:
    def test_dashboard_returns_all_sections(self, client, analyst_headers):
        resp = client.get("/api/v1/dashboard/", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "stats" in data
        assert "severity_distribution" in data
        assert "detection_trends" in data
        assert "mitre_distribution" in data
        assert "recent_alerts" in data

    def test_dashboard_stats_structure(self, client, analyst_headers):
        resp = client.get("/api/v1/dashboard/", headers=analyst_headers)
        stats = resp.json()["stats"]
        expected_keys = [
            "total_logs", "total_alerts", "open_alerts", "high_severity_alerts",
            "critical_alerts", "total_incidents", "active_incidents",
            "detections_today", "logs_today",
        ]
        for key in expected_keys:
            assert key in stats, f"Missing key in stats: {key}"

    def test_dashboard_requires_auth(self, client):
        resp = client.get("/api/v1/dashboard/")
        assert resp.status_code == 403


# ═══════════════════════════════════════════════════════
# Search Endpoint Tests
# ═══════════════════════════════════════════════════════

class TestSearchEndpoints:
    def test_search_alerts_no_query(self, client, analyst_headers):
        resp = client.get("/api/v1/search/alerts", headers=analyst_headers)
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_search_logs_no_query(self, client, analyst_headers):
        resp = client.get("/api/v1/search/logs", headers=analyst_headers)
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_search_alerts_by_keyword(self, client, analyst_headers):
        client.post("/api/v1/alerts/", json={
            "title": "UNIQUE_KEYWORD_XYZ Brute Force",
            "description": "Contains special keyword",
            "severity": "high",
        }, headers=analyst_headers)

        resp = client.get("/api/v1/search/alerts?q=UNIQUE_KEYWORD_XYZ", headers=analyst_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert any("UNIQUE_KEYWORD_XYZ" in a["title"] for a in items)

    def test_search_logs_by_ip(self, client, analyst_headers, sample_json_logs):
        client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("ev.json", io.BytesIO(sample_json_logs.encode()), "application/json")},
        )
        resp = client.get("/api/v1/search/logs?source_ip=192.168.1.100", headers=analyst_headers)
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════
# User Management Tests
# ═══════════════════════════════════════════════════════

class TestUserEndpoints:
    def test_list_users_admin_only(self, client, admin_headers, analyst_headers):
        # Admin can access
        resp = client.get("/api/v1/users/", headers=admin_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

        # Analyst cannot
        resp = client.get("/api/v1/users/", headers=analyst_headers)
        assert resp.status_code == 403

    def test_get_own_profile(self, client, analyst_headers, test_analyst):
        resp = client.get(f"/api/v1/users/{test_analyst.id}", headers=analyst_headers)
        assert resp.status_code == 200
        assert resp.json()["username"] == test_analyst.username

    def test_update_own_profile(self, client, analyst_headers, test_analyst):
        resp = client.patch(
            f"/api/v1/users/{test_analyst.id}",
            json={"full_name": "Updated Analyst Name"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["full_name"] == "Updated Analyst Name"

    def test_analyst_cannot_access_other_user(self, client, analyst_headers, test_admin):
        resp = client.get(f"/api/v1/users/{test_admin.id}", headers=analyst_headers)
        assert resp.status_code == 403


# ═══════════════════════════════════════════════════════
# Health Check
# ═══════════════════════════════════════════════════════

class TestHealthCheck:
    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "ThreatLens AI"
