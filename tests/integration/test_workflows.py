"""
Integration Tests — End-to-end workflow scenarios for ThreatLens AI.

These tests exercise complete user journeys across multiple API endpoints,
verifying that all components work together correctly.
"""
import io
import json
import pytest
from fastapi.testclient import TestClient


class TestFullSOCWorkflow:
    """
    Test the complete SOC analyst workflow:
    Upload logs → Verify detections → Manage alerts → Create incident → Generate report
    """

    def test_complete_brute_force_workflow(self, client: TestClient, analyst_headers, sample_json_logs):
        """Full workflow: upload brute-force logs → detect → alert created → update → resolve."""

        # Step 1: Upload logs containing brute-force pattern
        resp = client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("bf_attack.json", io.BytesIO(sample_json_logs.encode()), "application/json")},
        )
        assert resp.status_code == 200
        upload_data = resp.json()
        assert upload_data["logs_stored"] > 0
        batch_id = upload_data["batch_id"]
        assert len(batch_id) == 12

        # Step 2: Verify detections were created (alerts should exist)
        assert upload_data["detections_created"] >= 1
        assert upload_data["alerts_created"] >= 1

        # Step 3: Fetch alerts and verify at least one is related to our upload
        alerts_resp = client.get("/api/v1/alerts/?status=open", headers=analyst_headers)
        assert alerts_resp.status_code == 200
        alerts = alerts_resp.json()["items"]
        assert len(alerts) >= 1

        # Verify alert has AI analysis populated
        first_alert = alerts[0]
        assert first_alert["ai_summary"] is not None
        assert first_alert["ai_recommendations"] is not None
        assert isinstance(first_alert["ai_recommendations"], list)

        # Step 4: Analyst investigates — mark alert as in_progress
        alert_id = first_alert["id"]
        update_resp = client.patch(
            f"/api/v1/alerts/{alert_id}",
            json={
                "status": "in_progress",
                "analyst_notes": "Confirmed brute-force from external IP. Firewall block initiated.",
            },
            headers=analyst_headers,
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["status"] == "in_progress"

        # Step 5: Create incident from the alert
        incident_resp = client.post(
            "/api/v1/incidents/",
            json={
                "title": "Brute Force Attack — Production SSH",
                "description": "Sustained brute-force attack detected against production SSH service.",
                "severity": "high",
                "alert_id": alert_id,
                "affected_assets": ["192.168.1.100", "server-01"],
            },
            headers=analyst_headers,
        )
        assert incident_resp.status_code == 201
        incident = incident_resp.json()
        assert incident["incident_number"].startswith("INC-")
        incident_id = incident["id"]

        # Step 6: Update incident through lifecycle
        lifecycle_states = ["investigating", "contained", "eradicated", "recovered"]
        for state in lifecycle_states:
            patch_resp = client.patch(
                f"/api/v1/incidents/{incident_id}",
                json={"status": state},
                headers=analyst_headers,
            )
            assert patch_resp.status_code == 200
            assert patch_resp.json()["status"] == state

        # Step 7: Close incident with lessons learned
        close_resp = client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={
                "status": "closed",
                "root_cause": "Weak SSH password policy allowed brute-force attack to succeed.",
                "lessons_learned": "Implemented MFA, fail2ban, and stronger password policy.",
                "containment_actions": ["Blocked source IP", "Reset compromised credentials", "Enabled MFA"],
            },
            headers=analyst_headers,
        )
        assert close_resp.status_code == 200
        closed = close_resp.json()
        assert closed["status"] == "closed"
        assert closed["closed_at"] is not None
        assert closed["root_cause"] is not None

        # Step 8: Resolve the original alert
        resolve_resp = client.patch(
            f"/api/v1/alerts/{alert_id}",
            json={"status": "resolved"},
            headers=analyst_headers,
        )
        assert resolve_resp.status_code == 200
        assert resolve_resp.json()["resolved_at"] is not None

        # Step 9: Verify dashboard shows updated stats
        dash_resp = client.get("/api/v1/dashboard/", headers=analyst_headers)
        assert dash_resp.status_code == 200
        stats = dash_resp.json()["stats"]
        assert stats["total_logs"] > 0
        assert stats["total_alerts"] > 0
        assert stats["total_incidents"] > 0

    def test_csv_upload_workflow(self, client: TestClient, analyst_headers, sample_csv_logs):
        """CSV log upload creates valid entries and detections."""
        resp = client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("auth.csv", io.BytesIO(sample_csv_logs.encode()), "text/csv")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["logs_stored"] >= 5
        assert data["detections_created"] >= 1  # 5 failed logins should trigger brute force

    def test_txt_syslog_workflow(self, client: TestClient, analyst_headers, sample_txt_logs):
        """TXT/syslog upload triggers multiple detection types."""
        resp = client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("syslog.txt", io.BytesIO(sample_txt_logs.encode()), "text/plain")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["logs_stored"] > 0
        # The txt sample has sudo (priv esc) and powershell — expect detections
        assert data["detections_created"] >= 1

    def test_api_ingest_workflow(self, client: TestClient, analyst_headers):
        """Direct API log ingestion creates detections and alerts."""
        # Simulate credential dumping
        logs = [
            {
                "source_ip": "10.10.10.5",
                "username": "attacker",
                "message": "mimikatz sekurlsa::logonpasswords executed",
                "hostname": "COMPROMISED-WS01",
                "event_type": "process_creation",
            }
        ]
        resp = client.post("/api/v1/logs/ingest", json=logs, headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["logs_stored"] == 1
        # Mimikatz should trigger credential_access detection
        assert data["detections_created"] >= 1
        assert data["alerts_created"] >= 1


class TestSearchWorkflow:
    """Test search functionality across logs and alerts."""

    def test_search_after_upload_finds_logs(self, client: TestClient, analyst_headers, sample_json_logs):
        """Uploaded logs are searchable by IP."""
        client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("search_test.json", io.BytesIO(sample_json_logs.encode()), "application/json")},
        )

        # Search by known IP from sample data
        resp = client.get("/api/v1/search/logs?source_ip=192.168.1.100", headers=analyst_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) > 0
        assert all(i.get("source_ip") == "192.168.1.100" for i in items if i.get("source_ip"))

    def test_search_alerts_by_severity(self, client: TestClient, analyst_headers):
        """Alerts are searchable and filterable by severity."""
        # Create alerts with different severities
        for sev in ["critical", "high", "medium"]:
            client.post("/api/v1/alerts/", json={
                "title": f"Search Test Alert {sev.title()}",
                "description": f"Alert with {sev} severity for search test",
                "severity": sev,
            }, headers=analyst_headers)

        # Search for critical only
        resp = client.get("/api/v1/search/alerts?severity=critical", headers=analyst_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(a["severity"] == "critical" for a in items)

    def test_search_alerts_by_keyword(self, client: TestClient, analyst_headers):
        """Keyword search returns matching alerts."""
        unique_keyword = "THREATLENS_SEARCH_INTEGRATION_TEST_XYZ"
        client.post("/api/v1/alerts/", json={
            "title": f"Alert containing {unique_keyword}",
            "description": "Integration test search target",
            "severity": "low",
        }, headers=analyst_headers)

        resp = client.get(f"/api/v1/search/alerts?q={unique_keyword}", headers=analyst_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) >= 1
        assert any(unique_keyword in a["title"] for a in items)

    def test_pagination_works_correctly(self, client: TestClient, analyst_headers):
        """Pagination returns correct page sizes and totals."""
        # Create 5 alerts
        for i in range(5):
            client.post("/api/v1/alerts/", json={
                "title": f"Pagination Test Alert {i:03d}",
                "description": "For pagination testing",
                "severity": "info",
            }, headers=analyst_headers)

        # Get page 1 with page_size=2
        resp = client.get("/api/v1/alerts/?page=1&page_size=2", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) <= 2
        assert data["page"] == 1
        assert data["total"] >= 5
        assert data["pages"] >= 3


class TestAuthorizationWorkflow:
    """Test that authorization is correctly enforced across all endpoints."""

    def test_unauthenticated_requests_rejected(self, client: TestClient):
        """All protected endpoints reject unauthenticated requests."""
        protected_endpoints = [
            ("GET", "/api/v1/alerts/"),
            ("GET", "/api/v1/logs/"),
            ("GET", "/api/v1/incidents/"),
            ("GET", "/api/v1/reports/"),
            ("GET", "/api/v1/dashboard/"),
            ("GET", "/api/v1/search/alerts"),
        ]
        for method, path in protected_endpoints:
            resp = client.request(method, path)
            assert resp.status_code in (401, 403), f"{method} {path} should require auth, got {resp.status_code}"

    def test_analyst_cannot_access_admin_endpoints(self, client: TestClient, analyst_headers):
        """Analyst role cannot access admin-only user list."""
        resp = client.get("/api/v1/users/", headers=analyst_headers)
        assert resp.status_code == 403

    def test_admin_can_access_all_endpoints(self, client: TestClient, admin_headers):
        """Admin role can access all endpoints including user management."""
        resp = client.get("/api/v1/users/", headers=admin_headers)
        assert resp.status_code == 200

    def test_analyst_can_create_alerts_and_incidents(self, client: TestClient, analyst_headers):
        """Analyst role can perform core SOC operations."""
        # Create alert
        alert_resp = client.post("/api/v1/alerts/", json={
            "title": "Analyst Permission Test",
            "description": "Testing analyst permissions",
            "severity": "medium",
        }, headers=analyst_headers)
        assert alert_resp.status_code == 201

        # Create incident
        inc_resp = client.post("/api/v1/incidents/", json={
            "title": "Analyst Incident Test",
            "description": "Testing analyst incident creation",
            "severity": "low",
        }, headers=analyst_headers)
        assert inc_resp.status_code == 201

    def test_expired_token_rejected(self, client: TestClient):
        """Expired/invalid tokens are rejected with 401/403."""
        bad_headers = {"Authorization": "Bearer invalid.token.signature"}
        resp = client.get("/api/v1/dashboard/", headers=bad_headers)
        assert resp.status_code in (401, 403)


class TestDashboardAggregation:
    """Test that dashboard stats correctly aggregate data."""

    def test_dashboard_counts_increase_after_upload(self, client: TestClient, analyst_headers, sample_csv_logs):
        """Dashboard stats reflect new logs and alerts after upload."""
        # Get baseline
        before = client.get("/api/v1/dashboard/", headers=analyst_headers).json()["stats"]

        # Upload logs
        client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("dash_test.csv", io.BytesIO(sample_csv_logs.encode()), "text/csv")},
        )

        # Get updated stats
        after = client.get("/api/v1/dashboard/", headers=analyst_headers).json()["stats"]

        assert after["total_logs"] > before["total_logs"]
        assert after["total_alerts"] >= before["total_alerts"]

    def test_dashboard_severity_distribution_is_list(self, client: TestClient, analyst_headers):
        """Dashboard severity distribution returns a list."""
        resp = client.get("/api/v1/dashboard/", headers=analyst_headers)
        data = resp.json()
        assert isinstance(data["severity_distribution"], list)
        for item in data["severity_distribution"]:
            assert "severity" in item
            assert "count" in item
            assert isinstance(item["count"], int)

    def test_dashboard_recent_alerts_limit(self, client: TestClient, analyst_headers):
        """Dashboard returns at most 10 recent alerts."""
        resp = client.get("/api/v1/dashboard/", headers=analyst_headers)
        recent = resp.json()["recent_alerts"]
        assert len(recent) <= 10


class TestDataValidation:
    """Test input validation and error handling."""

    def test_invalid_severity_rejected(self, client: TestClient, analyst_headers):
        """Invalid severity value returns 422."""
        resp = client.post("/api/v1/alerts/", json={
            "title": "Test",
            "description": "Test",
            "severity": "extreme",  # not a valid SeverityLevel
        }, headers=analyst_headers)
        assert resp.status_code == 422

    def test_invalid_uuid_in_path_returns_422(self, client: TestClient, analyst_headers):
        """Invalid UUID in path parameter returns 422."""
        resp = client.get("/api/v1/alerts/not-a-uuid", headers=analyst_headers)
        assert resp.status_code == 422

    def test_nonexistent_resource_returns_404(self, client: TestClient, analyst_headers):
        """Valid UUID for nonexistent resource returns 404."""
        resp = client.get(
            "/api/v1/alerts/00000000-0000-0000-0000-000000000000",
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    def test_empty_log_upload_rejected(self, client: TestClient, analyst_headers):
        """Uploading file with no parseable logs returns 400."""
        empty = b""
        resp = client.post(
            "/api/v1/logs/upload",
            headers=analyst_headers,
            files={"file": ("empty.json", io.BytesIO(empty), "application/json")},
        )
        assert resp.status_code == 400

    def test_register_with_invalid_email(self, client: TestClient):
        """Invalid email format returns 422."""
        resp = client.post("/api/v1/auth/register", json={
            "username": "validuser",
            "email": "not-an-email",
            "password": "ValidPass1",
        })
        assert resp.status_code == 422

    def test_log_ingest_empty_list_rejected(self, client: TestClient, analyst_headers):
        """Ingesting empty log list returns 400."""
        resp = client.post("/api/v1/logs/ingest", json=[], headers=analyst_headers)
        assert resp.status_code == 400
