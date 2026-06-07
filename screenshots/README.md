# Screenshots

This directory contains screenshots of the ThreatLens AI platform for the portfolio README.

## How to Generate Screenshots

After running `docker compose up --build` and navigating to `http://localhost`:

### Recommended Screenshots

| Filename | Page | Notes |
|----------|------|-------|
| `01-login.png` | `/login` | Dark login page with ThreatLens branding |
| `02-dashboard.png` | `/` | Full dashboard with charts (upload sample logs first) |
| `03-alerts.png` | `/alerts` | Alert table with severity badges |
| `04-alert-detail.png` | `/alerts` | Alert detail modal with MITRE techniques |
| `05-logs-upload.png` | `/logs` | Drag-drop upload zone |
| `06-logs-result.png` | `/logs` | Upload success banner with detection counts |
| `07-incidents.png` | `/incidents` | Incident management table |
| `08-incident-edit.png` | `/incidents` | Edit modal with lifecycle stages |
| `09-reports.png` | `/reports` | Reports page with PDF generation |
| `10-search.png` | `/search` | Search results across logs and alerts |

### Quick Demo Setup

```bash
# 1. Start the platform
docker compose up -d

# 2. Register an admin account at http://localhost/register

# 3. Upload the sample JSON log file (triggers all detections):
curl -X POST http://localhost/api/v1/logs/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@docs/sample-logs/security_events.json"

# 4. Take screenshots — dashboard will show:
#    - Brute Force alerts (Critical/High)
#    - Privilege Escalation alert
#    - Suspicious PowerShell alert
#    - Credential Dumping alert (Critical)
#    - Reconnaissance alert
#    - Impossible Travel alert
```

### Screenshot Tips

- Use a **1440×900** or **1920×1080** browser window for best results
- The dark theme renders best with system dark mode enabled
- Use browser DevTools Device Toolbar to capture consistent viewport sizes
- macOS: `Shift+Cmd+4` for region screenshot
- Linux: `gnome-screenshot -a` or `flameshot gui`
- Windows: `Win+Shift+S` for region screenshot
