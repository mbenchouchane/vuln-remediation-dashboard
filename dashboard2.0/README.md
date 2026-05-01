# Vulnerability Management Hub

A centralized platform for orchestrating vulnerability scanning, AI-powered remediation, and result visualization.

## Architecture

```
┌─────────────────────────┐
│  Web Dashboard (UI)     │
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐
│  Backend Orchestrator   │
│  (Flask API)            │
└─┬─────┬─────┬──────┬───┘
  │     │     │      │
  ▼     ▼     ▼      ▼
Nessus  DB   AI    Metasploit
        │   Agent  (Verify)
        ▼
    SQLite
```

## Modules

### 1. Ingestion Module (nessus_connector.py)
- Connects to Nessus REST API
- Lists, launches, and imports scan results
- Normalizes vulnerability data

### 2. Database Layer (database.py)
- SQLite database for scans, vulnerabilities, assets, and remediation cases
- Tracks full lifecycle: scan → vulnerability → remediation → verification

### 3. Orchestration Module (orchestrator.py)
- Business logic and workflow management
- Vulnerability prioritization (Critical → High → Medium → Low)
- AI agent triggering and case management
- Deduplication and asset tracking

### 4. Presentation Layer (frontend/)
- Real-time dashboard with statistics
- Scan history and vulnerability details
- One-click remediation triggering
- Case tracking with status updates

## Setup

### Backend

```bash
cd backend
pip install -r requirements.txt

# Configure Nessus credentials
# Edit config.py or set environment variables:
# NESSUS_URL, NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY

python app.py
```

The API will run on `http://localhost:5000`

### Frontend

```bash
cd frontend
python -m http.server 8080
```

Visit `http://localhost:8080`

## Configuration

Edit `backend/config.py`:

```python
NESSUS_URL = 'https://your-nessus:8834'
NESSUS_ACCESS_KEY = 'your_access_key'
NESSUS_SECRET_KEY = 'your_secret_key'
AI_AGENT_ENDPOINT = 'http://localhost:8000'
```

## Workflow

1. **Import Scan**: Click "Import from Nessus" → Enter Nessus scan ID
2. **View Results**: Dashboard shows vulnerabilities by severity
3. **Prioritize**: System automatically prioritizes Critical/High vulns
4. **Remediate**: Click "Remediate" → AI agent executes patch
5. **Track**: Monitor remediation case status in real-time
6. **Verify**: Optional Metasploit verification (future)

## API Endpoints

- `GET /api/scans` - List all scans
- `GET /api/scans/nessus` - List Nessus scans
- `POST /api/scans/import/<id>` - Import Nessus scan
- `GET /api/scans/<id>` - Get scan details
- `GET /api/scans/<id>/prioritize` - Get prioritized vulnerabilities
- `POST /api/remediate` - Trigger AI remediation
- `GET /api/cases` - List remediation cases
- `GET /api/stats` - Dashboard statistics

## Database Schema

- **scans**: Scan metadata and status
- **vulnerabilities**: CVE details, severity, host, status
- **remediation_cases**: AI agent execution tracking
- **assets**: Host inventory with vulnerability counts

## Next Steps

1. Add Metasploit verification module
2. Implement real-time WebSocket updates
3. Add authentication (JWT/OAuth)
4. Create detailed vulnerability reports
5. Add email notifications for critical findings
6. Implement asset grouping and tagging
