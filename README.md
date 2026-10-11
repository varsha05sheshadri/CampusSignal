# CampusSignal — premium cybersecurity dashboard MVP

A Flask + SQLite prototype for collecting suspicious campus messages, organizing reports into candidate groups, reviewing status, and keeping a basic audit trail.

## Features in this version
- Dark, premium security-operations dashboard with live database metrics and a Chart.js report mix chart.
- Report submission form with CSRF protection, size limits, basic email/phone redaction, and rate limiting.
- Reports list with search and status filters.
- Report detail with candidate related reports, extracted URL-domain indicator, and review status workflow.
- Explainable MVP grouping: URL domain first; otherwise a simple category/text key. This is a triage hint, not a fraud classifier.
- Audit events for report submissions and status changes.
- SQLite database created automatically in `instance/campussignal.db`.
- Mobile-responsive layout.

## Run on Windows (PowerShell)

1. Extract this ZIP to a folder such as `Documents\campussignal_solid`.
2. Open that folder in VS Code.
3. In VS Code, choose **Terminal → New Terminal**.
4. Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt terminal and run:

```bat
.venv\Scripts\activate.bat
```

5. Install packages:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

6. Start the app:

```powershell
python app.py
```

7. Open `http://127.0.0.1:5000` in your browser. Health check: `http://127.0.0.1:5000/health`.

## Important limitations before any public deployment
- This is a college-project MVP, not a production security service.
- There is no authentication or role-based authorization yet. Anyone who can access the app can update review statuses and read reports. Keep it local or on a trusted private network.
- Set a strong random `SECRET_KEY` environment variable before deployment; do not use the development fallback.
- Basic regex redaction is imperfect and does not remove every type of personal information. Avoid submitting secrets or unnecessary personal data.
- Campaign grouping is intentionally simple and can create false matches or miss real ones. It must never be treated as proof of malicious activity.
- Chart.js and Google Fonts are loaded from CDNs, so those decorative features need internet access. The core Flask app still serves its own pages locally.

## Next project milestones
1. Add authentication, roles, and moderator-only decisions.
2. Improve indicator normalization and explainable similarity scoring, with synthetic test data and precision/recall evaluation.
3. Add evidence snapshots and stronger audit attribution.
4. Add pytest coverage and Docker/Compose.
