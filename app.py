import os
import re
import sqlite3
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)
DB_PATH = INSTANCE_DIR / "campussignal.db"

app = Flask(__name__, instance_path=str(INSTANCE_DIR))
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-before-deployment")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[])

CATEGORIES = [
    "Fake internship/job offer",
    "Phishing message",
    "Payment or QR scam",
    "Suspicious URL",
    "Other",
]
STATUSES = ["New", "Under Review", "Confirmed", "Inconclusive", "Dismissed"]


def connect_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with connect_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'New',
            indicator TEXT NOT NULL DEFAULT '',
            campaign_key TEXT NOT NULL DEFAULT 'unclustered'
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE SET NULL
        );
        """)
        # Add columns when opening an older starter database created by the first version.
        cols = {r[1] for r in db.execute("PRAGMA table_info(reports)").fetchall()}
        if "indicator" not in cols:
            db.execute("ALTER TABLE reports ADD COLUMN indicator TEXT NOT NULL DEFAULT ''")
        if "campaign_key" not in cols:
            db.execute("ALTER TABLE reports ADD COLUMN campaign_key TEXT NOT NULL DEFAULT 'unclustered'")


def redact_personal_info(text):
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED EMAIL]", text)
    text = re.sub(r"\b(?:\+?\d[\d\s().-]{7,}\d)\b", "[REDACTED PHONE]", text)
    return text


def extract_url(text):
    match = re.search(r"(?:https?://|www\.)[^\s<>\]\[{}\"']+", text, flags=re.I)
    if not match:
        return ""
    candidate = match.group(0).rstrip(".,);!?'\"")
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    try:
        host = urlparse(candidate).hostname or ""
        host = host.lower().strip(".")
        if host and "." in host:
            return host
    except ValueError:
        pass
    return ""


def campaign_for(category, message):
    """Simple explainable MVP grouping: shared URL domain, otherwise normalized category+phrases.
    This is a triage hint only, not a fraud verdict.
    """
    domain = extract_url(message)
    if domain:
        return domain, domain
    words = re.findall(r"[a-z0-9]{4,}", message.lower())
    stop = {"this", "that", "with", "from", "your", "have", "will", "your", "please", "click", "here", "they", "them", "offer", "send", "http", "https", "www"}
    keywords = [w for w in words if w not in stop]
    top = sorted(set(keywords))[:3]
    key = f"{category.lower()}::" + "-".join(top[:2]) if top else category.lower()
    return key, "No domain detected · text-based grouping"


def log_event(db, report_id, action, details):
    db.execute("INSERT INTO audit_events (report_id, action, details) VALUES (?, ?, ?)", (report_id, action, details))


def get_campaigns(db):
    rows = db.execute("""
        SELECT campaign_key, COUNT(*) AS report_count,
               MIN(created_at) AS first_seen, MAX(created_at) AS last_seen,
               SUM(CASE WHEN status IN ('New', 'Under Review') THEN 1 ELSE 0 END) AS pending_count,
               GROUP_CONCAT(DISTINCT category) AS categories
        FROM reports
        GROUP BY campaign_key
        ORDER BY report_count DESC, last_seen DESC
    """).fetchall()
    campaigns = []
    for row in rows:
        if row["campaign_key"] == "unclustered":
            continue
        campaigns.append(dict(row))
    return campaigns


@app.route("/")
def dashboard():
    with connect_db() as db:
        total = db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        pending = db.execute("SELECT COUNT(*) FROM reports WHERE status IN ('New','Under Review')").fetchone()[0]
        reviewed = db.execute("SELECT COUNT(*) FROM reports WHERE status IN ('Confirmed','Inconclusive','Dismissed')").fetchone()[0]
        campaign_count = db.execute("SELECT COUNT(DISTINCT campaign_key) FROM reports WHERE campaign_key != 'unclustered'").fetchone()[0]
        recent = db.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 6").fetchall()
        by_status = db.execute("SELECT status, COUNT(*) AS n FROM reports GROUP BY status").fetchall()
        by_category = db.execute("SELECT category, COUNT(*) AS n FROM reports GROUP BY category ORDER BY n DESC").fetchall()
        campaigns = get_campaigns(db)[:5]
        events = db.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 5").fetchall()
    return render_template("dashboard.html", total=total, pending=pending, reviewed=reviewed,
                           campaign_count=campaign_count, recent=recent, by_status=by_status,
                           by_category=by_category, campaigns=campaigns, events=events)


@app.route("/report/new")
def new_report():
    return render_template("report_new.html", categories=CATEGORIES)


@app.route("/report", methods=["POST"])
@limiter.limit("10 per minute")
def submit_report():
    category = request.form.get("category", "").strip()
    message = request.form.get("message", "").strip()
    if category not in CATEGORIES:
        flash("Choose a valid report category.", "error")
        return redirect(url_for("new_report"))
    if not message or len(message) > 3000:
        flash("Description must contain between 1 and 3,000 characters.", "error")
        return redirect(url_for("new_report"))
    safe_message = redact_personal_info(message)
    campaign_key, indicator = campaign_for(category, safe_message)
    with connect_db() as db:
        cur = db.execute("INSERT INTO reports (category, message, indicator, campaign_key) VALUES (?, ?, ?, ?)",
                          (category, safe_message, indicator, campaign_key))
        report_id = cur.lastrowid
        log_event(db, report_id, "REPORT_SUBMITTED", f"New report submitted under category: {category}")
    flash(f"Report CS-{report_id:04d} submitted for review. It has not been verified as malicious.", "success")
    return redirect(url_for("report_detail", report_id=report_id))


@app.route("/reports")
def reports():
    q = request.args.get("q", "").strip()[:100]
    status = request.args.get("status", "").strip()
    sql = "SELECT * FROM reports WHERE 1=1"
    args = []
    if q:
        sql += " AND (message LIKE ? OR category LIKE ? OR CAST(id AS TEXT) LIKE ?)"
        args.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if status in STATUSES:
        sql += " AND status = ?"
        args.append(status)
    sql += " ORDER BY id DESC"
    with connect_db() as db:
        rows = db.execute(sql, args).fetchall()
    return render_template("reports.html", reports=rows, statuses=STATUSES, q=q, selected_status=status)


@app.route("/reports/<int:report_id>")
def report_detail(report_id):
    with connect_db() as db:
        report = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if report is None:
            abort(404)
        related = db.execute("SELECT * FROM reports WHERE campaign_key = ? AND id != ? ORDER BY id DESC LIMIT 8",
                             (report["campaign_key"], report_id)).fetchall()
        events = db.execute("SELECT * FROM audit_events WHERE report_id = ? ORDER BY id DESC", (report_id,)).fetchall()
    return render_template("report_detail.html", report=report, related=related, events=events, statuses=STATUSES)


@app.route("/reports/<int:report_id>/status", methods=["POST"])
@limiter.limit("30 per minute")
def update_status(report_id):
    status = request.form.get("status", "")
    if status not in STATUSES:
        flash("Invalid status.", "error")
        return redirect(url_for("reports"))
    with connect_db() as db:
        old = db.execute("SELECT status FROM reports WHERE id = ?", (report_id,)).fetchone()
        if old is None:
            abort(404)
        db.execute("UPDATE reports SET status = ? WHERE id = ?", (status, report_id))
        log_event(db, report_id, "STATUS_CHANGED", f"Status changed from {old['status']} to {status}")
    flash("Review status updated and audit event recorded.", "success")
    return redirect(url_for("report_detail", report_id=report_id))


@app.route("/campaigns")
def campaigns_page():
    with connect_db() as db:
        campaigns = get_campaigns(db)
    return render_template("campaigns.html", campaigns=campaigns)


@app.route("/audit")
def audit():
    with connect_db() as db:
        events = db.execute("""SELECT audit_events.*, reports.category
                              FROM audit_events LEFT JOIN reports ON reports.id = audit_events.report_id
                              ORDER BY audit_events.id DESC LIMIT 100""").fetchall()
    return render_template("audit.html", events=events)


@app.route("/health")
def health():
    return {"status": "ok", "application": "CampusSignal"}


init_db()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG", "0") == "1"
    )
