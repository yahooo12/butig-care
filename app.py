from datetime import date, datetime, timedelta
from io import BytesIO
from contextlib import contextmanager
import sqlite3
import os
import socket

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
import qrcode

app = Flask(__name__, static_folder="templates/templates/templates/static", static_url_path="/static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "butig-care-development-key")
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

DATABASE = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "butig_care.db"))
CASE_THRESHOLD = 3


@contextmanager
def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY, name TEXT NOT NULL, password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'resident'
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL,
                resident_name TEXT NOT NULL, disease TEXT NOT NULL, symptoms TEXT NOT NULL,
                status TEXT NOT NULL, barangay TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS interventions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL,
                kind TEXT NOT NULL, notes TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS medicines (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                quantity INTEGER NOT NULL, minimum_stock INTEGER NOT NULL,
                expiry_date TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS medicine_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, medicine_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL, kind TEXT NOT NULL, created_at TEXT NOT NULL
            );
        """)


init_db()


def can_manage_reports():
    return session.get("role") in {"staff", "administrator", "admin"}


def admin_required():
    return session.get("role") == "admin"


def alerts(db):
    threshold_rows = db.execute(
        "SELECT disease, barangay, COUNT(*) AS count FROM reports "
        "WHERE date(created_at) >= date('now', '-30 day') GROUP BY disease, barangay "
        "HAVING count >= ?", (CASE_THRESHOLD,)
    ).fetchall()
    medicine_rows = db.execute("SELECT * FROM medicines ORDER BY expiry_date").fetchall()
    expiry_limit = (date.today() + timedelta(days=30)).isoformat()
    return {
        "case_alerts": threshold_rows,
        "expiry_alerts": [item for item in medicine_rows if item["expiry_date"] <= expiry_limit],
        "low_stock_alerts": [item for item in medicine_rows if item["quantity"] <= item["minimum_stock"]],
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/qr-code")
def qr_code():
    website_url = os.environ.get("PUBLIC_URL", request.url_root).rstrip("/")
    image = qrcode.make(website_url)
    output = BytesIO()
    image.save(output, format="PNG")
    output.seek(0)
    return send_file(output, mimetype="image/png", max_age=300)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        with get_db() as db:
            existing = db.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            flash("An account with that email already exists.", "error")
            return render_template("register.html")

        requested_role = request.form.get("role", "resident")
        role = requested_role if requested_role in {"resident", "administrator", "admin"} else "resident"
        if role in {"administrator", "admin"}:
            invite_code_name = "ADMIN_INVITE_CODE" if role == "admin" else "STAFF_INVITE_CODE"
            invite_code = os.environ.get(invite_code_name)
            if not invite_code or request.form.get("access_code") != invite_code:
                flash("A valid invite code is required for this account type.", "error")
                return render_template("register.html")
        with get_db() as db:
            db.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (email, name, generate_password_hash(password), role))
        session["user"] = name
        session["email"] = email
        session["role"] = role
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and check_password_hash(user["password"], password):
            session["user"] = user["name"]
            session["email"] = email
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Email or password is incorrect.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/report", methods=["GET", "POST"])
def report():
    if "user" not in session:
        return redirect(url_for("login"))
    if session.get("role") in {"staff", "administrator"}:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        resident_name = request.form["resident_name"].strip()
        disease = request.form["disease"].strip()
        symptoms = request.form["symptoms"].strip()
        status = request.form.get("status", "Monitoring")
        barangay = request.form.get("barangay", "Unassigned").strip() or "Unassigned"
        with get_db() as db:
            db.execute(
                "INSERT INTO reports (owner, resident_name, disease, symptoms, status, barangay, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (session["email"], resident_name, disease, symptoms, status, barangay, datetime.now().isoformat(timespec="seconds"))
            )

        return redirect(url_for("dashboard"))

    return render_template("templates/report.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as db:
        scope = "" if can_manage_reports() else " WHERE owner = ?"
        params = () if can_manage_reports() else (session["email"],)
        user_reports = db.execute("SELECT * FROM reports" + scope + " ORDER BY created_at DESC", params).fetchall()
        all_reports = db.execute("SELECT * FROM reports ORDER BY created_at DESC").fetchall()
        barangays = db.execute("SELECT barangay, COUNT(*) AS count FROM reports GROUP BY barangay ORDER BY count DESC").fetchall()
        medicine = db.execute("SELECT * FROM medicines ORDER BY expiry_date").fetchall()
        current_alerts = alerts(db)
    if not admin_required():
        current_alerts["expiry_alerts"] = []
        current_alerts["low_stock_alerts"] = []
    query = request.args.get("q", "").strip().lower()
    visible_reports = [
        report for report in user_reports
        if not query or query in report["resident_name"].lower()
        or query in report["disease"].lower()
        or query in report["symptoms"].lower()
        or query in report["barangay"].lower()
    ]
    active_reports = sum(report["status"] == "Monitoring" for report in user_reports)
    resolved_reports = sum(report["status"] == "Resolved" for report in user_reports)

    return render_template(
        "templates/templates/dashboard.html",
        reports=visible_reports,
        total_reports=len(user_reports),
        active_reports=active_reports,
        resolved_reports=resolved_reports,
        query=request.args.get("q", ""),
        user=session["user"],
        all_reports=all_reports,
        barangays=barangays,
        medicine=medicine,
        alerts=current_alerts,
        is_staff=can_manage_reports(),
        is_admin=admin_required(),
        is_resident=session.get("role") == "resident"
    )


@app.route("/case/<int:report_id>", methods=["GET", "POST"])
def case_detail(report_id):
    if not can_manage_reports():
        return redirect(url_for("dashboard"))
    with get_db() as db:
        if request.method == "POST":
            db.execute("UPDATE reports SET status = ? WHERE id = ?", (request.form["status"], report_id))
            return redirect(url_for("case_detail", report_id=report_id))
        report_row = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        case_interventions = db.execute("SELECT * FROM interventions WHERE report_id = ? ORDER BY created_at DESC", (report_id,)).fetchall()
    if not report_row:
        return redirect(url_for("dashboard"))
    return render_template("templates/case.html", report=report_row, interventions=case_interventions)


@app.route("/case/<int:report_id>/intervention", methods=["POST"])
def add_intervention(report_id):
    if not can_manage_reports():
        return redirect(url_for("login"))
    with get_db() as db:
        db.execute("INSERT INTO interventions (report_id, kind, notes, created_at) VALUES (?, ?, ?, ?)",
                   (report_id, request.form["kind"], request.form.get("notes", "").strip(), datetime.now().isoformat(timespec="seconds")))
    return redirect(url_for("case_detail", report_id=report_id))


@app.route("/medicine", methods=["POST"])
def add_medicine():
    if not admin_required():
        return redirect(url_for("login"))
    with get_db() as db:
        db.execute("INSERT INTO medicines (name, quantity, minimum_stock, expiry_date) VALUES (?, ?, ?, ?)",
                   (request.form["name"].strip(), int(request.form["quantity"]), int(request.form["minimum_stock"]), request.form["expiry_date"]))
    return redirect(url_for("dashboard"))


@app.route("/medicine/<int:medicine_id>/distribute", methods=["POST"])
def distribute_medicine(medicine_id):
    if not admin_required():
        return redirect(url_for("login"))
    quantity = max(0, int(request.form["quantity"]))
    with get_db() as db:
        db.execute("UPDATE medicines SET quantity = MAX(quantity - ?, 0) WHERE id = ?", (quantity, medicine_id))
        db.execute("INSERT INTO medicine_transactions (medicine_id, quantity, kind, created_at) VALUES (?, ?, 'distribution', ?)",
                   (medicine_id, quantity, datetime.now().isoformat(timespec="seconds")))
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    local_ip = socket.gethostbyname(socket.gethostname())
    print(f"Open on this computer: http://127.0.0.1:{port}")
    print(f"Share with phones on the same Wi-Fi: http://{local_ip}:{port}")
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")