# ── app.py ──────────────────────────────────────────────────────────────────
from flask import (Flask, render_template_string, request, redirect, url_for,
                   session, flash, jsonify, render_template)
from functools import wraps
from datetime import datetime, date, timedelta, time
import random, smtplib, os, io, shutil, tempfile
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy import create_engine, text
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from pytz import timezone
import MySQLdb
import re
from math import ceil
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from dateutil.relativedelta import relativedelta

# 🆕 SLACK IMPORTS
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# 🆕 Import the Blueprint from the new file
from dashboard_blueprint import dashboard_bp 

# ── CONFIG ────────────────────────────────────────────────────────────────
import os
from dotenv import load_dotenv
app = Flask(__name__)

# 🆕 SLACK CONFIGURATION

load_dotenv()

SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")

slack_client = WebClient(token=SLACK_BOT_TOKEN)

def send_slack_alert(user_email, message_text):
    """Sends a direct message to a specific user email."""
    if not SLACK_BOT_TOKEN or "xoxb" not in SLACK_BOT_TOKEN:
        return
    try:
        user_info = slack_client.users_lookupByEmail(email=user_email)
        slack_user_id = user_info['user']['id']
        slack_client.chat_postMessage(channel=slack_user_id, text=message_text)
    except SlackApiError as e:
        # Log error silently or print to console
        print(f"Slack Error for {user_email}: {e}")

# 🆕 HIERARCHY NOTIFICATION SYSTEM
def notify_hierarchy(actor_user, message):
    """Notify Superadmins and relevant Team Admins."""
    try:
        supers = User.query.filter_by(role="superadmin").all()
        for s in supers:
            if s.email:
                send_slack_alert(s.email, f"*[System Alert - SuperAdmin]*\n{message}")

        if actor_user.team:
            admins = User.query.filter(User.role == "admin", User.team == actor_user.team).all()
            for a in admins:
                if a.email:
                    send_slack_alert(a.email, f"*[Team Alert - {actor_user.team}]*\n{message}")
    except Exception as e:
        print(f"Hierarchy Notification Error: {e}")

# ── AUTOMATION / SCHEDULER FUNCTIONS ─────────────────────────────────────

def check_long_running_timers():
    """
    Checks for timers running longer than allowed hours.
    Mon-Fri: > 9 hours
    Sat: > 8 hours
    """
    with app.app_context():
        print("Checking for long-running timers...")
        now = datetime.now()
        today_str = now.strftime("%Y-%m-%d")
        day_idx = now.weekday() # 0=Mon, 6=Sun

        # Sunday: Skip checks
        if day_idx == 6: 
            return

        # Threshold logic: Mon-Fri=9h, Sat=8h
        hours_threshold = 8 if day_idx == 5 else 9
        
        cur = mysql.connection.cursor()
        # Get active timers
        cur.execute("""
            SELECT id, name, project, start_time 
            FROM timesheetlogs 
            WHERE date = %s AND end_time IS NULL
        """, (today_str,))
        active_rows = cur.fetchall()
        cur.close()

        for row in active_rows:
            entry_id, username, project, start_time_str = row
            try:
                st_h, st_m = map(int, start_time_str.split(':'))
                start_dt = now.replace(hour=st_h, minute=st_m, second=0, microsecond=0)
                
                duration = now - start_dt
                duration_hours = duration.total_seconds() / 3600.0

                if duration_hours > hours_threshold:
                    user = User.query.filter_by(username=username).first()
                    if user and user.email:
                        msg = (f"Long Running Timer Alert\n"
                               f"User: {username}\n"
                               f"Project: {project}\n"
                               f"Duration: {int(duration_hours)} hours\n"
                               f"Please verify if this timer should be stopped.")
                        send_slack_alert(user.email, msg)
            except Exception as e:
                print(f"Error checking timer for {username}: {e}")

def check_missing_entries():
    """
    Mon-Fri @ 7 PM: Remind users who haven't logged ANYTHING today.
    """
    with app.app_context():
        print("Checking for missing entries...")
        today_str = datetime.now().strftime("%Y-%m-%d")
        all_users = User.query.all()
        cur = mysql.connection.cursor()
        for user in all_users:
            cur.execute("SELECT COUNT(*) FROM timesheetlogs WHERE name = %s AND date = %s", (user.username, today_str))
            count = cur.fetchone()[0]
            if count == 0:
                msg = (f"Timesheet Submission Reminder\n"
                       f"Hello {user.username}, no entries have been logged for today ({today_str}).\n"
                       f"Please ensure your timesheet is updated before end of day.")
                send_slack_alert(user.email, msg)
        cur.close()

def send_weekly_summary():
    """
    Friday @ 7:30 PM: Send weekly summary.
    """
    with app.app_context():
        print("Sending weekly summaries...")
        today = date.today()
        start_of_week = today - timedelta(days=4)
        all_users = User.query.all()
        cur = mysql.connection.cursor()
        for user in all_users:
            cur.execute("""
                SELECT SUM(total_hours) 
                FROM timesheetlogs 
                WHERE name = %s AND date BETWEEN %s AND %s
            """, (user.username, start_of_week, today))
            result = cur.fetchone()[0]
            total_hrs = float(result) if result else 0.0
            if total_hrs > 0:
                msg = (f"Weekly Hours Summary\n"
                       f"User: {user.username}\n"
                       f"Total Hours (Mon-Fri): {round(total_hrs, 2)}\n"
                       f"Thank you for your contributions this week.")
                send_slack_alert(user.email, msg)
        cur.close()

def send_admin_daily_report():
    """
    Mon-Fri @ 8:00 PM: Admin report.
    """
    with app.app_context():
        print("Sending Admin Report...")
        today_str = datetime.now().strftime("%Y-%m-%d")
        defaulters = []
        all_users = User.query.all()
        cur = mysql.connection.cursor()
        for user in all_users:
            cur.execute("SELECT COUNT(*) FROM timesheetlogs WHERE name = %s AND date = %s", (user.username, today_str))
            if cur.fetchone()[0] == 0:
                defaulters.append(f"{user.username} ({user.team})")
        cur.close()
        
        if defaulters:
            defaulter_list = "\n".join([f"- {d}" for d in defaulters])
            msg = (f"Daily Compliance Report ({today_str})\n"
                   f"The following users have not logged any time today:\n\n"
                   f"{defaulter_list}\n\n"
                   f"Please take necessary action.")
            supers = User.query.filter_by(role="superadmin").all()
            for s in supers:
                send_slack_alert(s.email, msg)

# def refresh_data():
#     print("Refreshing data @07:30 AM IST")

# def create_scheduler():
#     ist = timezone("Asia/Kolkata")
#     sched = BackgroundScheduler(timezone=ist)
#     sched.add_job(refresh_data, CronTrigger(hour=12, minute=22, timezone=ist))
#     sched.add_job(check_long_running_timers, 'interval', minutes=60, timezone=ist)
#     sched.add_job(check_missing_entries, CronTrigger(day_of_week='mon-fri', hour=19, minute=0, timezone=ist))
#     sched.add_job(send_weekly_summary, CronTrigger(day_of_week='fri', hour=19, minute=30, timezone=ist))
#     sched.add_job(send_admin_daily_report, CronTrigger(day_of_week='mon-fri', hour=20, minute=0, timezone=ist))
#     sched.start()
#     return sched

# def maybe_start_scheduler():
#     if not os.getenv("GAE_ENV"): 
#         try:
#             create_scheduler()
#         except Exception as e:
#             app.logger.warning(f"Scheduler not started: {e}")

# @app.route("/")
# def landing():
#     return render_template("landing.html")

# # --- secrets & config from ENV (set in app.yaml) ---
# app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

# DB_HOST = os.getenv("DB_HOST", "34.93.75.171") 
# DB_PORT = int(os.getenv("DB_PORT", "3306"))
# DB_NAME = os.getenv("DB_NAME", "timesheet")
# DB_USER = os.getenv("DB_USER", "appsadmin")
# DB_PASS = os.getenv("DB_PASS", "appsadmin2025")

# DB_URI = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
# app.config["SQLALCHEMY_DATABASE_URI"] = DB_URI
# app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# db = SQLAlchemy(app)

# app.config["MYSQL_HOST"] = DB_HOST
# app.config["MYSQL_USER"] = DB_USER
# app.config["MYSQL_PASSWORD"] = DB_PASS
# app.config["MYSQL_DB"] = DB_NAME
# app.config["MYSQL_PORT"] = DB_PORT
# mysql = MySQL(app)

# engine = create_engine(DB_URI)
# #__________________________App_dep_______________________________

def refresh_data():
    print("Refreshing data @07:30 AM IST")
    # 👉 put your refresh logic here (DB update, cache clear, etc.)

def create_scheduler():
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from pytz import timezone

    ist = timezone("Asia/Kolkata")
    sched = BackgroundScheduler(timezone=ist)
    # every day at 12:22 PM IST
    sched.add_job(refresh_data, CronTrigger(hour=12, minute=22, timezone=ist))
    sched.start()
    return sched

@app.route("/")
def landing():
    return render_template("landing.html")

# ── SECRET KEY ──────────────────────────────────────────────
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

# ── DB CONFIG (Cloud SQL via Unix Socket) ───────────────────
DB_USER = os.environ.get("DB_USER", "appsadmin")
DB_PASS = os.environ.get("DB_PASS", "appsadmin2025")
DB_NAME = os.environ.get("DB_NAME", "timesheet")
INSTANCE_UNIX_SOCKET = os.environ.get(
    "INSTANCE_UNIX_SOCKET",
    "/cloudsql/theta-messenger-459613-p7:asia-south1:appsadmin"
)

# SQLAlchemy URI (pymysql + unix socket)
DB_URI = (
    f"mysql+pymysql://{DB_USER}:{DB_PASS}@/{DB_NAME}"
    f"?unix_socket={INSTANCE_UNIX_SOCKET}"
)

app.config["SQLALCHEMY_DATABASE_URI"] = DB_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Flask-MySQLdb config (if you still use mysql.cursor())
app.config["MYSQL_USER"] = DB_USER
app.config["MYSQL_PASSWORD"] = DB_PASS
app.config["MYSQL_DB"] = DB_NAME
app.config["MYSQL_UNIX_SOCKET"] = INSTANCE_UNIX_SOCKET
mysql = MySQL(app)

# Raw engine (if you use create_engine anywhere)
engine = create_engine(DB_URI)
# #__________________________App_dep________________________________
SMTP_SERVER  = os.getenv("SMTP_SERVER", "smtp.datasolve-analytics.com")
SMTP_PORT    = int(os.getenv("SMTP_PORT", "587"))
WEBMAIL_USER = os.getenv("SMTP_USER", "apps.admin@datasolve-analytics.com")
WEBMAIL_PASS = os.getenv("SMTP_PASS", "datasolve@2025")

# maybe_start_scheduler()

# ── MODELS ────────────────────────────────────────────────────────────────
class UserNotification(db.Model):
    __tablename__ = "user_notifications"
    __table_args__ = {"extend_existing": True}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("desktop_userstable.id"), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_mandatory = db.Column(db.Boolean, default=False)
    date_context = db.Column(db.Date)
    notif_type = db.Column(db.String(50)) 

class QuickTimerPreset(db.Model):
    __tablename__  = "quick_timer_presets"
    __table_args__ = {"extend_existing": True}
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("desktop_userstable.id"), nullable=False)
    name        = db.Column(db.String(100), nullable=False) 
    project     = db.Column(db.String(100), nullable=False)
    process     = db.Column(db.String(100), nullable=False)
    sub_process = db.Column(db.String(100), nullable=False)

class User(db.Model):
    __tablename__  = "desktop_userstable"
    __table_args__ = {"extend_existing": True}
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email    = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(10))
    role     = db.Column(db.Enum("superadmin","admin","user"), default="user")
    team     = db.Column(db.String(100)) 

class ProcessTable(db.Model):
    __tablename__  = "process_table"
    __table_args__ = {"extend_existing": True}
    id          = db.Column(db.Integer, primary_key=True)
    team        = db.Column("Team", db.String(100))
    process     = db.Column("Process", db.String(100))
    sub_process = db.Column("Sub-Process", db.String(100))

class ProjectCode(db.Model):
    __tablename__  = "project_codes"
    __table_args__ = {"extend_existing": True}
    id          = db.Column(db.Integer, primary_key=True)
    code        = db.Column(db.String(100), unique=True, nullable=False)
    status      = db.Column(db.Enum('YTI','WIP','Hold','Closed', name='project_status'),
                             default='WIP', nullable=False)
    team        = db.Column(db.String(100))
    start_date = db.Column(db.Date)
    end_date   = db.Column(db.Date)
    hold_on    = db.Column(db.Date)
    yti_end_date = db.Column(db.Date) 

class UserProjectAssignment(db.Model):
    __tablename__  = "user_project_assignments"
    __table_args__ = {"extend_existing": True}
    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey("desktop_userstable.id"), nullable=False)
    project_id      = db.Column(db.Integer, db.ForeignKey("project_codes.id"), nullable=False)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey("desktop_userstable.id"), nullable=False)
    start_date      = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    end_date        = db.Column(db.Date, nullable=True)
    is_active       = db.Column(db.Boolean, default=True)
    user        = db.relationship("User", foreign_keys=[user_id])
    assigned_by = db.relationship("User", foreign_keys=[assigned_by_id])
    project     = db.relationship("ProjectCode", foreign_keys=[project_id])

class UserProfile(db.Model):
    __tablename__  = "User_Profiles"
    __table_args__ = {"extend_existing": True, "schema": "mainapp"} 
    Email_ID  = db.Column(db.String(255), primary_key=True)
    Image_URL = db.Column(db.Text)
    Designation  = db.Column(db.String(200))
    Team         = db.Column(db.String(100))

with engine.begin() as conn:
    res = conn.execute(text("SHOW COLUMNS FROM desktop_userstable LIKE 'role'")).fetchone()
    if not res:
        conn.execute(text("ALTER TABLE desktop_userstable ADD COLUMN role ENUM('superadmin','admin','user') DEFAULT 'user'"))

import hashlib
def get_profile_for_email(email: str):
    if not email: return None, None, None
    rec = (db.session.query(UserProfile.Designation, UserProfile.Team, UserProfile.Image_URL)
           .filter(UserProfile.Email_ID == email).first())
    if not rec: return None, None, None
    return rec[0], rec[1], rec[2]

def gravatar_url(email: str, size=64, default="identicon"):
    if not email: return ""
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    return f"https://www.gravatar.com/avatar/{h}?s={size}&d={default}&r=g"

@app.context_processor
def inject_gravatar():
    return dict(gravatar_url=gravatar_url)

@app.context_processor
def inject_profile_image():
    img_url = None
    display_name = session.get("username")
    email = session.get("email")
    employee_id = None
    full_name = None
    role = None
    try:
        if not email and display_name:
            u = User.query.filter_by(username=display_name).first()
            email = u.email if u else None
        if email:
            rec = (db.session.query(UserProfile.Email_ID, UserProfile.Image_URL, UserProfile.Designation)
                   .filter(UserProfile.Email_ID == email).first())
            if rec:
                img_url = rec[1]
                full_name = rec[2] or display_name 
            emp_row = db.session.execute(
                text("SELECT Employee_ID, Name FROM mainapp.User_Profiles WHERE Email_ID = :email"),
                {"email": email}
            ).fetchone()
            if emp_row:
                employee_id = emp_row[0]
                full_name = emp_row[1]
        u = User.query.filter_by(username=display_name).first()
        if u: role = u.role
    except Exception as e:
        app.logger.exception("Profile inject failed: %s", e)
    return {
        "user_email": email,
        "profile_image_url": img_url,
        "profile_name": full_name or display_name,
        "employee_id": employee_id,
        "role": role,
    }

def login_required(f):
    @wraps(f)
    def _wrap(*a, **kw):
        if "username" not in session: return redirect("/signin")
        return f(*a, **kw)
    return _wrap

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def _wrap(*a, **kw):
            user = User.query.filter_by(username=session.get("username")).first()
            if user and user.role in roles: return f(*a, **kw)
            flash("⛔ Permission denied")
            return redirect("/home")
        return _wrap
    return decorator

def send_otp(email, otp):
    msg = MIMEMultipart("alternative")
    msg["From"] = f"Logsy App <{WEBMAIL_USER}>"
    msg["To"]   = email
    msg["Subject"] = "Logsy App – Your OTP Verification Code"
    plain = f"OTP: {otp}"
    html  = f"<h3>Your One-Time Password (OTP) for accessing the Logsy App is : [ <b>{otp}</b> ]</h3>"
    msg.attach(MIMEText(plain,"plain"))
    msg.attach(MIMEText(html,"html"))
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
        s.starttls()
        s.login(WEBMAIL_USER, WEBMAIL_PASS)
        s.sendmail(WEBMAIL_USER, email, msg.as_string())

def get_visible_project_codes_for(user: User):
    assignments = (
        UserProjectAssignment.query
        .join(ProjectCode, UserProjectAssignment.project_id == ProjectCode.id)
        .filter(UserProjectAssignment.user_id == user.id,
                UserProjectAssignment.is_active == True,
                ProjectCode.status == "WIP").all()
    )
    return [{
        "code": a.project.code,
        "status": a.project.status,
        "assigned_by": a.assigned_by.username if a.assigned_by else "",
        "start_date": a.start_date.strftime("%Y-%m-%d") if a.start_date else "",
        "end_date": a.end_date.strftime("%Y-%m-%d") if a.end_date else ""
    } for a in assignments]

# ── AUTH ROUTES ───────────────────────────────────────────────────────────
@app.route("/signup", methods=["GET", "POST"])
def register():
    err = None
    if request.method == "POST":
        u = request.form["username"]
        e = request.form["email"]
        p = request.form["password"]
        t = request.form["team"] 

        if User.query.filter((User.username == u) | (User.email == e)).first():
            err = "Username or email already exists"
            return render_template("register.html", err=err)

        code = random.randint(100_000, 999_999)
        new_user = User(
            username=u, email=e, password=generate_password_hash(p),
            verification_code=code, role="user", team=t
        )
        db.session.add(new_user)
        db.session.commit()

        # 🆕 NOTIFY ADMINS (HIERARCHY)
        notify_hierarchy(new_user, f"New User Registration\nName: {u}\nTeam: {t}")

        send_otp(e, code)
        session["pending_email"] = e
        return redirect("/verify")

    return render_template("register.html", err=err)

@app.route("/verify", methods=["GET", "POST"])
def verify():
    err = None
    if request.method == "POST":
        otp_entered = request.form["otp"]
        user = User.query.filter_by(email=session.get("pending_email")).first()
        if user and str(user.verification_code) == otp_entered:
            user.verified = True
            user.verification_code = None
            db.session.commit()
            session.pop("pending_email", None)
            return redirect("/signin")
        err = "Wrong OTP. Please try again."
    return render_template("verify.html", err=err)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    err = None
    ok  = None
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        user  = User.query.filter_by(email=email, verified=True).first()
        if not user:
            err = "No verified account found with that email."
        else:
            reset_code = random.randint(100_000, 999_999)
            user.verification_code = reset_code
            db.session.commit()
            send_otp(email, reset_code)
            session["reset_email"] = email
            return redirect("/reset-password")
    return render_template("forgot_password.html", err=err, ok=ok)

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if "reset_email" not in session: return redirect("/forgot-password")
    err = None
    ok  = None
    if request.method == "POST":
        otp_entered   = request.form["otp"]
        new_password  = request.form["new_password"]
        confirm       = request.form["confirm_password"]
        user = User.query.filter_by(email=session["reset_email"]).first()
        if not user or str(user.verification_code) != otp_entered:
            err = "Invalid OTP."
        elif new_password != confirm:
            err = "Passwords do not match."
        else:
            user.password = generate_password_hash(new_password)
            user.verification_code = None
            db.session.commit()
            session.pop("reset_email", None)
            ok = "Password reset successful. Please log in."
            return redirect("/signin")
    return render_template("reset_password.html", err=err, ok=ok)

@app.route("/signin", methods=["GET","POST"])
def login():
    if request.method=="POST":
        e, p = request.form["email"], request.form["password"]
        user = User.query.filter_by(email=e, verified=True).first()
        if user and check_password_hash(user.password,p):
            session["username"] = user.username 
            session["email"] = user.email 
            session["role"] = user.role
            session["team"] = user.team
            return redirect("/welcome")
        flash("Invalid creds / not verified")
        return redirect("/signin")
    return render_template("login.html")

@app.route("/welcome")
@login_required
def welcome():
    user = User.query.filter_by(username=session["username"]).first()
    return render_template("welcome.html", username=user.username,no_sidebar=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.template_filter("todatetime")
def todatetime(value, fmt="%Y-%m-%d"):
    return datetime.strptime(value, fmt)

# ── DASHBOARD ROUTE ─────────────────────────────────────────────
@app.route("/home", methods=["GET"])
@login_required
def dashboard():
    today = datetime.now().strftime("%Y-%m-%d")
    user = User.query.filter_by(username=session["username"]).first()
    role = user.role
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT name, date, day, project, project_type, team, process, sub_process,
               start_time, end_time, duration, total_hours, project_code, project_type_mc, disease, country, id
        FROM   timesheetlogs
        WHERE  name = %s
        ORDER  BY id DESC
        LIMIT  30
    """, (user.username,))
    entries = cur.fetchall()
    cur.close()

    processed_entries = []
    for row in entries:
        new_row = list(row) 
        for i in range(len(new_row)):
            if isinstance(new_row[i], date):
                new_row[i] = new_row[i].isoformat()
            elif isinstance(new_row[i], timedelta):
                total_seconds = int(new_row[i].total_seconds())
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                new_row[i] = f"{hours:02d}:{minutes:02d}"
        processed_entries.append(new_row)

    team_map = {}
    for row in ProcessTable.query.all():
        team_map.setdefault(row.team, {}).setdefault(row.process, set()).add(row.sub_process)

    team_json = {team: {proc: sorted(list(subs)) for proc, subs in proc_dict.items()} for team, proc_dict in team_map.items()}
    user_project_codes = get_visible_project_codes_for(user)
    raw_presets = QuickTimerPreset.query.filter_by(user_id=user.id).all()
    quick_presets = [{"id": p.id, "name": p.name, "project": p.project, "process": p.process, "sub_process": p.sub_process} for p in raw_presets]
    
    return render_template("dashboard.html", username=user.username, role=role, entries=processed_entries, user_email=user.email, today=today, team_json=team_json, user_project_codes=user_project_codes, user_team=user.team, quick_presets=quick_presets)

def promote_first_user():
    with app.app_context():
        db.create_all()
        first = User.query.order_by(User.id).first()
        if first and first.role == "user":
            first.role = "superadmin"
            db.session.commit()

@app.route("/api/process-master")
@login_required
def process_master():
    data = [dict(id=p.id, team=p.team, process=p.process, sub_process=p.sub_process) for p in ProcessTable.query.all()]
    return jsonify(data)

@app.route("/admin/usermanagement", methods=["GET", "POST"])
@role_required("superadmin")
def manage_users():
    if request.method == "POST":
        uid       = request.form["uid"]
        new_role  = request.form["role"]
        new_team  = request.form["team"]
        target = User.query.get(uid)
        if target:
            old_role = target.role # 🆕 Capture old role
            target.role = new_role
            target.team = new_team
            db.session.commit()
            flash(f"{target.username}'s role updated", "success")
            
            # 🆕 SLACK NOTIFICATION: Notify User about Role Change
            if old_role != new_role:
                msg = f"Role Update Notification\nYour role has been updated to {new_role.upper()} (Team: {new_team})."
                send_slack_alert(target.email, msg)
        else:
            flash("User not found", "error")
    users = User.query.all()
    emails = [u.email for u in users]
    email_img_map = {}
    if emails:
        rows = (db.session.query(UserProfile.Email_ID, UserProfile.Image_URL).filter(UserProfile.Email_ID.in_(emails)).all())
        email_img_map = {e: url for e, url in rows if url}
    current = User.query.filter_by(username=session["username"]).first()
    return render_template("users.html", users=users, username=current.username, role=current.role, email_img_map=email_img_map)

@app.route("/process&subprocess", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def manage_process():
    me = User.query.filter_by(username=session["username"]).first()
    is_super = (me.role == "superadmin")
    if request.method == "POST":
        team = request.form["team"].strip()
        process = request.form["process"].strip()
        sub_proc = request.form["sub"].strip()
        if team and process and sub_proc:
            db.session.add(ProcessTable(team=team, process=process, sub_process=sub_proc))
            db.session.commit()
            flash("Row added", "ok")
        else:
            flash("Required fields missing", "error")
    if is_super: all_rows = ProcessTable.query.all()
    else: all_rows = ProcessTable.query.filter_by(team=me.team).all()
    teams = sorted({row.team for row in all_rows})
    processes = sorted({row.process for row in all_rows})
    sub_processes = sorted({row.sub_process for row in all_rows})
    selected_team = request.args.get("filter_team") or ''
    selected_process = request.args.get("filter_process") or ''
    selected_sub = request.args.get("filter_sub") or ''
    q = ProcessTable.query
    if not is_super: q = q.filter_by(team=me.team)
    if selected_team: q = q.filter_by(team=selected_team)
    if selected_process: q = q.filter_by(process=selected_process)
    if selected_sub: q = q.filter_by(sub_process=selected_sub)
    rows = q.order_by(ProcessTable.id).all()
    return render_template("process.html", rows=rows, username=me.username, role=me.role, teams=teams, processes=processes, sub_processes=sub_processes, selected_team=selected_team, selected_process=selected_process, selected_sub=selected_sub)

@app.route('/admin/delete_process_row', methods=['POST'])
@role_required("superadmin", "admin")
def delete_process_row():
    data = request.get_json()
    row = ProcessTable.query.get(data['id'])
    if not row: return jsonify(success=False, error="Row not found")
    me = User.query.filter_by(username=session["username"]).first()
    if me.role != "superadmin" and row.team != me.team: return jsonify(success=False, error="Permission denied")
    db.session.delete(row)
    db.session.commit()
    return jsonify(success=True)

@app.route('/update_process_row', methods=['POST'])
@role_required("superadmin", "admin")
def update_process_row():
    data = request.get_json()
    row = ProcessTable.query.get(data['id'])
    if not row: return jsonify(success=False, error="Row not found")
    me = User.query.filter_by(username=session["username"]).first()
    if me.role != "superadmin" and row.team != me.team: return jsonify(success=False, error="Permission denied")
    row.team = data['team']
    row.process = data['process']
    row.sub_process = data['sub_process']
    db.session.commit()
    return jsonify(success=True)

@app.route("/allocations", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def admin_project_codes():
    me = User.query.filter_by(username=session["username"]).first()
    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        status = (request.form.get("status") or "WIP").strip()
        team = me.team
        if not code:
            flash("Code required", "error")
            return redirect(url_for("admin_project_codes"))
        existing = ProjectCode.query.filter_by(code=code).first()
        today = date.today()
        if existing:
            prev_status = existing.status
            existing.status = status
            if not existing.team and team: existing.team = team
            if status == "WIP" and not existing.start_date: existing.start_date = today
            if status == "Closed" and not existing.end_date: existing.end_date = today
            if status == "Hold" and not existing.hold_on: existing.hold_on = today
            if prev_status == "Hold" and status != "Hold": existing.hold_on = None
            db.session.commit()
            flash("Code updated", "success")
        else:
            pc = ProjectCode(code=code, status=status, team=team)
            if status == "WIP": pc.start_date = today
            elif status == "Closed": pc.end_date = today
            elif status == "Hold": pc.hold_on = today
            db.session.add(pc)
            db.session.commit()
            flash("Code created", "success")
        return redirect(url_for("admin_project_codes"))
    if me.role == "superadmin": q = ProjectCode.query
    else: q = ProjectCode.query.filter_by(team=me.team) if me.team else ProjectCode.query
    rows = q.order_by(ProjectCode.code.asc()).all()
    return render_template("project_codes.html", rows=rows, username=me.username, role=me.role, team=me.team)

@app.route("/assign-projects", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def assign_projects():
    me = User.query.filter_by(username=session["username"]).first()
    users = User.query.filter_by(team=me.team).all() if me.team else User.query.all()
    codes = ProjectCode.query.filter_by(team=me.team).all() if me.team else ProjectCode.query.all()

    if request.method == "POST":
        action = request.form.get("action", "")
        pid = request.form.get("project_id")
        if not pid:
            flash("Select a project first.", "error")
            return redirect(url_for("assign_projects"))

        project_obj = ProjectCode.query.get(int(pid))
        project_name = project_obj.code if project_obj else "Unknown Project"

        if action in ("bulk_assign", "bulk_end"):
            user_ids = request.form.getlist("user_ids")
            if not user_ids:
                flash("Select at least one user.", "error")
                return redirect(url_for("assign_projects"))

            assigned_count = 0
            ended_count = 0

            for uid in user_ids:
                target_user = User.query.get(int(uid))
                if not target_user: continue
                if me.team and target_user.team != me.team: continue

                if action == "bulk_assign":
                    exists = (UserProjectAssignment.query.filter_by(user_id=target_user.id, project_id=int(pid), is_active=True).first())
                    if exists: continue
                    db.session.add(UserProjectAssignment(user_id=target_user.id, project_id=int(pid), assigned_by_id=me.id, start_date=datetime.utcnow().date(), is_active=True))
                    assigned_count += 1
                    
                    # 🆕 SLACK: Direct DM + Hierarchy
                    send_slack_alert(target_user.email, f"Project Assignment Notification\nYou have been assigned to project {project_name} by {me.username}.")
                    notify_hierarchy(target_user, f"User {target_user.username} was assigned to project {project_name} by {me.username}.")

                elif action == "bulk_end":
                    exists = (UserProjectAssignment.query.filter_by(user_id=target_user.id, project_id=int(pid), is_active=True).first())
                    if exists:
                        exists.is_active = False
                        exists.end_date  = datetime.utcnow().date()
                        ended_count += 1
                        
                        # 🆕 SLACK: Direct DM + Hierarchy
                        send_slack_alert(target_user.email, f"Project Assignment Ended\nYour assignment for project {project_name} has been ended by {me.username}.")
                        notify_hierarchy(target_user, f"User {target_user.username} was removed from project {project_name} by {me.username}.")

            db.session.commit()
            if action == "bulk_assign": flash(f"Assigned to {assigned_count} user(s).", "success")
            else: flash(f"Ended for {ended_count} user(s).", "success")
            return redirect(url_for("assign_projects"))

        user_id  = request.form.get("user_id")
        code_id  = request.form.get("project_id")
        action   = request.form.get("action", "assign")
        if user_id and code_id:
            target_user = User.query.get(int(user_id))
            code = ProjectCode.query.get(int(code_id))
            if not target_user or not code:
                flash("Invalid user or code", "error")
                return redirect(url_for("assign_projects"))
            if me.team and target_user.team != me.team:
                flash("You can manage only your team's users.", "error")
                return redirect(url_for("assign_projects"))

            if action == "assign":
                existing = (UserProjectAssignment.query.filter_by(user_id=target_user.id, project_id=code.id, is_active=True).first())
                if existing: flash("Already assigned", "info")
                else:
                    db.session.add(UserProjectAssignment(user_id=target_user.id, project_id=code.id, assigned_by_id=me.id, start_date=datetime.utcnow().date(), is_active=True))
                    db.session.commit()
                    flash(f"Assigned {code.code} to {target_user.username}", "success")
                    
                    # 🆕 SLACK
                    send_slack_alert(target_user.email, f"Project Assignment Notification\nYou have been assigned to project {code.code} by {me.username}.")
                    notify_hierarchy(target_user, f"User {target_user.username} was assigned to project {code.code} by {me.username}.")

            elif action == "end":
                existing = (UserProjectAssignment.query.filter_by(user_id=target_user.id, project_id=code.id, is_active=True).first())
                if not existing: flash("No active assignment found", "info")
                else:
                    existing.is_active = False
                    existing.end_date  = datetime.utcnow().date()
                    db.session.commit()
                    flash(f"Ended {code.code} for {target_user.username}", "success")
                    
                    # 🆕 SLACK
                    send_slack_alert(target_user.email, f"Project Assignment Ended\nYour assignment for project {code.code} has been ended by {me.username}.")
                    notify_hierarchy(target_user, f"User {target_user.username} was removed from project {code.code} by {me.username}.")

            return redirect(url_for("assign_projects"))

    active = (UserProjectAssignment.query.join(User, UserProjectAssignment.user_id == User.id).join(ProjectCode, UserProjectAssignment.project_id == ProjectCode.id).filter(User.team == me.team if me.team else True).filter(UserProjectAssignment.is_active == True).all())
    assigned_map = {}
    for a in active: assigned_map.setdefault(str(a.project_id), []).append(a.user_id)
    return render_template("assign_projects.html", users=users, codes=codes, active=active, assigned_map=assigned_map, username=me.username, role=me.role)

@app.route("/api/my-project-codes")
@login_required
def my_project_codes():
    user = User.query.filter_by(username=session["username"]).first()
    return jsonify(get_visible_project_codes_for(user))

PROJECT_SPLIT_TEAMS = {"MCTeam", "IPTeam", "AnalyticsTeam", "BDTeam", "MRTeam"}
def parse_project_fields(team: str, project: str):
    if not project: return "", "", "", ""
    proj = project.strip()
    if team not in PROJECT_SPLIT_TEAMS or "_" not in proj: return proj, "", "", ""
    parts = re.split(r"_+", proj)
    while len(parts) < 4: parts.append("")
    return parts[0], parts[1], parts[2], parts[3]

@app.route("/start", methods=["POST"])
@login_required
def start():
    name = session["username"]
    date_str = request.form["date"]
    team = request.form["team"]
    project = request.form["project"]
    process = request.form["process"]
    sub_proc = request.form["sub_process"]
    start_time = request.form["start_time"]
    end_time = request.form["end_time"]

    pc = ProjectCode.query.filter_by(code=project).first()
    proj_type_db = pc.status if pc else "WIP"
    current_user = User.query.filter_by(username=name).first()
    allowed = {p["code"] for p in get_visible_project_codes_for(current_user)}
    if project not in allowed:
        flash("Selected project is not assigned to you or not WIP.", "error")
        return redirect("/home")

    day = datetime.strptime(date_str, "%Y-%m-%d").strftime("%A")
    cur = mysql.connection.cursor()
    try:
        cur.execute("""SELECT COUNT(*) FROM timesheetlogs WHERE name = %s AND date = %s AND start_time <= %s AND end_time >= %s""", (name, date_str, end_time, start_time))
        if cur.fetchone()[0] > 0:
            flash(f"Error: Time ({start_time} - {end_time}) overlaps.", "error")
            cur.close()
            return redirect("/home")
    except Exception as e:
        app.logger.error(f"Error: {e}")
        flash("An error occurred.", "error")
        cur.close()
        return redirect("/home")

    try:
        start_dt = datetime.strptime(start_time, "%H:%M")
        end_dt = datetime.strptime(end_time, "%H:%M")
        dur = end_dt - start_dt
        seconds = int(dur.total_seconds())
        if seconds < 0: seconds += 24 * 3600
    except ValueError:
        flash("Invalid time format.", "error")
        cur.close()
        return redirect("/home")

    hours, remainder = divmod(seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    duration_str = f"{hours:02d}:{minutes:02d}"
    total_h = round(seconds / 3600, 2)
    proj_code, proj_type_mc, disease, country = parse_project_fields(team, project)

    try:
        cur.execute("""
            INSERT INTO timesheetlogs (name, date, day, team, project, project_type, process, sub_process, start_time, end_time, duration, total_hours, project_code, project_type_mc, disease, country)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (name, date_str, day, team, project, proj_type_db, process, sub_proc, start_time, end_time, duration_str, total_h, proj_code, proj_type_mc, disease, country))
        mysql.connection.commit()
        
        # 🆕 NOTIFY HIERARCHY
        notify_hierarchy(current_user, f"Manual Time Entry Created\nUser: {name}\nProject: {project}\nProcess: {process}\nTime: {start_time} - {end_time}")

    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f"Error: {e}")
        flash(f"Database error: {e}", "error")
    finally:
        cur.close()
    return redirect("/home")

def format_time_for_input(val):
    if val is None: return ""
    if isinstance(val, time): return f"{val.hour:02d}:{val.minute:02d}"
    if isinstance(val, datetime): return f"{val.hour:02d}:{val.minute:02d}"
    s = str(val).strip()
    if not s: return ""
    try:
        parts = s.split(":")
        h = int(parts[0])
        m = int(parts[1]) if len(parts) > 1 else 0
        return f"{h:02d}:{m:02d}"
    except: return s[:5] if len(s) >= 5 else s

def safe_parse_project_fields(team, project):
    try: return parse_project_fields(team, project)
    except NameError: return (None, None, None, None)

def _strip_param(url, param_name="editing_id"):
    try:
        pu = urlparse(url)
        q = [(k, v) for (k, v) in parse_qsl(pu.query, keep_blank_values=True) if k != param_name]
        return urlunparse((pu.scheme, pu.netloc, pu.path, pu.params, urlencode(q), pu.fragment))
    except: return url

@app.route("/update-entry", methods=["POST"])
@login_required
def update_entry():
    entry_id = (request.form.get("entry_id") or "").strip()
    project = (request.form.get("project") or "").strip()
    process = (request.form.get("process") or "").strip()
    sub_proc = (request.form.get("sub_process") or "").strip()
    start_time = (request.form.get("start_time") or "").strip()
    end_time = (request.form.get("end_time") or "").strip()
    ptmc_manual = (request.form.get("project_type_mc") or "").strip()
    next_url = (request.form.get("next") or request.referrer or url_for("view_team_logs"))

    current_user = User.query.filter_by(username=session.get("username")).first()
    if not current_user:
        flash("Not authenticated.", "error")
        return redirect(url_for("view_team_logs"))

    cur = mysql.connection.cursor()
    try:
        cur.execute("""SELECT name, date, team, project_code, project_type_mc, disease, country, project FROM timesheetlogs WHERE id=%s""", (entry_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            flash("Entry not found.", "error")
            return redirect(url_for("view_team_logs"))
        entry_name, entry_date, entry_team, old_proj_code, old_proj_type_mc, old_disease, old_country, old_project = row
        if current_user.role != "superadmin" and current_user.team != entry_team:
            cur.close()
            flash("Permission denied.", "error")
            return redirect(url_for("view_team_logs"))
    except Exception as e:
        cur.close()
        flash(f"DB error: {e}", "error")
        return redirect(url_for("view_team_logs"))

    if not (project and process and sub_proc and start_time and end_time):
        cur.close()
        flash("All fields required.", "error")
        return redirect(url_for("view_team_logs", editing_id=entry_id))

    def parse_hms(s):
        parts = s.split(":")
        h, m = int(parts[0]), int(parts[1])
        return h, m, 0
    def minutes_since_midnight(h, m, s=0): return h * 60 + m + (s // 60)
    def hhmm_from_minutes(total_mins): return f"{total_mins // 60:02d}:{total_mins % 60:02d}"

    project_for_lookup = project if project else old_project
    try:
        new_proj_code, new_proj_type_mc, new_disease, new_country = safe_parse_project_fields(entry_team, project_for_lookup)
        proj_code = new_proj_code if new_proj_code else old_proj_code
        proj_type_mc = new_proj_type_mc if new_proj_type_mc else old_proj_type_mc
        disease = new_disease if new_disease else old_disease
        country = new_country if new_country else old_country
    except:
        proj_code, proj_type_mc, disease, country = old_proj_code, old_proj_type_mc, old_disease, old_country
    if ptmc_manual: proj_type_mc = ptmc_manual

    try:
        cur.execute("""SELECT COUNT(*) FROM timesheetlogs WHERE name = %s AND date = %s AND id != %s AND start_time < %s AND end_time > %s""", (entry_name, entry_date, entry_id, end_time, start_time))
        if cur.fetchone()[0] > 0:
            flash(f"Error: Overlap detected.", "error")
            return redirect(url_for("view_team_logs", editing_id=entry_id))
        
        sh, sm, ss = parse_hms(start_time)
        eh, em, es = parse_hms(end_time)
        delta_min = (minutes_since_midnight(eh, em, es) - minutes_since_midnight(sh, sm, ss)) % (24 * 60)
        duration_hhmm = hhmm_from_minutes(delta_min)
        total_hours = round(delta_min / 60.0, 2)
    except Exception as e:
        cur.close() 
        flash(f"Time error: {e}", "error")
        return redirect(url_for("view_team_logs", editing_id=entry_id))

    try:
        # 💡 FIX: Removed AND team=%s check to allow Admin editing even if team string mismatches or is NULL.
        # Permission was already checked above via Python logic.
        where_clause = "WHERE id=%s"
        where_params = (entry_id,)
        
        params = [project, process, sub_proc, start_time, end_time, duration_hhmm, total_hours, proj_code, proj_type_mc, disease, country] + list(where_params)
        cur.execute(f"""UPDATE timesheetlogs SET project=%s, process=%s, sub_process=%s, start_time=%s, end_time=%s, duration=%s, total_hours=%s, project_code=%s, project_type_mc=%s, disease=%s, country=%s {where_clause}""", tuple(params))
        mysql.connection.commit()
        
        # 🆕 NOTIFY HIERARCHY (Log Update)
        notify_hierarchy(current_user, f"Log Entry Updated\nEditor: {current_user.username}\nProject: {project}")

    except Exception as e:
        mysql.connection.rollback()
        flash(f"DB error: {e}", "error")
        return redirect(url_for("view_team_logs", editing_id=entry_id))
    finally:
        cur.close()

    next_url = _strip_param(next_url, "editing_id")
    flash("Entry updated successfully!", "success")
    return redirect(next_url)

@app.route("/team-logs", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def view_team_logs():
    current_user = User.query.filter_by(username=session["username"]).first()
    team = current_user.team
    is_post = (request.method == "POST")
    
    filter_user = (request.form.get("username") if is_post else request.args.get("username")) or None
    filter_project = (request.form.get("project") if is_post else request.args.get("project")) or None
    filter_process = (request.form.get("process") if is_post else request.args.get("process")) or None
    filter_sub_process = (request.form.get("sub_process") if is_post else request.args.get("sub_process")) or None
    filter_date = (request.form.get("date") if is_post else request.args.get("date")) or None
    filter_start_date = (request.form.get("start_date") if is_post else request.args.get("start_date")) or None
    filter_end_date = (request.form.get("end_date") if is_post else request.args.get("end_date")) or None
    filter_team = (request.form.get("team") if is_post else request.args.get("team")) or None
    editing_id = request.args.get("editing_id")

    def _to_int(x, d): 
        try: return int(x)
        except: return d
    page = _to_int((request.form.get("page") or request.args.get("page")), 1)
    per_page = _to_int((request.form.get("per_page") or request.args.get("per_page")), 50)
    if per_page not in {50, 100, 200, 500, 1000}: per_page = 50
    if page < 1: page = 1

    where_sql = []
    values = []
    if current_user.role != 'superadmin':
        where_sql.append("team = %s"); values.append(team)
    if filter_user: where_sql.append("name = %s"); values.append(filter_user)
    if filter_team and current_user.role == 'superadmin': where_sql.append("team = %s"); values.append(filter_team)
    if filter_project: where_sql.append("project = %s"); values.append(filter_project)
    if filter_process: where_sql.append("process = %s"); values.append(filter_process)
    if filter_sub_process: where_sql.append("sub_process = %s"); values.append(filter_sub_process)
    if filter_date: where_sql.append("date = %s"); values.append(filter_date)
    elif filter_start_date or filter_end_date:
        if filter_start_date: where_sql.append("date >= %s"); values.append(filter_start_date)
        if filter_end_date: where_sql.append("date <= %s"); values.append(filter_end_date)
        
    where_clause = ""
    if where_sql: where_clause = "WHERE " + " AND ".join(where_sql)

    cur = mysql.connection.cursor()
    count_q = f"SELECT COUNT(*) FROM timesheetlogs {where_clause}"
    cur.execute(count_q, tuple(values))
    total_rows = cur.fetchone()[0] if cur.rowcount != -1 else 0
    total_pages = max(1, ceil(total_rows / per_page)) if total_rows else 1
    if page > total_pages: page = total_pages
    offset = (page - 1) * per_page

    select_q = f"""SELECT name, date, day, project, team, process, sub_process, start_time, end_time, duration, total_hours, id FROM timesheetlogs {where_clause} ORDER BY id DESC LIMIT %s OFFSET %s"""
    cur.execute(select_q, tuple(values + [per_page, offset]))
    raw_logs = cur.fetchall()

    teams = []
    if current_user.role != 'superadmin':
        cur.execute("SELECT DISTINCT project FROM timesheetlogs WHERE team = %s", (team,))
        projects = [r[0] for r in cur.fetchall() if r[0]]
        cur.execute("SELECT DISTINCT process FROM timesheetlogs WHERE team = %s", (team,))
        processes = [r[0] for r in cur.fetchall() if r[0]]
        cur.execute("SELECT DISTINCT sub_process FROM timesheetlogs WHERE team = %s", (team,))
        sub_processes = [r[0] for r in cur.fetchall() if r[0]]
        users = User.query.filter_by(team=team).all()
    else:
        cur.execute("SELECT DISTINCT project FROM timesheetlogs"); projects = [r[0] for r in cur.fetchall() if r[0]]
        cur.execute("SELECT DISTINCT process FROM timesheetlogs"); processes = [r[0] for r in cur.fetchall() if r[0]]
        cur.execute("SELECT DISTINCT sub_process FROM timesheetlogs"); sub_processes = [r[0] for r in cur.fetchall() if r[0]]
        cur.execute("SELECT DISTINCT team FROM timesheetlogs WHERE team IS NOT NULL AND team != ''"); teams = [r[0] for r in cur.fetchall() if r[0]]
        users = User.query.all()
    cur.close()

    logs = []
    for row in raw_logs:
        row = list(row)
        row[7] = format_time_for_input(row[7])
        row[8] = format_time_for_input(row[8])
        logs.append(row)

    return render_template("team_logs.html", logs=logs, users=users, projects=projects, processes=processes, sub_processes=sub_processes, teams=teams, username=current_user.username, role=current_user.role, editing_id=editing_id, page=page, per_page=per_page, total_pages=total_pages, total_rows=total_rows)

@app.route("/admin/delete-log/<int:log_id>", methods=["POST"])
@role_required("superadmin")
def delete_log(log_id):
    current_user = User.query.filter_by(username=session["username"]).first()
    if not current_user or current_user.role != 'superadmin':
        flash("Permission denied.", "error")
        return redirect(url_for('view_team_logs'))
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM timesheetlogs WHERE id = %s", (log_id,))
        mysql.connection.commit()
        cur.close()
        flash("Log deleted.", "success")
        notify_hierarchy(current_user, f"Log Entry Deleted\nID: {log_id}\nDeleted by Superadmin {current_user.username}.")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('view_team_logs'))

@app.post("/project-codes/update-status", endpoint="update_project_status")
@role_required("superadmin", "admin")
def update_project_status():
    me = User.query.filter_by(username=session["username"]).first()
    data = request.get_json(silent=True) or {}
    rec_id = data.get("id")
    new_status = (data.get("status") or "").strip()
    if not rec_id or new_status not in {"WIP","YTI","Hold","Closed"}: return jsonify(ok=False, message="Invalid"), 400
    rec = ProjectCode.query.get(rec_id)
    if not rec: return jsonify(ok=False, message="Not found"), 404
    if me.role != "superadmin":
        if me.team and rec.team and rec.team != me.team: return jsonify(ok=False, message="Forbidden"), 403
    today = date.today()
    prev_status = rec.status # 🆕 Capture old status
    rec.status = new_status
    if new_status == "WIP" and not rec.start_date: rec.start_date = today
    if new_status == "Closed" and not rec.end_date: rec.end_date = today
    if new_status == "Hold" and not rec.hold_on: rec.hold_on = today
    if prev_status == "Hold" and new_status != "Hold": rec.hold_on = None
    if prev_status == "YTI" and new_status != "YTI" and not rec.yti_end_date: rec.yti_end_date = today
    db.session.commit()

    # 🆕 SLACK NOTIFICATION: Notify assigned users if status changes
    if prev_status != new_status:
        assignments = UserProjectAssignment.query.filter_by(project_id=rec.id, is_active=True).all()
        for assign in assignments:
            user_to_notify = User.query.get(assign.user_id)
            if user_to_notify and user_to_notify.email:
                msg = f"Project Status Update\nProject: {rec.code}\nNew Status: {new_status}\nUpdated by: {me.username}"
                send_slack_alert(user_to_notify.email, msg)

    return jsonify(ok=True, id=rec.id, status=rec.status, start_date=rec.start_date.isoformat() if rec.start_date else "", end_date=rec.end_date.isoformat() if rec.end_date else "", hold_on=rec.hold_on.isoformat() if rec.hold_on else "", yti_end_date=rec.yti_end_date.isoformat() if rec.yti_end_date else ""), 200

@app.route("/admin/user-access", methods=["GET", "POST"], endpoint="user_access")
@role_required("superadmin", "admin")
def user_access():
    me = User.query.filter_by(username=session["username"]).first()
    users_q = User.query
    codes_q = ProjectCode.query.filter(ProjectCode.status.in_(["WIP", "YTI", "Hold"]))
    if me.role != "superadmin" and me.team:
        users_q = users_q.filter_by(team=me.team)
        codes_q = codes_q.filter_by(team=me.team)
    users = users_q.order_by(User.username.asc()).all()
    codes = codes_q.order_by(ProjectCode.code.asc()).all()
    selected_user_id = request.values.get("user_id", type=int)
    selected_user = User.query.get(selected_user_id) if selected_user_id else (users[0] if users else None)

    if request.method == "POST" and selected_user:
        action = request.form.get("action")
        code_ids = request.form.getlist("code_ids")
        code_ids = [int(cid) for cid in code_ids]
        added, removed = 0, 0
        if action == "add":
            for cid in code_ids:
                already = (UserProjectAssignment.query.filter_by(user_id=selected_user.id, project_id=cid, is_active=True).first())
                if not already:
                    db.session.add(UserProjectAssignment(user_id=selected_user.id, project_id=cid, assigned_by_id=me.id, start_date=datetime.utcnow().date(), is_active=True))
                    added += 1
                    # Notification
                    pc = ProjectCode.query.get(cid)
                    notify_hierarchy(selected_user, f"Project Assignment Notification\nUser: {selected_user.username}\nAssigned to Project: {pc.code}\nBy: {me.username}")
            db.session.commit()
            flash(f"Added {added} projects.", "success")
        elif action == "remove":
            rows = (UserProjectAssignment.query.filter(UserProjectAssignment.user_id == selected_user.id, UserProjectAssignment.project_id.in_(code_ids), UserProjectAssignment.is_active == True).all())
            for r in rows:
                r.is_active = False
                r.end_date = datetime.utcnow().date()
                removed += 1
                notify_hierarchy(selected_user, f"Project Assignment Ended\nUser: {selected_user.username}\nRemoved from Project: {r.project.code}\nBy: {me.username}")
            db.session.commit()
            flash(f"Removed {removed} projects.", "success")
        return redirect(url_for("user_access", user_id=selected_user.id))

    assigned_ids = set()
    assigned_rows = []
    if selected_user:
        rows = (UserProjectAssignment.query.join(ProjectCode, UserProjectAssignment.project_id == ProjectCode.id).filter(UserProjectAssignment.user_id == selected_user.id, UserProjectAssignment.is_active == True).order_by(ProjectCode.code.asc()).all())
        for r in rows:
            assigned_ids.add(r.project_id)
            assigned_rows.append(r)
    emails = [u.email for u in users if u.email]
    email_to_img = {}
    if emails:
        rows = (db.session.query(UserProfile.Email_ID, UserProfile.Image_URL).filter(UserProfile.Email_ID.in_(emails)).all())
        email_to_img = {e: url for e, url in rows if url}
    fallback_img = url_for('static', filename='img/avatar-default.png')
    avatar_map = {u.id: (email_to_img.get(u.email) or gravatar_url(u.email, 96) or fallback_img) for u in users}
    selected_avatar = fallback_img
    selected_role, selected_team = None, None
    if selected_user:
        pr_role, pr_team, pr_img = get_profile_for_email(selected_user.email)
        selected_role = pr_role or selected_user.role
        selected_team = pr_team or selected_user.team
        selected_avatar = pr_img or avatar_map.get(selected_user.id, fallback_img)
    return render_template("user_access.html", users=users, codes=codes, selected_user=selected_user, assigned_ids=assigned_ids, assigned_rows=assigned_rows, username=me.username, role=me.role, avatar_map=avatar_map, selected_avatar=selected_avatar, selected_role=selected_role, selected_team=selected_team)

@app.route("/admin/user-project-matrix", methods=["GET"], endpoint="user_project_matrix")
@role_required("superadmin", "admin")
def user_project_matrix():
    me = User.query.filter_by(username=session["username"]).first()
    users_q = User.query.order_by(User.username.asc())
    if me.role != "superadmin" and me.team: users_q = users_q.filter_by(team=me.team)
    users = users_q.all()
    user_ids = [u.id for u in users]
    assignments = []
    if user_ids:
        assignments = (UserProjectAssignment.query.join(ProjectCode, UserProjectAssignment.project_id == ProjectCode.id).filter(UserProjectAssignment.user_id.in_(user_ids), UserProjectAssignment.is_active == True).order_by(ProjectCode.code.asc()).all())
    mapping = {u.id: [] for u in users}
    for r in assignments: mapping.setdefault(r.user_id, []).append((r.project.code, r.project.status))
    return render_template("user_project_matrix.html", users=users, mapping=mapping, username=me.username, role=me.role)

def parse_time_to_decimal(time_value):
    if time_value is None: return 0.0
    if isinstance(time_value, (float, int)): return float(time_value)
    try:
        parts = str(time_value).split(':')
        return int(parts[0]) + (int(parts[1]) if len(parts)>1 else 0)/60.0 + (int(parts[2]) if len(parts)>2 else 0)/3600.0
    except: return 0.0

@app.template_filter('hm_format')
def format_hours_minutes(hours):
    if hours is None: return "00:00"
    hours = float(hours)
    total_seconds = int(hours * 3600)
    return f"{total_seconds // 3600:02d}:{(total_seconds % 3600) // 60:02d}"

@app.route("/admin/admin/dashboard", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def admin_dashboard():
    current_user = User.query.filter_by(username=session["username"]).first()
    filters = []
    selected_user = None
    start_date, end_date = None, None
    if current_user.role != "superadmin": filters.append(f"team = '{current_user.team}'")
    if request.method == "POST":
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")
        selected_user = request.form.get("user_select")
        if start_date and end_date: filters.append(f"date BETWEEN '{start_date}' AND '{end_date}'")
        if selected_user and selected_user != "all": filters.append(f"name = '{selected_user}'")
    cur = mysql.connection.cursor()
    where_clause = ""
    if filters: where_clause = "WHERE " + " AND ".join(filters)
    work_condition = f"{where_clause} {'AND ' if where_clause else 'WHERE '} process != 'Breaks'"
    break_condition = f"{where_clause} {'AND ' if where_clause else 'WHERE '} process = 'Breaks'"
    cur.execute(f"SELECT COUNT(*) FROM timesheetlogs {where_clause}"); total_entries = cur.fetchone()[0]
    cur.execute(f"SELECT COUNT(DISTINCT name) FROM timesheetlogs {where_clause}"); total_users = cur.fetchone()[0]
    cur.execute(f"SELECT SUM(TIME_TO_SEC(duration)) FROM timesheetlogs {work_condition}"); total_work_seconds = float(cur.fetchone()[0] or 0)
    cur.execute(f"SELECT SUM(TIME_TO_SEC(duration)) FROM timesheetlogs {break_condition}"); total_break_seconds = float(cur.fetchone()[0] or 0)
    cur.execute(f"SELECT DISTINCT project FROM timesheetlogs {where_clause}"); active_project_codes = [row[0] for row in cur.fetchall()]
    inactive_project_filters = []
    if current_user.role != "superadmin": inactive_project_filters.append(f"team = '{current_user.team}'")
    inactive_project_filters.append("date < DATE_SUB(CURDATE(), INTERVAL 90 DAY)")
    inactive_where_clause = ""
    if inactive_project_filters: inactive_where_clause = "WHERE " + " AND ".join(inactive_project_filters)
    cur.execute(f"SELECT DISTINCT project FROM timesheetlogs {inactive_where_clause}"); inactive_projects = [row[0] for row in cur.fetchall()]
    cur.execute(f"SELECT process, COUNT(*) FROM timesheetlogs {where_clause} GROUP BY process"); process_data = cur.fetchall()
    cur.execute(f"SELECT project, SUM(duration) FROM timesheetlogs {where_clause} GROUP BY project ORDER BY SUM(duration) DESC"); project_hours_data = cur.fetchall()
    cur.execute(f"SELECT date, SUM(duration) FROM timesheetlogs {where_clause} GROUP BY date ORDER BY date DESC LIMIT 7"); daily_data = cur.fetchall()
    cur.execute(f"SELECT name, SUM(duration) FROM timesheetlogs {where_clause} GROUP BY name ORDER BY SUM(duration) DESC"); user_hours = cur.fetchall()
    cur.execute(f"""SELECT date, SUM(CASE WHEN process != 'Breaks' THEN TIME_TO_SEC(duration) ELSE 0 END), SUM(CASE WHEN process = 'Breaks' THEN TIME_TO_SEC(duration) ELSE 0 END) FROM timesheetlogs {where_clause} GROUP BY date ORDER BY date DESC LIMIT 7""")
    daily_work_break_data = [(r[0], float(r[1])/3600.0, float(r[2])/3600.0) for r in cur.fetchall()]
    cur.execute(f"SELECT sub_process, SUM(duration) FROM timesheetlogs {where_clause} GROUP BY sub_process ORDER BY SUM(duration) DESC"); sub_process_data = cur.fetchall()
    cur.execute(f"SELECT name, date, project, process, sub_process, duration FROM timesheetlogs {where_clause} ORDER BY date DESC LIMIT 100"); raw_table_data = cur.fetchall()
    table_data = [(row[0], row[1], row[2], row[3], row[4], parse_time_to_decimal(row[5])) for row in raw_table_data]
    user_list_query = "SELECT DISTINCT name FROM timesheetlogs"
    if current_user.role != "superadmin": user_list_query += f" WHERE team = '{current_user.team}'"
    cur.execute(user_list_query); users = [u[0] for u in cur.fetchall()]
    cur.close()
    return render_template("admin_dashboard.html", current_user=current_user, total_entries=total_entries, total_users=total_users, total_work_hours=round(total_work_seconds/3600.0, 2), total_break_hours=round(total_break_seconds/3600.0, 2), active_project_codes=active_project_codes, inactive_projects=inactive_projects, process_data=process_data, project_hours_data=project_hours_data, daily_data=daily_data, user_hours=user_hours, daily_work_break_data=daily_work_break_data, sub_process_data=sub_process_data, table_data=table_data, users=users, selected_user=selected_user, start_date=start_date, end_date=end_date)

@app.template_filter("datetimeformat")
def datetimeformat(value, fmt="%Y-%m-%d"):
    try: return datetime.strptime(value, "%Y-%m-%d").strftime(fmt)
    except: return value

def _sec_to_hm(total_seconds: int) -> str:
    total_seconds = int(total_seconds or 0)
    return f"{total_seconds // 3600:02d}:{(total_seconds % 3600) // 60:02d}"

@app.route("/api/my-7day-hours", methods=["GET"])
@login_required
def api_my_7day_hours():
    end_dt, start_dt = date.today(), date.today() - timedelta(days=6)
    user = User.query.filter_by(username=session["username"]).first()
    if not user: return jsonify({"error": "User not found"}), 404
    cur = mysql.connection.cursor()
    q = """SELECT date, SUM(CASE WHEN duration IS NOT NULL AND duration <> '' THEN TIME_TO_SEC(duration) WHEN total_hours IS NOT NULL THEN ROUND(total_hours * 3600) ELSE 0 END) AS total_secs FROM timesheetlogs WHERE name = %s AND date BETWEEN %s AND %s AND NOT (project = 'General' AND process = 'Breaks') GROUP BY date ORDER BY date ASC"""
    cur.execute(q, (user.username, start_dt, end_dt))
    by_date_secs = {str(r[0]): int(r[1] or 0) for r in cur.fetchall()}
    cur.close()
    series, total_secs, d = [], 0, start_dt
    for _ in range(7):
        k = d.isoformat()
        s = by_date_secs.get(k, 0)
        series.append({"date": k, "hours_hms": _sec_to_hm(s), "hours_decimal": round(s/3600.0, 2)})
        total_secs += s
        d += timedelta(days=1)
    return jsonify({"start_date": start_dt.isoformat(), "end_date": end_dt.isoformat(), "by_day": series, "total_hours_hms": _sec_to_hm(total_secs), "total_hours_decimal": round(total_secs/3600.0, 2)})

def _get_monthly_hours(username: str, start_date: date, end_date: date) -> float:
    cur = mysql.connection.cursor()
    q = """SELECT SUM(CASE WHEN duration IS NOT NULL AND duration <> '' THEN TIME_TO_SEC(duration) WHEN total_hours IS NOT NULL THEN ROUND(total_hours * 3600) ELSE 0 END) AS total_secs FROM timesheetlogs WHERE name = %s AND date BETWEEN %s AND %s"""
    cur.execute(q, (username, start_date, end_date))
    total_seconds = cur.fetchone()[0] or 0
    cur.close()
    return float(total_seconds)

@app.route("/api/my-monthly-hours", methods=["GET"])
@login_required
def api_my_monthly_hours():
    user = User.query.filter_by(username=session["username"]).first()
    today = datetime.now().date()
    start_of_this_month = today.replace(day=1)
    end_of_this_month = start_of_this_month + relativedelta(months=+1, days=-1)
    start_of_last_month = start_of_this_month - relativedelta(months=1)
    end_of_last_month = start_of_last_month + relativedelta(months=+1, days=-1)
    total_this_month_secs = _get_monthly_hours(user.username, start_of_this_month, today)
    total_last_month_secs = _get_monthly_hours(user.username, start_of_last_month, end_of_last_month)
    if total_last_month_secs > 0: percent_change = ((total_this_month_secs - total_last_month_secs) / total_last_month_secs) * 100
    else: percent_change = 0 if total_this_month_secs == 0 else 100
    return jsonify({"total_hours_hms": _sec_to_hm(total_this_month_secs), "total_hours_decimal": round(total_this_month_secs/3600, 2), "percent_change": round(percent_change, 1)})

@app.route("/api/quick-presets", methods=["GET"])
@login_required
def get_quick_presets():
    user = User.query.filter_by(username=session["username"]).first()
    presets = QuickTimerPreset.query.filter_by(user_id=user.id).all()
    return jsonify([{"id": p.id, "name": p.name, "project": p.project, "process": p.process, "sub_process": p.sub_process} for p in presets])

@app.route("/api/quick-presets/add", methods=["POST"])
@login_required
def add_quick_preset():
    user = User.query.filter_by(username=session["username"]).first()
    data = request.get_json()
    if not all(data.get(k) for k in ["name", "project", "process", "sub_process"]): return jsonify({"success": False, "message": "Missing fields"}), 400
    new_preset = QuickTimerPreset(user_id=user.id, name=data["name"], project=data["project"], process=data["process"], sub_process=data["sub_process"])
    db.session.add(new_preset)
    db.session.commit()
    return jsonify({"success": True, "id": new_preset.id}), 201

@app.route("/api/quick-presets/delete/<int:preset_id>", methods=["POST"])
@login_required
def delete_quick_preset(preset_id):
    user = User.query.filter_by(username=session["username"]).first()
    preset = QuickTimerPreset.query.filter_by(id=preset_id, user_id=user.id).first()
    if not preset: return jsonify({"success": False, "message": "Not found"}), 404
    db.session.delete(preset)
    db.session.commit()
    return jsonify({"success": True}), 200

@app.route("/admin/live-status")
@role_required("superadmin", "admin")
def live_status():
    me = User.query.filter_by(username=session["username"]).first()
    today_str = datetime.now().strftime("%Y-%m-%d")
    cur = mysql.connection.cursor()
    query_base = """SELECT name, team, project, process, sub_process, start_time FROM timesheetlogs WHERE date = %s AND end_time IS NULL"""
    params = [today_str]
    if me.role == "admin" and me.team:
        query_base += " AND team = %s"
        params.append(me.team)
    query_base += " ORDER BY team, name, start_time"
    cur.execute(query_base, tuple(params))
    live_entries = cur.fetchall()
    cur.close()
    return render_template("live_status.html", entries=live_entries, username=me.username, role=me.role, today_date=today_str)

@app.route("/api/timer/start", methods=["POST"])
@login_required
def start_timer():
    data = request.get_json()
    preset = QuickTimerPreset.query.get(data.get("id"))
    if not preset: return jsonify({"success": False, "message": "Preset not found"}), 404
    if session.get("active_timer"): return jsonify({"success": False, "message": "Timer already running"}), 409
    try:
        name = session["username"]
        user = User.query.filter_by(username=name).first()
        team = user.team
        start_dt = datetime.now()
        proj_code, proj_type_mc, disease, country = parse_project_fields(team, preset.project)
        pc = ProjectCode.query.filter_by(code=preset.project).first()
        proj_type_db = pc.status if pc else "WIP"
        cur = mysql.connection.cursor()
        cur.execute("""INSERT INTO timesheetlogs (name, date, day, team, project, project_type, process, sub_process, start_time, end_time, duration, total_hours, project_code, project_type_mc, disease, country) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL, NULL, %s, %s, %s, %s)""", (name, start_dt.strftime("%Y-%m-%d"), start_dt.strftime("%A"), team, preset.project, proj_type_db, preset.process, preset.sub_process, start_dt.strftime("%H:%M"), proj_code, proj_type_mc, disease, country))
        new_entry_id = cur.lastrowid
        mysql.connection.commit()
        cur.close()
        
        # 🆕 NOTIFY HIERARCHY
        notify_hierarchy(user, f"Quick Timer Started\nUser: {name}\nPreset: {preset.name}\nProject: {preset.project}")

    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f"Error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    session["active_timer"] = {"db_id": new_entry_id, "preset_id": preset.id, "name": preset.name, "start_time": start_dt.isoformat(), "project": preset.project, "process": preset.process, "sub_process": preset.sub_process, "is_manual": False}
    session.modified = True
    return jsonify({"success": True, "timer": session["active_timer"]})

@app.route("/api/timer/stop", methods=["POST"])
@login_required
def stop_timer():
    timer_data = session.pop("active_timer", None)
    if not timer_data: return jsonify({"success": False, "message": "No active timer"}), 404
    entry_db_id = timer_data.get("db_id")
    if not entry_db_id: return jsonify({"success": False, "message": "Corrupt data"}), 500
    try:
        start_dt = datetime.fromisoformat(timer_data["start_time"])
        end_dt = datetime.now()
        if end_dt <= start_dt: end_dt = start_dt + timedelta(seconds=1)
        dur = end_dt - start_dt
        seconds = int(dur.total_seconds())
        hours, remainder = divmod(seconds, 3600)
        duration_str = f"{hours:02d}:{divmod(remainder, 60)[0]:02d}"
        total_h = round(seconds / 3600, 2)
        cur = mysql.connection.cursor()
        cur.execute("""UPDATE timesheetlogs SET end_time = %s, duration = %s, total_hours = %s WHERE id = %s""", (end_dt.strftime("%H:%M"), duration_str, total_h, entry_db_id))
        mysql.connection.commit()
        cur.close()
        
        # 🆕 NOTIFY HIERARCHY
        user = User.query.filter_by(username=session["username"]).first()
        notify_hierarchy(user, f"Timer Stopped\nUser: {session['username']}\nProject: {timer_data['project']}\nDuration: {duration_str}")

    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f"Error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    session.modified = True
    return jsonify({"success": True, "log_entry": {"duration": duration_str, "project": timer_data["project"]}})

@app.route("/api/timer/status", methods=["GET"])
@login_required
def get_timer_status():
    timer = session.get("active_timer")
    if timer:
        start_time = datetime.fromisoformat(timer["start_time"])
        elapsed = (datetime.now() - start_time).total_seconds()
        timer["elapsed_time"] = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
        return jsonify({"active": True, "timer": timer})
    return jsonify({"active": False})

@app.route("/api/manual/start", methods=["POST"])
@login_required
def start_manual_timer():
    if session.get("active_timer"): return jsonify({"success": False, "message": "Timer running"}), 409
    data = request.get_json()
    if not all([data.get("project"), data.get("process"), data.get("sub_process"), data.get("start_time"), data.get("date")]): return jsonify({"success": False, "message": "Missing fields"}), 400
    try:
        name = session["username"]
        user = User.query.filter_by(username=name).first()
        team = user.team
        proj_code, proj_type_mc, disease, country = parse_project_fields(team, data.get("project"))
        pc = ProjectCode.query.filter_by(code=data.get("project")).first()
        proj_type_db = pc.status if pc else "WIP"
        cur = mysql.connection.cursor()
        cur.execute("""INSERT INTO timesheetlogs (name, date, day, team, project, project_type, process, sub_process, start_time, end_time, duration, total_hours, project_code, project_type_mc, disease, country) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL, NULL, %s, %s, %s, %s)""", (name, data.get("date"), datetime.strptime(data.get("date"), "%Y-%m-%d").strftime("%A"), team, data.get("project"), proj_type_db, data.get("process"), data.get("sub_process"), data.get("start_time"), proj_code, proj_type_mc, disease, country))
        new_entry_id = cur.lastrowid
        mysql.connection.commit()
        cur.close()
        
        # 🆕 NOTIFY HIERARCHY
        notify_hierarchy(user, f"Manual Time Entry Created\nUser: {name}\nProject: {data.get('project')}")

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    session["active_timer"] = {"db_id": new_entry_id, "name": f"Manual: {data.get('project')}", "start_time": datetime.now().isoformat(), "project": data.get("project"), "is_manual": True}
    session.modified = True
    return jsonify({"success": True, "db_id": new_entry_id})

@app.route("/api/manual/stop", methods=["POST"])
@login_required
def stop_manual_timer():
    db_id, end_time, start_time = request.form.get("active_db_id"), request.form.get("end_time"), request.form.get("start_time")
    timer_data = session.get("active_timer")
    if not timer_data or str(timer_data.get("db_id")) != db_id: return jsonify({"success": False, "message": "No active manual timer"}), 404
    if not end_time or not start_time: return jsonify({"success": False, "message": "Times required"}), 400
    try:
        start_dt = datetime.strptime(start_time, "%H:%M")
        end_dt = datetime.strptime(end_time, "%H:%M")
        dur = end_dt - start_dt
        seconds = int(dur.total_seconds())
        if seconds < 0: seconds += 24 * 3600
        hours, remainder = divmod(seconds, 3600)
        duration_str = f"{hours:02d}:{divmod(remainder, 60)[0]:02d}"
        total_h = round(seconds / 3600, 2)
        cur = mysql.connection.cursor()
        cur.execute("""UPDATE timesheetlogs SET end_time = %s, duration = %s, total_hours = %s WHERE id = %s""", (end_time, duration_str, total_h, db_id))
        mysql.connection.commit()
        cur.close()
        
        # 🆕 NOTIFY HIERARCHY
        user = User.query.filter_by(username=session["username"]).first()
        notify_hierarchy(user, f"Manual Timer Stopped\nUser: {session['username']}\nDuration: {duration_str}")

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    session.pop("active_timer", None)
    session.modified = True
    return jsonify({"success": True})

@app.route("/api/manual/cancel", methods=["POST"])
@login_required
def cancel_manual_timer():
    timer_data = session.pop("active_timer", None)
    if not timer_data or not timer_data.get("is_manual", False): return jsonify({"success": False, "message": "No active manual timer"}), 404
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM timesheetlogs WHERE id = %s", (timer_data.get("db_id"),))
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    return jsonify({"success": True})

app.register_blueprint(dashboard_bp, url_prefix='/admin/dashboard')

if __name__ == "__main__":
    from os import environ
    port = int(environ.get("PORT", 7060))
    app.run(host="0.0.0.0", port=port, debug=True)