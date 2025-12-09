# ── app.py ──────────────────────────────────────────────────────────────────
import os
import io
import shutil
import tempfile
import random
import smtplib
import hashlib
import re
from functools import wraps
from datetime import datetime, timedelta, date, time
from math import ceil
from dateutil.relativedelta import relativedelta
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from flask import (Flask, render_template_string, request, redirect, url_for,
                   session, flash, jsonify, render_template)
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy import create_engine, text
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from pytz import timezone

# 🆕 Import the Blueprint from the new file
# (Ensure dashboard_blueprint.py exists in your folder)
try:
    from dashboard_blueprint import dashboard_bp
except ImportError:
    dashboard_bp = None
    print("Warning: dashboard_blueprint not found. Dashboard route might fail.")

# ── CONFIG ────────────────────────────────────────────────────────────────
app = Flask(__name__)

# --- secrets & config from ENV (set in app.yaml or .env) ---
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

DB_HOST = os.getenv("DB_HOST", "34.93.75.171")   # public IP for your DB
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "timesheet")
DB_USER = os.getenv("DB_USER", "appsadmin")
DB_PASS = os.getenv("DB_PASS", "appsadmin2025")

# SQLAlchemy Config
DB_URI = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
app.config["SQLALCHEMY_DATABASE_URI"] = DB_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Flask-MySQLdb Config
app.config["MYSQL_HOST"] = DB_HOST
app.config["MYSQL_USER"] = DB_USER
app.config["MYSQL_PASSWORD"] = DB_PASS
app.config["MYSQL_DB"] = DB_NAME
app.config["MYSQL_PORT"] = DB_PORT
mysql = MySQL(app)

# For raw ALTERs once
engine = create_engine(DB_URI)

# SMTP Config
SMTP_SERVER  = os.getenv("SMTP_SERVER", "smtp.datasolve-analytics.com")
SMTP_PORT    = int(os.getenv("SMTP_PORT", "587"))
WEBMAIL_USER = os.getenv("SMTP_USER", "apps.admin@datasolve-analytics.com")
WEBMAIL_PASS = os.getenv("SMTP_PASS", "datasolve@2025")

# ── SCHEDULER ─────────────────────────────────────────────────────────────
def refresh_data():
    print("Refreshing data @07:30 AM IST")
    # 👉 put your refresh logic here (DB update, cache clear, etc.)

def create_scheduler():
    ist = timezone("Asia/Kolkata")
    sched = BackgroundScheduler(timezone=ist)
    # every day at 12:22 PM IST
    sched.add_job(refresh_data, CronTrigger(hour=12, minute=22, timezone=ist))
    sched.start()
    return sched

def maybe_start_scheduler():
    """Start background scheduler only in local/dev."""
    if not os.getenv("GAE_ENV"):  # means we're NOT on App Engine Standard
        try:
            create_scheduler()
        except Exception as e:
            app.logger.warning(f"Scheduler not started: {e}")

maybe_start_scheduler()

# ── HELPERS & DECORATORS ─────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def _wrap(*a, **kw):
        if "username" not in session:  
            return redirect("/signin")
        return f(*a, **kw)
    return _wrap

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def _wrap(*a, **kw):
            user = User.query.filter_by(username=session.get("username")).first()
            if user and user.role in roles:  
                return f(*a, **kw)
            flash("⛔ Permission denied")
            return redirect("/home")
        return _wrap
    return decorator

# 🔔 NOTIFICATION HELPERS (NEW)
def create_notification(user_id, message, notif_type="INFO", is_mandatory=False):
    """Creates a notification for a specific user."""
    try:
        notif = UserNotification(
            user_id=user_id,
            message=message,
            notif_type=notif_type,
            is_mandatory=is_mandatory,
            date_context=datetime.utcnow().date()
        )
        db.session.add(notif)
    except Exception as e:
        print(f"Error creating notification: {e}")

def notify_admins_and_superadmins(team, message, notif_type, exclude_user_id=None):
    """Sends notification to Superadmins (always) and Admins of the specific 'team'."""
    targets = User.query.filter(User.role.in_(['superadmin', 'admin'])).all()
    for target in targets:
        if exclude_user_id and target.id == exclude_user_id:
            continue
        
        # Superadmin sees all, Admin sees only their team
        if target.role == 'superadmin' or (target.role == 'admin' and target.team == team):
            create_notification(target.id, message, notif_type)

def send_otp(email, otp):
    try:
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
    except Exception as e:
        print(f"SMTP Error: {e}")

def get_profile_for_email(email: str):
    """Return (role_from_profile, team_from_profile, image_url) for an email."""
    if not email:
        return None, None, None
    rec = (db.session.query(UserProfile.Designation, UserProfile.Team, UserProfile.Image_URL)
           .filter(UserProfile.Email_ID == email)
           .first())
    if not rec:
        return None, None, None
    return rec[0], rec[1], rec[2]

def gravatar_url(email: str, size=64, default="identicon"):
    if not email:
        return ""
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    return f"https://www.gravatar.com/avatar/{h}?s={size}&d={default}&r=g"

# Teams that use underscore-split format
PROJECT_SPLIT_TEAMS = {"MCTeam", "IPTeam", "AnalyticsTeam", "BDTeam", "MRTeam"}

def parse_project_fields(team: str, project: str):
    """Return (proj_code, proj_type_mc, disease, country) from `project`."""
    if not project:
        return "", "", "", ""
    proj = project.strip()
    if team not in PROJECT_SPLIT_TEAMS or "_" not in proj:
        return proj, "", "", ""
    parts = re.split(r"_+", proj)
    while len(parts) < 4:
        parts.append("")
    return parts[0], parts[1], parts[2], parts[3]

def safe_parse_project_fields(team, project):
    try:
        return parse_project_fields(team, project)
    except NameError:
        return (None, None, None, None)

def format_time_for_input(val):
    if val is None: return ""
    if isinstance(val, time): return f"{val.hour:02d}:{val.minute:02d}"
    if isinstance(val, datetime): return f"{val.hour:02d}:{val.minute:02d}"
    s = str(val).strip()
    if not s: return ""
    try:
        parts = s.split(":")
        return f"{int(parts[0]):02d}:{int(parts[1]):02d}"
    except:
        return s[:5] if len(s) >= 5 else s

def _strip_param(url, param_name="editing_id"):
    try:
        pu = urlparse(url)
        q = [(k, v) for (k, v) in parse_qsl(pu.query, keep_blank_values=True) if k != param_name]
        return urlunparse((pu.scheme, pu.netloc, pu.path, pu.params, urlencode(q), pu.fragment))
    except Exception:
        return url

# ── TEMPLATE FILTERS & CONTEXT ──────────────────────────────────────────

@app.template_filter("todatetime")
def todatetime(value, fmt="%Y-%m-%d"):
    try:
        return datetime.strptime(value, fmt)
    except:
        return value

@app.template_filter('hm_format')
def format_hours_minutes(hours):
    if hours is None: return "00:00"
    try:
        hours = float(hours)
        total_seconds = int(hours * 3600)
        h = total_seconds // 3600
        m = (total_seconds % 3600) // 60
        return f"{h:02d}:{m:02d}"
    except:
        return "00:00"

@app.context_processor
def inject_gravatar():
    return dict(gravatar_url=gravatar_url)

@app.context_processor
def inject_profile_image():
    """Kept for backward compatibility if used in templates directly"""
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
        "user_email": email, "profile_image_url": img_url,
        "profile_name": full_name or display_name, "employee_id": employee_id, "role": role,
    }

# 🆕 Inject Unread Notification Count globally for the Bell Icon
@app.context_processor
def inject_notifications_and_profile():
    context = {}
    display_name = session.get("username")
    unread_count = 0
    if display_name:
        try:
            user = User.query.filter_by(username=display_name).first()
            if user:
                unread_count = UserNotification.query.filter_by(user_id=user.id, is_read=False).count()
        except Exception:
            pass
    context.update({"unread_notif_count": unread_count})
    return context

# ── MODELS ────────────────────────────────────────────────────────────────

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
    team     = db.Column(db.String(100))  # team scoping

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
    notif_type = db.Column(db.String(50)) # 'NEW_USER', 'LOG_UPDATE', 'ASSIGNMENT', etc.

class QuickTimerPreset(db.Model):
    __tablename__  = "quick_timer_presets"
    __table_args__ = {"extend_existing": True}

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("desktop_userstable.id"), nullable=False)
    name        = db.Column(db.String(100), nullable=False)
    project     = db.Column(db.String(100), nullable=False)
    process     = db.Column(db.String(100), nullable=False)
    sub_process = db.Column(db.String(100), nullable=False)

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

# ── ROUTES: AUTH ──────────────────────────────────────────────────────────

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
        # 🔔 NOTIFY ADMINS
        notify_admins_and_superadmins(t, f"New Member Alert: '{u}' has joined '{t}'.", "NEW_USER")
        db.session.commit()
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
    if "reset_email" not in session:
        return redirect("/forgot-password")
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
    return render_template("welcome.html", username=user.username, no_sidebar=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ── DASHBOARD & USER ROUTES ──

def get_visible_project_codes_for(user: User):
    assignments = (
        UserProjectAssignment.query
        .join(ProjectCode, UserProjectAssignment.project_id == ProjectCode.id)
        .filter(
            UserProjectAssignment.user_id == user.id,
            UserProjectAssignment.is_active == True,
            ProjectCode.status == "WIP"
        ).all()
    )
    return [
        {
            "code": a.project.code,
            "status": a.project.status,
            "assigned_by": a.assigned_by.username if a.assigned_by else "",
            "start_date": a.start_date.strftime("%Y-%m-%d") if a.start_date else "",
            "end_date": a.end_date.strftime("%Y-%m-%d") if a.end_date else ""
        }
        for a in assignments
    ]

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
        team_map.setdefault(row.team, {}) \
                .setdefault(row.process, set()) \
                .add(row.sub_process)

    team_json = {
        team: {proc: sorted(list(subs)) for proc, subs in proc_dict.items()}
        for team, proc_dict in team_map.items()
    }

    user_project_codes = get_visible_project_codes_for(user)
    raw_presets = QuickTimerPreset.query.filter_by(user_id=user.id).all()
    quick_presets = [{
        "id": p.id, "name": p.name, "project": p.project,
        "process": p.process, "sub_process": p.sub_process,
    } for p in raw_presets]
    
    return render_template(
        "dashboard.html",
        username=user.username,
        role=role,
        entries=processed_entries,
        user_email=user.email,  
        today=today,
        team_json=team_json,
        user_project_codes=user_project_codes,
        user_team=user.team,
        quick_presets=quick_presets
    )

# ── LOG START/UPDATE ROUTES ──

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

    # 1-MIN GAP VALIDATION
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            SELECT COUNT(*) FROM timesheetlogs 
            WHERE name = %s AND date = %s 
              AND start_time <= %s AND end_time >= %s
        """, (name, date_str, end_time, start_time))
        if cur.fetchone()[0] > 0:
            flash(f"Error: Time ({start_time} - {end_time}) overlaps existing entry.", "error")
            cur.close()
            return redirect("/home")
    except Exception as e:
        app.logger.error(f"Error during start time validation: {e}")
        cur.close()
        return redirect("/home")

    # Duration
    try:
        start_dt = datetime.strptime(start_time, "%H:%M")
        end_dt = datetime.strptime(end_time, "%H:%M")
        dur = end_dt - start_dt
        seconds = int(dur.total_seconds())
        if seconds < 0: seconds += 24 * 3600
        hours, remainder = divmod(seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        duration_str = f"{hours:02d}:{minutes:02d}"
        total_h = round(seconds / 3600, 2)
    except ValueError:
        flash("Invalid time format.", "error")
        cur.close()
        return redirect("/home")

    proj_code, proj_type_mc, disease, country = parse_project_fields(team, project)

    try:
        cur.execute("""
            INSERT INTO timesheetlogs
              (name, date, day, team, project, project_type, process, sub_process,
               start_time, end_time, duration, total_hours,
               project_code, project_type_mc, disease, country)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (name, date_str, day, team, project, proj_type_db, process, sub_proc,
              start_time, end_time, duration_str, total_h,
              proj_code, proj_type_mc, disease, country))
        mysql.connection.commit()
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Database error: {e}", "error")
    finally:
        cur.close()

    return redirect("/home")

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
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            SELECT name, date, team, project_code, project_type_mc, disease, country, project
            FROM timesheetlogs WHERE id=%s
        """, (entry_id,))
        row = cur.fetchone()
        if not row:
            cur.close(); flash("Entry not found.", "error"); return redirect(url_for("view_team_logs"))
            
        entry_name, entry_date, entry_team, old_proj_code, old_proj_type_mc, old_disease, old_country, old_project = row
        
        if current_user.role != "superadmin" and current_user.team != entry_team:
             cur.close(); flash("Permission denied.", "error"); return redirect(url_for("view_team_logs"))
    except Exception as e:
        cur.close(); flash(f"DB Error: {e}", "error"); return redirect(url_for("view_team_logs"))

    if not (project and process and sub_proc and start_time and end_time):
        cur.close(); flash("All fields required.", "error"); return redirect(url_for("view_team_logs", editing_id=entry_id))

    # Time helpers
    def parse_hms(s):
        parts = s.split(":")
        h, m = int(parts[0]), int(parts[1])
        return h, m, 0
    def minutes_since_midnight(h, m, s=0): return h * 60 + m + (s // 60)
    def hhmm_from_minutes(t): return f"{t // 60:02d}:{t % 60:02d}"

    project_for_lookup = project if project else old_project
    try:
        new_proj_code, new_proj_type_mc, new_disease, new_country = safe_parse_project_fields(entry_team, project_for_lookup)
        proj_code = new_proj_code if new_proj_code else old_proj_code
        proj_type_mc = new_proj_type_mc if new_proj_type_mc else old_proj_type_mc
        disease = new_disease if new_disease else old_disease
        country = new_country if new_country else old_country
    except Exception:
        proj_code, proj_type_mc, disease, country = old_proj_code, old_proj_type_mc, old_disease, old_country
    if ptmc_manual: proj_type_mc = ptmc_manual

    # Validation & Update
    try:
        cur.execute("""
            SELECT COUNT(*) FROM timesheetlogs WHERE name=%s AND date=%s AND id!=%s 
            AND start_time<%s AND end_time>%s
        """, (entry_name, entry_date, entry_id, end_time, start_time))
        if cur.fetchone()[0] > 0:
             flash("Error: Time overlaps existing entry.", "error")
             return redirect(url_for("view_team_logs", editing_id=entry_id))

        sh, sm, _ = parse_hms(start_time)
        eh, em, _ = parse_hms(end_time)
        s_min = minutes_since_midnight(sh, sm)
        e_min = minutes_since_midnight(eh, em)
        delta_min = (e_min - s_min) % (24 * 60)
        duration_hhmm = hhmm_from_minutes(delta_min)
        total_hours = round(delta_min / 60.0, 2)

        if current_user.role == "superadmin":
            where = "WHERE id=%s"; p_where = (entry_id,)
        else:
            where = "WHERE id=%s AND team=%s"; p_where = (entry_id, entry_team)

        params = [project, process, sub_proc, start_time, end_time, duration_hhmm, total_hours,
                  proj_code, proj_type_mc, disease, country] + list(p_where)
        cur.execute(f"""
            UPDATE timesheetlogs SET project=%s, process=%s, sub_process=%s, start_time=%s, end_time=%s,
            duration=%s, total_hours=%s, project_code=%s, project_type_mc=%s, disease=%s, country=%s
            {where}
        """, tuple(params))
        mysql.connection.commit()

        # 🔔 TRIGGER NOTIFICATIONS
        msg = f"{current_user.username} updated log #{entry_id} for {entry_name}."
        if current_user.username == entry_name: msg = f"{entry_name} updated their log #{entry_id}."
        notify_admins_and_superadmins(entry_team, msg, "LOG_UPDATE", exclude_user_id=current_user.id)
        if current_user.username != entry_name:
             target = User.query.filter_by(username=entry_name).first()
             if target: create_notification(target.id, f"Your log #{entry_id} was updated by Admin.", "LOG_UPDATE")
        db.session.commit()

    except Exception as e:
        mysql.connection.rollback(); flash(f"Error: {e}", "error")
    finally:
        cur.close()

    next_url = _strip_param(next_url, "editing_id")
    flash("Entry updated!", "success")
    return redirect(next_url)

# ── ADMIN ROUTES ──────────────────────────────────────────────────────────

@app.route("/api/process-master")
@login_required
def process_master():
    data = [dict(id=p.id, team=p.team, process=p.process, sub_process=p.sub_process) 
            for p in ProcessTable.query.all()]
    return jsonify(data)

@app.route("/admin/usermanagement", methods=["GET", "POST"])
@role_required("superadmin")
def manage_users():
    if request.method == "POST":
        uid = request.form["uid"]
        new_role = request.form["role"]
        new_team = request.form["team"]
        target = User.query.get(uid)
        if target:
            target.role = new_role
            target.team = new_team
            db.session.commit()
            flash(f"{target.username} updated.", "success")
        else:
            flash("User not found", "error")
    users = User.query.all()
    emails = [u.email for u in users]
    email_img_map = {}
    if emails:
        rows = (db.session.query(UserProfile.Email_ID, UserProfile.Image_URL)
                .filter(UserProfile.Email_ID.in_(emails)).all())
        email_img_map = {e: url for e, url in rows if url}
    current = User.query.filter_by(username=session["username"]).first()
    return render_template("users.html", users=users, username=current.username,
                           role=current.role, email_img_map=email_img_map)

@app.route("/process&subprocess", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def manage_process():
    me = User.query.filter_by(username=session["username"]).first()
    is_super = (me.role == "superadmin")
    if request.method == "POST":
        t, p, s = request.form["team"].strip(), request.form["process"].strip(), request.form["sub"].strip()
        if t and p and s:
            db.session.add(ProcessTable(team=t, process=p, sub_process=s))
            db.session.commit()
            flash("Row added", "ok")
        else: flash("Fields required", "error")
    
    q = ProcessTable.query
    if not is_super: q = q.filter_by(team=me.team)
    if request.args.get("filter_team"): q = q.filter_by(team=request.args.get("filter_team"))
    if request.args.get("filter_process"): q = q.filter_by(process=request.args.get("filter_process"))
    if request.args.get("filter_sub"): q = q.filter_by(sub_process=request.args.get("filter_sub"))
    rows = q.order_by(ProcessTable.id).all()
    
    all_rows = ProcessTable.query.all() if is_super else ProcessTable.query.filter_by(team=me.team).all()
    teams = sorted({r.team for r in all_rows})
    processes = sorted({r.process for r in all_rows})
    subs = sorted({r.sub_process for r in all_rows})
    return render_template("process.html", rows=rows, username=me.username, role=me.role,
                           teams=teams, processes=processes, sub_processes=subs,
                           selected_team=request.args.get("filter_team",""),
                           selected_process=request.args.get("filter_process",""),
                           selected_sub=request.args.get("filter_sub",""))

@app.route('/admin/delete_process_row', methods=['POST'])
@role_required("superadmin", "admin")
def delete_process_row():
    data = request.get_json()
    row = ProcessTable.query.get(data['id'])
    me = User.query.filter_by(username=session["username"]).first()
    if not row or (me.role != "superadmin" and row.team != me.team):
        return jsonify(success=False, error="Denied")
    db.session.delete(row)
    db.session.commit()
    return jsonify(success=True)

@app.route('/update_process_row', methods=['POST'])
@role_required("superadmin", "admin")
def update_process_row():
    data = request.get_json()
    row = ProcessTable.query.get(data['id'])
    me = User.query.filter_by(username=session["username"]).first()
    if not row or (me.role != "superadmin" and row.team != me.team):
        return jsonify(success=False, error="Denied")
    row.team, row.process, row.sub_process = data['team'], data['process'], data['sub_process']
    db.session.commit()
    return jsonify(success=True)

@app.route("/allocations", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def admin_project_codes():
    me = User.query.filter_by(username=session["username"]).first()
    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        status = (request.form.get("status") or "WIP").strip()
        if not code: return redirect(url_for("admin_project_codes"))
        
        existing = ProjectCode.query.filter_by(code=code).first()
        today = date.today()
        if existing:
            prev_s = existing.status
            existing.status = status
            if not existing.team: existing.team = me.team
            if status == "WIP" and not existing.start_date: existing.start_date = today
            if status == "Closed" and not existing.end_date: existing.end_date = today
            if status == "Hold" and not existing.hold_on: existing.hold_on = today
            if prev_s == "Hold" and status != "Hold": existing.hold_on = None
            db.session.commit(); flash("Code updated", "success")
        else:
            pc = ProjectCode(code=code, status=status, team=me.team)
            if status == "WIP": pc.start_date = today
            elif status == "Closed": pc.end_date = today
            elif status == "Hold": pc.hold_on = today
            db.session.add(pc); db.session.commit(); flash("Code created", "success")
        return redirect(url_for("admin_project_codes"))

    q = ProjectCode.query if me.role == "superadmin" else ProjectCode.query.filter_by(team=me.team)
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
        if not pid: flash("Select project", "error"); return redirect(url_for("assign_projects"))

        if action in ("bulk_assign", "bulk_end"):
            user_ids = request.form.getlist("user_ids")
            proj = ProjectCode.query.get(pid)
            cnt = 0
            for uid in user_ids:
                u = User.query.get(int(uid))
                if not u or (me.team and u.team != me.team): continue
                exists = UserProjectAssignment.query.filter_by(user_id=u.id, project_id=int(pid), is_active=True).first()
                
                if action == "bulk_assign" and not exists:
                    db.session.add(UserProjectAssignment(user_id=u.id, project_id=int(pid), assigned_by_id=me.id, is_active=True))
                    create_notification(u.id, f"Project Assigned: {proj.code} by {me.username}", "ASSIGNMENT")
                    cnt += 1
                elif action == "bulk_end" and exists:
                    exists.is_active = False
                    exists.end_date = datetime.utcnow().date()
                    create_notification(u.id, f"Project Removed: {proj.code} by {me.username}", "ASSIGNMENT")
                    cnt += 1
            db.session.commit()
            flash(f"Updated {cnt} users.", "success")
            return redirect(url_for("assign_projects"))

        # Single assign/end logic
        uid, pid_s, act = request.form.get("user_id"), request.form.get("project_id"), request.form.get("action", "assign")
        if uid and pid_s:
            u, c = User.query.get(int(uid)), ProjectCode.query.get(int(pid_s))
            if u and c:
                exists = UserProjectAssignment.query.filter_by(user_id=u.id, project_id=c.id, is_active=True).first()
                if act == "assign" and not exists:
                    db.session.add(UserProjectAssignment(user_id=u.id, project_id=c.id, assigned_by_id=me.id, is_active=True))
                    create_notification(u.id, f"Project Assigned: {c.code}", "ASSIGNMENT")
                    db.session.commit(); flash("Assigned", "success")
                elif act == "end" and exists:
                    exists.is_active = False; exists.end_date = datetime.utcnow().date()
                    create_notification(u.id, f"Project Removed: {c.code}", "ASSIGNMENT")
                    db.session.commit(); flash("Ended", "success")
            return redirect(url_for("assign_projects"))

    active = UserProjectAssignment.query.join(User).join(ProjectCode).filter(UserProjectAssignment.is_active==True)
    if me.team: active = active.filter(User.team == me.team)
    active = active.all()
    assigned_map = {}
    for a in active: assigned_map.setdefault(str(a.project_id), []).append(a.user_id)
    return render_template("assign_projects.html", users=users, codes=codes, active=active,
                           assigned_map=assigned_map, username=me.username, role=me.role)

@app.route("/api/my-project-codes")
@login_required
def my_project_codes():
    user = User.query.filter_by(username=session["username"]).first()
    return jsonify(get_visible_project_codes_for(user))

@app.route("/team-logs", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def view_team_logs():
    current_user = User.query.filter_by(username=session["username"]).first()
    team = current_user.team
    is_post = (request.method == "POST")
    getf = request.form.get if is_post else request.args.get

    f_user, f_proj, f_proc, f_sub = getf("username"), getf("project"), getf("process"), getf("sub_process")
    f_date, f_start, f_end = getf("date"), getf("start_date"), getf("end_date")
    f_team = getf("team")
    editing_id = request.args.get("editing_id")

    page = int(getf("page") or request.args.get("page") or 1)
    per_page = int(getf("per_page") or request.args.get("per_page") or 50)
    if per_page not in {50, 100, 200, 500, 1000}: per_page = 50

    where_sql, values = [], []
    if current_user.role != 'superadmin': where_sql.append("team = %s"); values.append(team)
    if f_user: where_sql.append("name = %s"); values.append(f_user)
    if f_team and current_user.role == 'superadmin': where_sql.append("team = %s"); values.append(f_team)
    if f_proj: where_sql.append("project = %s"); values.append(f_proj)
    if f_proc: where_sql.append("process = %s"); values.append(f_proc)
    if f_sub: where_sql.append("sub_process = %s"); values.append(f_sub)
    if f_date: where_sql.append("date = %s"); values.append(f_date)
    elif f_start or f_end:
        if f_start: where_sql.append("date >= %s"); values.append(f_start)
        if f_end: where_sql.append("date <= %s"); values.append(f_end)
    
    where_clause = ("WHERE " + " AND ".join(where_sql)) if where_sql else ""
    
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT COUNT(*) FROM timesheetlogs {where_clause}", tuple(values))
    total_rows = cur.fetchone()[0]
    total_pages = max(1, ceil(total_rows / per_page))
    if page > total_pages: page = total_pages
    offset = (page - 1) * per_page

    cur.execute(f"""
        SELECT name, date, day, project, team, process, sub_process,
               start_time, end_time, duration, total_hours, id
        FROM timesheetlogs {where_clause} ORDER BY id DESC LIMIT %s OFFSET %s
    """, tuple(values + [per_page, offset]))
    raw_logs = cur.fetchall()

    teams_list, projects, processes, sub_processes, users = [], [], [], [], []
    if current_user.role != 'superadmin':
        cur.execute("SELECT DISTINCT project FROM timesheetlogs WHERE team=%s", (team,))
        projects = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT DISTINCT process FROM timesheetlogs WHERE team=%s", (team,))
        processes = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT DISTINCT sub_process FROM timesheetlogs WHERE team=%s", (team,))
        sub_processes = [r[0] for r in cur.fetchall()]
        users = User.query.filter_by(team=team).all()
    else:
        cur.execute("SELECT DISTINCT project FROM timesheetlogs")
        projects = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT DISTINCT process FROM timesheetlogs")
        processes = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT DISTINCT sub_process FROM timesheetlogs")
        sub_processes = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT DISTINCT team FROM timesheetlogs WHERE team IS NOT NULL")
        teams_list = [r[0] for r in cur.fetchall()]
        users = User.query.all()
    cur.close()

    logs = [list(row) for row in raw_logs]
    for r in logs:
        r[7] = format_time_for_input(r[7])
        r[8] = format_time_for_input(r[8])

    return render_template("team_logs.html", logs=logs, users=users, projects=projects,
                           processes=processes, sub_processes=sub_processes, teams=teams_list,
                           username=current_user.username, role=current_user.role,
                           editing_id=editing_id, page=page, per_page=per_page,
                           total_pages=total_pages, total_rows=total_rows)

@app.route("/admin/delete-log/<int:log_id>", methods=["POST"])
@role_required("superadmin")
def delete_log(log_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM timesheetlogs WHERE id = %s", (log_id,))
        mysql.connection.commit(); cur.close()
        flash("Log entry deleted.", "success")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for('view_team_logs'))

@app.post("/project-codes/update-status", endpoint="update_project_status")
@role_required("superadmin", "admin")
def update_project_status():
    me = User.query.filter_by(username=session["username"]).first()
    data = request.get_json(silent=True) or {}
    rec = ProjectCode.query.get(data.get("id"))
    new_s = data.get("status")
    if not rec or not new_s: return jsonify(ok=False), 400
    if me.role!="superadmin" and rec.team!=me.team: return jsonify(ok=False), 403
    
    prev_s = rec.status; rec.status = new_s; today = date.today()
    if new_s=="WIP" and not rec.start_date: rec.start_date=today
    if new_s=="Closed" and not rec.end_date: rec.end_date=today
    if new_s=="Hold" and not rec.hold_on: rec.hold_on=today
    if prev_s=="Hold" and new_s!="Hold": rec.hold_on=None
    if prev_s=="YTI" and new_s!="YTI" and not rec.yti_end_date: rec.yti_end_date=today
    db.session.commit()
    return jsonify(ok=True, id=rec.id, status=rec.status,
                   start_date=str(rec.start_date), end_date=str(rec.end_date),
                   hold_on=str(rec.hold_on), yti_end_date=str(rec.yti_end_date)), 200

@app.route("/admin/user-access", methods=["GET", "POST"], endpoint="user_access")
@role_required("superadmin", "admin")
def user_access():
    me = User.query.filter_by(username=session["username"]).first()
    uq = User.query
    cq = ProjectCode.query.filter(ProjectCode.status.in_(["WIP", "YTI", "Hold"]))
    if me.role != "superadmin" and me.team:
        uq = uq.filter_by(team=me.team); cq = cq.filter_by(team=me.team)
    users, codes = uq.order_by(User.username).all(), cq.order_by(ProjectCode.code).all()

    sel_uid = request.values.get("user_id", type=int)
    sel_user = User.query.get(sel_uid) if sel_uid else (users[0] if users else None)

    if request.method == "POST" and sel_user:
        act, cids = request.form.get("action"), request.form.getlist("code_ids")
        cids = [int(x) for x in cids]
        cnt = 0
        if act == "add":
            for c in cids:
                if not UserProjectAssignment.query.filter_by(user_id=sel_user.id, project_id=c, is_active=True).first():
                    db.session.add(UserProjectAssignment(user_id=sel_user.id, project_id=c, assigned_by_id=me.id, is_active=True))
                    cnt+=1
            if cnt: create_notification(sel_user.id, f"{cnt} projects assigned by {me.username}", "ASSIGNMENT")
        elif act == "remove":
            rows = UserProjectAssignment.query.filter(UserProjectAssignment.user_id==sel_user.id, UserProjectAssignment.project_id.in_(cids), UserProjectAssignment.is_active==True).all()
            for r in rows:
                r.is_active = False; r.end_date = datetime.utcnow().date()
                cnt+=1
            if cnt: create_notification(sel_user.id, f"{cnt} projects removed by {me.username}", "ASSIGNMENT")
        db.session.commit(); flash(f"{act.title()}ed {cnt} projects.", "success")
        return redirect(url_for("user_access", user_id=sel_user.id))

    assigned_ids = set()
    if sel_user:
        assigned_ids = {r.project_id for r in UserProjectAssignment.query.filter_by(user_id=sel_user.id, is_active=True).all()}

    # Avatar logic
    emails = [u.email for u in users if u.email]
    e_img = {}
    if emails:
        rows = db.session.query(UserProfile.Email_ID, UserProfile.Image_URL).filter(UserProfile.Email_ID.in_(emails)).all()
        e_img = {e: u for e, u in rows if u}
    fallback = url_for('static', filename='img/avatar-default.png')
    avatar_map = {u.id: (e_img.get(u.email) or gravatar_url(u.email,96) or fallback) for u in users}
    
    sel_avatar, sel_role, sel_team = fallback, None, None
    if sel_user:
        pr, pt, pi = get_profile_for_email(sel_user.email)
        sel_role = pr or sel_user.role; sel_team = pt or sel_user.team
        sel_avatar = pi or avatar_map.get(sel_user.id, fallback)

    return render_template("user_access.html", users=users, codes=codes, selected_user=sel_user,
                           assigned_ids=assigned_ids, username=me.username, role=me.role,
                           avatar_map=avatar_map, selected_avatar=sel_avatar, selected_role=sel_role, selected_team=sel_team)

@app.route("/admin/user-project-matrix", methods=["GET"], endpoint="user_project_matrix")
@role_required("superadmin", "admin")
def user_project_matrix():
    me = User.query.filter_by(username=session["username"]).first()
    uq = User.query.order_by(User.username)
    if me.role!="superadmin" and me.team: uq=uq.filter_by(team=me.team)
    users = uq.all()
    
    mapping = {u.id: [] for u in users}
    if users:
        uids = [u.id for u in users]
        assigns = UserProjectAssignment.query.join(ProjectCode).filter(UserProjectAssignment.user_id.in_(uids), UserProjectAssignment.is_active==True).order_by(ProjectCode.code).all()
        for a in assigns: mapping[a.user_id].append((a.project.code, a.project.status))
    return render_template("user_project_matrix.html", users=users, mapping=mapping, username=me.username, role=me.role)

@app.route("/admin/admin/dashboard", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def admin_dashboard():
    me = User.query.filter_by(username=session["username"]).first()
    filters = []
    if me.role != "superadmin": filters.append(f"team = '{me.team}'")
    
    s_date, e_date, s_user = None, None, None
    if request.method == "POST":
        s_date, e_date, s_user = request.form.get("start_date"), request.form.get("end_date"), request.form.get("user_select")
        if s_date and e_date: filters.append(f"date BETWEEN '{s_date}' AND '{e_date}'")
        if s_user and s_user != "all": filters.append(f"name = '{s_user}'")
    
    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    cur = mysql.connection.cursor()
    
    cur.execute(f"SELECT COUNT(*) FROM timesheetlogs {where}")
    total_entries = cur.fetchone()[0]
    cur.execute(f"SELECT COUNT(DISTINCT name) FROM timesheetlogs {where}")
    total_users = cur.fetchone()[0]
    
    w_cond = f"{where} {'AND' if where else 'WHERE'} process != 'Breaks'"
    b_cond = f"{where} {'AND' if where else 'WHERE'} process = 'Breaks'"
    cur.execute(f"SELECT SUM(TIME_TO_SEC(duration)) FROM timesheetlogs {w_cond}")
    tot_work = float(cur.fetchone()[0] or 0) / 3600.0
    cur.execute(f"SELECT SUM(TIME_TO_SEC(duration)) FROM timesheetlogs {b_cond}")
    tot_break = float(cur.fetchone()[0] or 0) / 3600.0

    cur.execute(f"SELECT DISTINCT project FROM timesheetlogs {where}")
    active_projects = [r[0] for r in cur.fetchall()]

    inact_filters = []
    if me.role!="superadmin": inact_filters.append(f"team = '{me.team}'")
    inact_filters.append("date < DATE_SUB(CURDATE(), INTERVAL 90 DAY)")
    inact_where = ("WHERE " + " AND ".join(inact_filters)) if inact_filters else ""
    cur.execute(f"SELECT DISTINCT project FROM timesheetlogs {inact_where}")
    inactive_projects = [r[0] for r in cur.fetchall()]

    cur.execute(f"SELECT process, COUNT(*) FROM timesheetlogs {where} GROUP BY process")
    proc_data = cur.fetchall()
    cur.execute(f"SELECT project, SUM(duration) FROM timesheetlogs {where} GROUP BY project ORDER BY SUM(duration) DESC")
    proj_hours = cur.fetchall()
    cur.execute(f"SELECT date, SUM(duration) FROM timesheetlogs {where} GROUP BY date ORDER BY date DESC LIMIT 7")
    daily_data = cur.fetchall()
    cur.execute(f"SELECT name, SUM(duration) FROM timesheetlogs {where} GROUP BY name ORDER BY SUM(duration) DESC")
    user_hours = cur.fetchall()
    cur.execute(f"""
        SELECT date, SUM(CASE WHEN process != 'Breaks' THEN TIME_TO_SEC(duration) ELSE 0 END),
               SUM(CASE WHEN process = 'Breaks' THEN TIME_TO_SEC(duration) ELSE 0 END)
        FROM timesheetlogs {where} GROUP BY date ORDER BY date DESC LIMIT 7
    """)
    daily_wb = [(r[0], float(r[1])/3600.0, float(r[2])/3600.0) for r in cur.fetchall()]
    cur.execute(f"SELECT sub_process, SUM(duration) FROM timesheetlogs {where} GROUP BY sub_process ORDER BY SUM(duration) DESC")
    sub_data = cur.fetchall()
    cur.execute(f"SELECT name, date, project, process, sub_process, duration FROM timesheetlogs {where} ORDER BY date DESC LIMIT 100")
    
    def parse_time(v):
        try:
            parts = str(v).split(':')
            return int(parts[0]) + int(parts[1])/60.0 + (int(parts[2]) if len(parts)>2 else 0)/3600.0
        except: return 0.0
    table_data = [(r[0], r[1], r[2], r[3], r[4], parse_time(r[5])) for r in cur.fetchall()]

    u_query = "SELECT DISTINCT name FROM timesheetlogs"
    if me.role!="superadmin": u_query += f" WHERE team = '{me.team}'"
    cur.execute(u_query)
    users = [r[0] for r in cur.fetchall()]
    cur.close()

    return render_template("admin_dashboard.html", current_user=me, total_entries=total_entries,
                           total_users=total_users, total_work_hours=round(tot_work,2), total_break_hours=round(tot_break,2),
                           active_project_codes=active_projects, inactive_projects=inactive_projects,
                           process_data=proc_data, project_hours_data=proj_hours, daily_data=daily_data,
                           user_hours=user_hours, daily_work_break_data=daily_wb, sub_process_data=sub_data,
                           table_data=table_data, users=users, selected_user=s_user, start_date=s_date, end_date=e_date)

# ── API ROUTES ────────────────────────────────────────────────────────────

def _sec_to_hm(secs):
    secs = int(secs or 0)
    return f"{secs//3600:02d}:{(secs%3600)//60:02d}"

@app.route("/api/my-7day-hours", methods=["GET"])
@login_required
def api_my_7day_hours():
    end = date.today(); start = end - timedelta(days=6)
    user = User.query.filter_by(username=session["username"]).first()
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT date, SUM(CASE WHEN duration!='' THEN TIME_TO_SEC(duration) ELSE 0 END)
        FROM timesheetlogs WHERE name=%s AND date BETWEEN %s AND %s AND NOT (project='General' AND process='Breaks')
        GROUP BY date
    """, (user.username, start, end))
    d_map = {str(r[0]): int(r[1] or 0) for r in cur.fetchall()}; cur.close()
    
    series = []
    tot = 0
    d = start
    for _ in range(7):
        k = d.isoformat(); s = d_map.get(k, 0)
        series.append({"date": k, "hours_hms": _sec_to_hm(s), "hours_decimal": round(s/3600.0, 2)})
        tot += s; d += timedelta(days=1)
    return jsonify({"start_date": start.isoformat(), "end_date": end.isoformat(), "by_day": series,
                    "total_hours_hms": _sec_to_hm(tot), "total_hours_decimal": round(tot/3600.0, 2)})

@app.route("/api/my-monthly-hours", methods=["GET"])
@login_required
def api_my_monthly_hours():
    user = User.query.filter_by(username=session["username"]).first()
    today = date.today()
    s_curr = today.replace(day=1)
    s_prev = (s_curr - timedelta(days=1)).replace(day=1)
    e_prev = s_curr - timedelta(days=1)

    def get_h(s, e):
        cur = mysql.connection.cursor()
        cur.execute("SELECT SUM(CASE WHEN duration!='' THEN TIME_TO_SEC(duration) ELSE 0 END) FROM timesheetlogs WHERE name=%s AND date BETWEEN %s AND %s", (user.username, s, e))
        res = cur.fetchone()[0] or 0; cur.close()
        return float(res)

    curr_secs, prev_secs = get_h(s_curr, today), get_h(s_prev, e_prev)
    pct = ((curr_secs - prev_secs)/prev_secs)*100 if prev_secs else (100 if curr_secs else 0)
    return jsonify({"total_hours_hms": _sec_to_hm(curr_secs), "total_hours_decimal": round(curr_secs/3600, 2), "percent_change": round(pct, 1)})

@app.route("/api/quick-presets", methods=["GET"])
@login_required
def get_quick_presets():
    user = User.query.filter_by(username=session["username"]).first()
    return jsonify([{"id": p.id, "name": p.name, "project": p.project, "process": p.process, "sub_process": p.sub_process} for p in QuickTimerPreset.query.filter_by(user_id=user.id).all()])

@app.route("/api/quick-presets/add", methods=["POST"])
@login_required
def add_quick_preset():
    user = User.query.filter_by(username=session["username"]).first()
    d = request.get_json()
    if not all(d.get(k) for k in ["name","project","process","sub_process"]): return jsonify({"success":False}), 400
    p = QuickTimerPreset(user_id=user.id, name=d["name"], project=d["project"], process=d["process"], sub_process=d["sub_process"])
    db.session.add(p); db.session.commit()
    return jsonify({"success":True, "id":p.id}), 201

@app.route("/api/quick-presets/delete/<int:preset_id>", methods=["POST"])
@login_required
def delete_quick_preset(preset_id):
    user = User.query.filter_by(username=session["username"]).first()
    p = QuickTimerPreset.query.filter_by(id=preset_id, user_id=user.id).first()
    if p: db.session.delete(p); db.session.commit(); return jsonify({"success":True})
    return jsonify({"success":False}), 404

@app.route("/admin/live-status")
@role_required("superadmin", "admin")
def live_status():
    me = User.query.filter_by(username=session["username"]).first()
    today = date.today().isoformat()
    q = "SELECT name, team, project, process, sub_process, start_time FROM timesheetlogs WHERE date=%s AND end_time IS NULL"
    p = [today]
    if me.role=="admin" and me.team: q+=" AND team=%s"; p.append(me.team)
    q+=" ORDER BY team, name, start_time"
    cur = mysql.connection.cursor(); cur.execute(q, tuple(p))
    entries = cur.fetchall(); cur.close()
    return render_template("live_status.html", entries=entries, username=me.username, role=me.role, today_date=today)

# ── TIMER API ─────────────────────────────────────────────────────────────

@app.route("/api/timer/start", methods=["POST"])
@login_required
def start_timer_api():
    if session.get("active_timer"): return jsonify({"success":False, "message":"Timer already running"}), 409
    d = request.get_json()
    preset = QuickTimerPreset.query.get(d.get("id"))
    if not preset: return jsonify({"success":False}), 404

    user = User.query.filter_by(username=session["username"]).first()
    now = datetime.now()
    pc = ProjectCode.query.filter_by(code=preset.project).first()
    pt = pc.status if pc else "WIP"
    pcode, pmc, dis, cou = parse_project_fields(user.team, preset.project)

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO timesheetlogs (name, date, day, team, project, project_type, process, sub_process,
            start_time, end_time, duration, total_hours, project_code, project_type_mc, disease, country)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL, NULL, %s, %s, %s, %s)
        """, (user.username, now.strftime("%Y-%m-%d"), now.strftime("%A"), user.team, preset.project, pt,
              preset.process, preset.sub_process, now.strftime("%H:%M"), pcode, pmc, dis, cou))
        lid = cur.lastrowid; mysql.connection.commit(); cur.close()
        
        session["active_timer"] = {"db_id": lid, "name": preset.name, "start_time": now.isoformat(), "project": preset.project, "is_manual": False}
        session.modified = True
        return jsonify({"success":True, "timer": session["active_timer"]})
    except Exception as e:
        return jsonify({"success":False, "message":str(e)}), 500

@app.route("/api/timer/stop", methods=["POST"])
@login_required
def stop_timer_api():
    td = session.pop("active_timer", None)
    if not td: return jsonify({"success":False}), 404
    
    try:
        start_dt = datetime.fromisoformat(td["start_time"])
        end_dt = datetime.now()
        if end_dt <= start_dt: end_dt = start_dt + timedelta(seconds=1)
        dur = end_dt - start_dt; secs = int(dur.total_seconds())
        h, rem = divmod(secs, 3600); m, _ = divmod(rem, 60)
        dur_s = f"{h:02d}:{m:02d}"; tot_h = round(secs/3600, 2)
        
        cur = mysql.connection.cursor()
        cur.execute("UPDATE timesheetlogs SET end_time=%s, duration=%s, total_hours=%s WHERE id=%s",
                    (end_dt.strftime("%H:%M"), dur_s, tot_h, td["db_id"]))
        mysql.connection.commit(); cur.close()
        
        # 🔔 NOTIFY ADMIN (Work Done)
        me = User.query.filter_by(username=session["username"]).first()
        notify_admins_and_superadmins(me.team, f"Work Done: {me.username} finished '{td['project']}'", "WORK_LOG", exclude_user_id=me.id)
        db.session.commit()

        return jsonify({"success":True})
    except Exception as e:
        return jsonify({"success":False, "message":str(e)}), 500

@app.route("/api/manual/start", methods=["POST"])
@login_required
def start_manual_timer():
    if session.get("active_timer"): return jsonify({"success":False, "message":"Timer running"}), 409
    d = request.get_json()
    proj, proc, sub, start_t, date_s = d.get("project"), d.get("process"), d.get("sub_process"), d.get("start_time"), d.get("date")
    if not all([proj, proc, sub, start_t, date_s]): return jsonify({"success":False}), 400

    user = User.query.filter_by(username=session["username"]).first()
    day_s = datetime.strptime(date_s, "%Y-%m-%d").strftime("%A")
    pc = ProjectCode.query.filter_by(code=proj).first(); pt = pc.status if pc else "WIP"
    pcode, pmc, dis, cou = parse_project_fields(user.team, proj)

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO timesheetlogs (name, date, day, team, project, project_type, process, sub_process,
            start_time, end_time, duration, total_hours, project_code, project_type_mc, disease, country)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL, NULL, %s, %s, %s, %s)
        """, (user.username, date_s, day_s, user.team, proj, pt, proc, sub, start_t, pcode, pmc, dis, cou))
        lid = cur.lastrowid; mysql.connection.commit(); cur.close()
        
        session["active_timer"] = {"db_id": lid, "name": f"Manual: {proj}", "start_time": datetime.now().isoformat(), "project": proj, "is_manual": True}
        session.modified = True
        return jsonify({"success":True, "db_id": lid})
    except Exception as e:
        return jsonify({"success":False, "message":str(e)}), 500

@app.route("/api/manual/stop", methods=["POST"])
@login_required
def stop_manual_timer():
    db_id = request.form.get("active_db_id")
    end_t = request.form.get("end_time")
    start_t = request.form.get("start_time")
    td = session.get("active_timer")
    
    if not td or not db_id or str(td.get("db_id")) != db_id: return jsonify({"success":False}), 404
    
    try:
        s_dt = datetime.strptime(start_t, "%H:%M")
        e_dt = datetime.strptime(end_t, "%H:%M")
        dur = e_dt - s_dt; secs = int(dur.total_seconds())
        if secs < 0: secs += 24*3600
        h, rem = divmod(secs, 3600); m, _ = divmod(rem, 60)
        dur_s = f"{h:02d}:{m:02d}"; tot_h = round(secs/3600, 2)

        cur = mysql.connection.cursor()
        cur.execute("UPDATE timesheetlogs SET end_time=%s, duration=%s, total_hours=%s WHERE id=%s", (end_t, dur_s, tot_h, db_id))
        mysql.connection.commit(); cur.close()
        
        # 🔔 NOTIFY ADMIN
        me = User.query.filter_by(username=session["username"]).first()
        notify_admins_and_superadmins(me.team, f"Work Done: {me.username} manual log.", "WORK_LOG", exclude_user_id=me.id)
        db.session.commit()

        session.pop("active_timer", None); session.modified = True
        return jsonify({"success":True})
    except Exception as e:
        return jsonify({"success":False, "message":str(e)}), 500

@app.route("/api/manual/cancel", methods=["POST"])
@login_required
def cancel_manual_timer():
    td = session.pop("active_timer", None)
    if td and td.get("db_id"):
        try:
            cur = mysql.connection.cursor()
            cur.execute("DELETE FROM timesheetlogs WHERE id=%s", (td["db_id"],))
            mysql.connection.commit(); cur.close()
            return jsonify({"success":True})
        except: pass
    return jsonify({"success":False})

@app.route("/api/timer/status", methods=["GET"])
@login_required
def get_timer_status():
    t = session.get("active_timer")
    if t:
        st = datetime.fromisoformat(t["start_time"])
        sec = (datetime.now() - st).total_seconds()
        t["elapsed_time"] = f"{int(sec//3600):02d}:{int((sec%3600)//60):02d}:{int(sec%60):02d}"
        return jsonify({"active":True, "timer":t})
    return jsonify({"active":False})

# ── 🔔 API: NOTIFICATIONS ──────────────────────────────────────────

@app.route("/api/notifications", methods=["GET"])
@login_required
def get_notifications():
    user = User.query.filter_by(username=session["username"]).first()
    ns = UserNotification.query.filter_by(user_id=user.id).order_by(UserNotification.created_at.desc()).limit(50).all()
    return jsonify([{
        "id": n.id, "message": n.message, "type": n.notif_type,
        "is_read": n.is_read, "date": n.created_at.strftime("%Y-%m-%d %H:%M")
    } for n in ns])

@app.route("/api/notifications/read/<int:notif_id>", methods=["POST"])
@login_required
def mark_notification_read(notif_id):
    user = User.query.filter_by(username=session["username"]).first()
    n = UserNotification.query.filter_by(id=notif_id, user_id=user.id).first()
    if n: n.is_read = True; db.session.commit(); return jsonify({"success":True})
    return jsonify({"success":False}), 404

@app.route("/api/notifications/read-all", methods=["POST"])
@login_required
def mark_all_notifications_read():
    user = User.query.filter_by(username=session["username"]).first()
    UserNotification.query.filter_by(user_id=user.id, is_read=False).update({"is_read": True})
    db.session.commit()
    return jsonify({"success":True})

# ── BLUEPRINTS & MAIN ─────────────────────────────────────────────────────

if dashboard_bp:
    app.register_blueprint(dashboard_bp, url_prefix='/admin/dashboard')

if __name__ == "__main__":
    from os import environ
    port = int(environ.get("PORT", 7060))
    app.run(host="0.0.0.0", port=port, debug=True)