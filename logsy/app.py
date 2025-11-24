# ── app.py ──────────────────────────────────────────────────────────────────
from flask import (Flask, render_template_string, request, redirect, url_for,
                   session, flash, jsonify, render_template)
from functools import wraps
from datetime import datetime
import random, smtplib, os, io, shutil, tempfile
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy import create_engine, text
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash

# ── CONFIG ────────────────────────────────────────────────────────────────
app = Flask(__name__)

@app.route("/")
def landing():
    return render_template("landing.html")

app.secret_key = "vasanth"  # TODO: change to a strong secret in prod

DB_URI = "mysql+pymysql://appsadmin:appsadmin2025@34.93.75.171:3306/timesheet"
app.config["SQLALCHEMY_DATABASE_URI"] = DB_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db  = SQLAlchemy(app)

app.config["MYSQL_HOST"]     = "34.93.75.171"
app.config["MYSQL_USER"]     = "appsadmin"
app.config["MYSQL_PASSWORD"] = "appsadmin2025"
app.config["MYSQL_DB"]       = "timesheet"
app.config["MYSQL_PORT"]     = 3306
mysql = MySQL(app)                 # keeps your existing cursor usage
engine = create_engine(DB_URI)     # for raw ALTERs once

SMTP_SERVER   = "smtp.datasolve-analytics.com"
SMTP_PORT     = 587
WEBMAIL_USER  = "apps.admin@datasolve-analytics.com"
WEBMAIL_PASS  = "datasolve@2025"

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

class ProcessTable(db.Model):
    __tablename__  = "process_table"
    __table_args__ = {"extend_existing": True}

    id          = db.Column(db.Integer, primary_key=True)
    team        = db.Column("Team", db.String(100))
    process     = db.Column("Process", db.String(100))
    sub_process = db.Column("Sub-Process", db.String(100))

# 🆕 Project code masters
class ProjectCode(db.Model):
    __tablename__  = "project_codes"
    __table_args__ = {"extend_existing": True}

    id         = db.Column(db.Integer, primary_key=True)
    code       = db.Column(db.String(100), unique=True, nullable=False)
    status     = db.Column(db.Enum('YTI','WIP','Hold','Closed', name='project_status'),
                           default='WIP', nullable=False)
    team       = db.Column(db.String(100))
    start_date = db.Column(db.Date)
    end_date   = db.Column(db.Date)
    hold_on    = db.Column(db.Date)
    yti_end_date = db.Column(db.Date)  # ← NEW

# 🆕 Assignments: which user has which code, by which admin, and when
class UserProjectAssignment(db.Model):
    __tablename__  = "user_project_assignments"
    __table_args__ = {"extend_existing": True}

    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey("desktop_userstable.id"), nullable=False)
    project_id     = db.Column(db.Integer, db.ForeignKey("project_codes.id"), nullable=False)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey("desktop_userstable.id"), nullable=False)
    start_date     = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    end_date       = db.Column(db.Date, nullable=True)
    is_active      = db.Column(db.Boolean, default=True)

    user        = db.relationship("User", foreign_keys=[user_id])
    assigned_by = db.relationship("User", foreign_keys=[assigned_by_id])
    project     = db.relationship("ProjectCode", foreign_keys=[project_id])
#_____________________________________________________________________________________
# ── PROFILE MODEL (lives in another schema: mainapp) ─────────────
class UserProfile(db.Model):
    __tablename__  = "User_Profiles"
    __table_args__ = {"extend_existing": True, "schema": "mainapp"}  # <- important

    # If the table has no PK, Email_ID is a safe choice
    Email_ID  = db.Column(db.String(255), primary_key=True)
    Image_URL = db.Column(db.Text)
    Designation  = db.Column(db.String(200))
    Team         = db.Column(db.String(100))

# ── ONE‑OFF: add role column if it’s missing ──────────────────────────────
with engine.begin() as conn:
    res = conn.execute(text("SHOW COLUMNS FROM desktop_userstable LIKE 'role'")).fetchone()
    if not res:
        conn.execute(
            text(
                "ALTER TABLE desktop_userstable "
                "ADD COLUMN role ENUM('superadmin','admin','user') DEFAULT 'user'"
            )
        )

### ── HELPERS image ───────────────────────────────────────────────────────────────

import hashlib
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

@app.context_processor
def inject_gravatar():
    return dict(gravatar_url=gravatar_url)

@app.context_processor
def inject_profile_image():
    """
    Make profile_image_url, profile_name, employee_id, role available in all templates.
    """
    img_url = None
    display_name = session.get("username")
    email = session.get("email")
    employee_id = None
    full_name = None
    role = None

    try:
        # fallback if email not in session
        if not email and display_name:
            u = User.query.filter_by(username=display_name).first()
            email = u.email if u else None

        # ✅ Lookup User Profile from mainapp.User_Profiles
        if email:
            rec = (db.session.query(UserProfile.Email_ID, UserProfile.Image_URL, UserProfile.Designation)
                   .filter(UserProfile.Email_ID == email)
                   .first())
            if rec:
                img_url = rec[1]
                full_name = rec[2] or display_name  # Use "Name" column if exists

            # fetch Employee_ID separately if needed
            emp_row = db.session.execute(
                text("SELECT Employee_ID, Name FROM mainapp.User_Profiles WHERE Email_ID = :email"),
                {"email": email}
            ).fetchone()
            if emp_row:
                employee_id = emp_row[0]
                full_name = emp_row[1]

        # ✅ Role from desktop_userstable
        u = User.query.filter_by(username=display_name).first()
        if u:
            role = u.role

    except Exception as e:
        app.logger.exception("Profile inject failed: %s", e)

    return {
        "user_email": email,
        "profile_image_url": img_url,
        "profile_name": full_name or display_name,
        "employee_id": employee_id,
        "role": role,
    }


# ── HELPERS ───────────────────────────────────────────────────────────────

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

def send_otp(email, otp):
    msg = MIMEMultipart("alternative")
    msg["From"] = f"Timesheet App <{WEBMAIL_USER}>"
    msg["To"]   = email
    msg["Subject"] = "Your OTP"
    plain = f"OTP: {otp}"
    html  = f"<h3>Your OTP is <b>{otp}</b></h3>"
    msg.attach(MIMEText(plain,"plain"))
    msg.attach(MIMEText(html,"html"))
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
        s.starttls()
        s.login(WEBMAIL_USER, WEBMAIL_PASS)
        s.sendmail(WEBMAIL_USER, email, msg.as_string())

# 🆕 Visible (allowed) project codes for a user: only active + WIP
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

# ── AUTH ROUTES ───────────────────────────────────────────────────────────
@app.route("/signup", methods=["GET", "POST"])
def register():
    err = None
    if request.method == "POST":
        u = request.form["username"]
        e = request.form["email"]
        p = request.form["password"]
        t = request.form["team"]   # capture team

        # duplicate user / email check
        if User.query.filter((User.username == u) | (User.email == e)).first():
            err = "Username or email already exists"
            return render_template("register.html", err=err)

        code = random.randint(100_000, 999_999)
        new_user = User(
            username=u,
            email=e,
            password=generate_password_hash(p),
            verification_code=code,
            role="user",
            team=t
        )
        db.session.add(new_user)
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
        u, p = request.form["username"], request.form["password"]
        user = User.query.filter_by(username=u, verified=True).first()
        if user and check_password_hash(user.password,p):
            session["username"]=u
            session["email"] = user.email 
            # Redirect to welcome page
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
from datetime import datetime

@app.template_filter("todatetime")
def todatetime(value, fmt="%Y-%m-%d"):
    return datetime.strptime(value, fmt)
# ── DASHBOARD ROUTE (dynamic) ─────────────────────────────────────────────
@app.route("/home", methods=["GET"])
@login_required
def dashboard():
    today = datetime.now().strftime("%Y-%m-%d")

    # current user & role
    user = User.query.filter_by(username=session["username"]).first()
    role = user.role

    # last 10 entries for this user
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT name, date, day, project, project_type, team, process, sub_process,
            start_time, end_time, duration, duration, project_code, project_type_mc, disease, country, id
        FROM   timesheetlogs
        WHERE  name = %s
        ORDER  BY id DESC
        LIMIT  10
    """, (user.username,))
    entries = cur.fetchall()
    cur.close()

    # Team → Process → Sub‑Process map
    team_map = {}
    for row in ProcessTable.query.all():
        team_map.setdefault(row.team, {}) \
                .setdefault(row.process, set()) \
                .add(row.sub_process)

    team_json = {
        team: {proc: sorted(list(subs)) for proc, subs in proc_dict.items()}
        for team, proc_dict in team_map.items()
    }

    # Assigned WIP project codes for this user
    user_project_codes = get_visible_project_codes_for(user)

    return render_template(
        "dashboard.html",
        username=user.username,
        role=role,
        entries=entries,
        user_email=user.email, 
        today=today,
        team_json=team_json,
        user_project_codes=user_project_codes,
        user_team=user.team  # 👈 send logged-in user's team to auto-select in UI
    )



def promote_first_user():
    with app.app_context():
        db.create_all()  # ensure tables exist
        first = User.query.order_by(User.id).first()
        if first and first.role == "user":
            first.role = "superadmin"
            db.session.commit()

# ── ADMIN APIs / PAGES ────────────────────────────────────────────────────
@app.route("/api/process-master")
@login_required
def process_master():
    data = [dict(id=p.id, team=p.team, process=p.process,
                 sub_process=p.sub_process) for p in ProcessTable.query.all()]
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
            target.role = new_role
            target.team = new_team
            db.session.commit()
            flash(f"{target.username}'s role set to {new_role} and team set to {new_team}", "success")
        else:
            flash("User not found", "error")

    users = User.query.all()

    # 🔹 email -> profile image map from mainapp.User_Profiles
    emails = [u.email for u in users]
    email_img_map = {}
    if emails:
        rows = (
            db.session.query(UserProfile.Email_ID, UserProfile.Image_URL)
            .filter(UserProfile.Email_ID.in_(emails))
            .all()
        )
        email_img_map = {e: url for e, url in rows if url}

    current = User.query.filter_by(username=session["username"]).first()
    return render_template(
        "users.html",
        users=users,
        username=current.username,
        role=current.role,
        email_img_map=email_img_map,   # 👈 pass to Jinja
    )


##############################################################################################
@app.route("/process&subprocess", methods=["GET", "POST"])
@role_required("superadmin", "admin")  # super-admin & admin
def manage_process():
    me = User.query.filter_by(username=session["username"]).first()
    is_super = (me.role == "superadmin")

    if request.method == "POST":
        team     = request.form["team"].strip()
        process  = request.form["process"].strip()
        sub_proc = request.form["sub"].strip()
        if team and process and sub_proc:
            db.session.add(ProcessTable(team=team, process=process, sub_process=sub_proc))
            db.session.commit()
            flash("Row added", "ok")
        else:
            flash("All three fields are required", "error")

    # FILTER DROPDOWN values
    if is_super:
        all_rows = ProcessTable.query.all()
    else:
        all_rows = ProcessTable.query.filter_by(team=me.team).all()

    # Unique filter values
    teams = sorted({row.team for row in all_rows})
    processes = sorted({row.process for row in all_rows})
    sub_processes = sorted({row.sub_process for row in all_rows})

    # Dropdown selected values (from query params)
    selected_team = request.args.get("filter_team") or ''
    selected_process = request.args.get("filter_process") or ''
    selected_sub = request.args.get("filter_sub") or ''

    # Query for actual data rows with filter
    q = ProcessTable.query
    if not is_super:
        q = q.filter_by(team=me.team)
    if selected_team:
        q = q.filter_by(team=selected_team)
    if selected_process:
        q = q.filter_by(process=selected_process)
    if selected_sub:
        q = q.filter_by(sub_process=selected_sub)
    rows = q.order_by(ProcessTable.id).all()

    return render_template(
        "process.html",
        rows=rows,
        username=me.username,
        role=me.role,
        teams=teams,
        processes=processes,
        sub_processes=sub_processes,
        selected_team=selected_team,
        selected_process=selected_process,
        selected_sub=selected_sub
    )
@app.route('/admin/delete_process_row', methods=['POST'])
@role_required("superadmin", "admin")
def delete_process_row():
    data = request.get_json()
    row = ProcessTable.query.get(data['id'])
    if not row:
        return jsonify(success=False, error="Row not found")
    # Team restriction
    me = User.query.filter_by(username=session["username"]).first()
    if me.role != "superadmin" and row.team != me.team:
        return jsonify(success=False, error="Permission denied")
    db.session.delete(row)
    db.session.commit()
    return jsonify(success=True)

@app.route('/update_process_row', methods=['POST'])
@role_required("superadmin", "admin")
def update_process_row():
    data = request.get_json()
    row = ProcessTable.query.get(data['id'])
    if not row:
        return jsonify(success=False, error="Row not found")
    # Team restriction: only superadmin can change any row
    me = User.query.filter_by(username=session["username"]).first()
    if me.role != "superadmin" and row.team != me.team:
        return jsonify(success=False, error="Permission denied")
    row.team = data['team']
    row.process = data['process']
    row.sub_process = data['sub_process']
    db.session.commit()
    return jsonify(success=True)
###################################################################

# 🆕 Admin: create/update project codes
from datetime import datetime, date

from datetime import date

from datetime import date
from flask import render_template, request, redirect, url_for, flash, jsonify

@app.route("/allocations", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def admin_project_codes():
    me = User.query.filter_by(username=session["username"]).first()

    if request.method == "POST":
        code   = (request.form.get("code") or "").strip()
        status = (request.form.get("status") or "WIP").strip()
        team   = me.team

        if not code:
            flash("Code is required", "error")
            return redirect(url_for("admin_project_codes"))

        existing = ProjectCode.query.filter_by(code=code).first()
        today = date.today()

        if existing:
            prev_status = existing.status
            existing.status = status

            # ensure team set
            if not existing.team and team:
                existing.team = team

            # date rules
            if status == "WIP" and not existing.start_date:
                existing.start_date = today
            if status == "Closed" and not existing.end_date:
                existing.end_date = today
            if status == "Hold" and not existing.hold_on:
                existing.hold_on = today

            # leaving Hold -> clear hold_on (optional)
            if prev_status == "Hold" and status != "Hold":
                existing.hold_on = None

            db.session.commit()
            flash("Code updated", "success")
        else:
            pc = ProjectCode(code=code, status=status, team=team)
            if status == "WIP":
                pc.start_date = today
            elif status == "Closed":
                pc.end_date = today
            elif status == "Hold":
                pc.hold_on = today
            db.session.add(pc)
            db.session.commit()
            flash("Code created", "success")

        return redirect(url_for("admin_project_codes"))

    # LIST: superadmin -> all; admin -> only their team (if set)
    if me.role == "superadmin":
        q = ProjectCode.query
    else:
        q = ProjectCode.query.filter_by(team=me.team) if me.team else ProjectCode.query

    rows = q.order_by(ProjectCode.code.asc()).all()

    return render_template(
        "project_codes.html",
        rows=rows,
        username=me.username,
        role=me.role,
        team=me.team 
    )


# 🆕 Admin: assign/unassign project codes to users (team-scoped)
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

        # Bulk actions
        if action in ("bulk_assign", "bulk_end"):
            user_ids = request.form.getlist("user_ids")
            if not user_ids:
                flash("Select at least one user.", "error")
                return redirect(url_for("assign_projects"))

            assigned_count = 0
            ended_count = 0

            for uid in user_ids:
                target_user = User.query.get(int(uid))
                if not target_user:
                    continue
                if me.team and target_user.team != me.team:
                    continue

                if action == "bulk_assign":
                    exists = (UserProjectAssignment.query
                              .filter_by(user_id=target_user.id, project_id=int(pid), is_active=True)
                              .first())
                    if exists:
                        continue
                    db.session.add(UserProjectAssignment(
                        user_id=target_user.id,
                        project_id=int(pid),
                        assigned_by_id=me.id,
                        start_date=datetime.utcnow().date(),
                        is_active=True
                    ))
                    assigned_count += 1

                elif action == "bulk_end":
                    exists = (UserProjectAssignment.query
                              .filter_by(user_id=target_user.id, project_id=int(pid), is_active=True)
                              .first())
                    if exists:
                        exists.is_active = False
                        exists.end_date  = datetime.utcnow().date()
                        ended_count += 1

            db.session.commit()
            if action == "bulk_assign":
                flash(f"Assigned to {assigned_count} user(s).", "success")
            else:
                flash(f"Ended for {ended_count} user(s).", "success")

            return redirect(url_for("assign_projects"))

        # single assign/end (kept backward‑compatible)
        user_id  = request.form.get("user_id")
        code_id  = request.form.get("project_id")
        action   = request.form.get("action", "assign")
        if user_id and code_id:
            target_user = User.query.get(int(user_id))
            code        = ProjectCode.query.get(int(code_id))

            if not target_user or not code:
                flash("Invalid user or code", "error")
                return redirect(url_for("assign_projects"))

            if me.team and target_user.team != me.team:
                flash("You can manage only your team's users.", "error")
                return redirect(url_for("assign_projects"))

            if action == "assign":
                existing = (UserProjectAssignment.query
                            .filter_by(user_id=target_user.id, project_id=code.id, is_active=True)
                            .first())
                if existing:
                    flash("Already assigned", "info")
                else:
                    db.session.add(UserProjectAssignment(
                        user_id=target_user.id,
                        project_id=code.id,
                        assigned_by_id=me.id,
                        start_date=datetime.utcnow().date(),
                        is_active=True
                    ))
                    db.session.commit()
                    flash(f"Assigned {code.code} to {target_user.username}", "success")

            elif action == "end":
                existing = (UserProjectAssignment.query
                            .filter_by(user_id=target_user.id, project_id=code.id, is_active=True)
                            .first())
                if not existing:
                    flash("No active assignment found", "info")
                else:
                    existing.is_active = False
                    existing.end_date  = datetime.utcnow().date()
                    db.session.commit()
                    flash(f"Ended {code.code} for {target_user.username}", "success")

            return redirect(url_for("assign_projects"))

    # Build active list
    active = (
        UserProjectAssignment.query
        .join(User, UserProjectAssignment.user_id == User.id)
        .join(ProjectCode, UserProjectAssignment.project_id == ProjectCode.id)
        .filter(User.team == me.team if me.team else True)
        .filter(UserProjectAssignment.is_active == True)
        .all()
    )

    # Build assigned_map: project_id -> [user_id, ...]
    assigned_map = {}
    for a in active:
        assigned_map.setdefault(str(a.project_id), []).append(a.user_id)
        

    return render_template(
        "assign_projects.html",
        users=users, codes=codes, active=active,
        assigned_map=assigned_map,
        username=me.username, role=me.role
    )

# 🆕 API: current user's visible project codes
@app.route("/api/my-project-codes")
@login_required
def my_project_codes():
    user = User.query.filter_by(username=session["username"]).first()
    return jsonify(get_visible_project_codes_for(user))

# put this near your routes
# at top
import re

# Teams that use underscore-split format
PROJECT_SPLIT_TEAMS = {"MCTeam", "IPTeam", "AnalyticsTeam", "BDTeam", "MRTeam"}

def parse_project_fields(team: str, project: str):
    """
    Return (proj_code, proj_type_mc, disease, country) from `project`.
    For teams in PROJECT_SPLIT_TEAMS, we split on underscores into 4 parts.
    Otherwise, we keep project as code and leave others empty.
    """
    if not project:
        return "", "", "", ""

    proj = project.strip()

    if team not in PROJECT_SPLIT_TEAMS or "_" not in proj:
        # no structured pieces → treat entire string as project_code
        return proj, "", "", ""

    # split on one or more underscores to be tolerant (e.g., "MC__TYPE__DIS__IN")
    parts = re.split(r"_+", proj)
    # ensure exactly 4 fields (extra parts ignored)
    while len(parts) < 4:
        parts.append("")
    return parts[0], parts[1], parts[2], parts[3]


@app.route("/start", methods=["POST"])
@login_required
def start():
    name       = session["username"]
    date_str   = request.form["date"]
    team       = request.form["team"]
    project    = request.form["project"]
    process    = request.form["process"]
    sub_proc   = request.form["sub_process"]
    start_time = request.form["start_time"]
    end_time   = request.form["end_time"]

    pc = ProjectCode.query.filter_by(code=project).first()
    proj_type_db = pc.status if pc else "WIP"

    current_user = User.query.filter_by(username=name).first()
    allowed = {p["code"] for p in get_visible_project_codes_for(current_user)}
    if project not in allowed:
        flash("Selected project is not assigned to you or not WIP.", "error")
        return redirect("/home")

    # Day from date
    day = datetime.strptime(date_str, "%Y-%m-%d").strftime("%A")

    # Calculate duration
    dur = datetime.strptime(end_time, "%H:%M") - datetime.strptime(start_time, "%H:%M")
    seconds = int(dur.total_seconds())
    hours, remainder = divmod(seconds, 3600)
    minutes, _ = divmod(remainder, 60)

    # Store both formats
    duration_str = f"{hours:02}:{minutes:02}"      # HH:MM
    total_h = round(seconds / 3600, 2)             # decimal hours

    # Parse project fields
    proj_code, proj_type_mc, disease, country = parse_project_fields(team, project)

    # Insert
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO timesheetlogs
          (name, date, day, team, project, project_type, process, sub_process,
           start_time, end_time, duration, total_hours,
           project_code, project_type_mc, disease, country)
        VALUES
          (%s, %s, %s, %s, %s, %s, %s, %s,
           %s, %s, %s, %s,
           %s, %s, %s, %s)
    """, (name, date_str, day, team, project, proj_type_db, process, sub_proc,
          start_time, end_time, duration_str, total_h,
          proj_code, proj_type_mc, disease, country))
    mysql.connection.commit()
    cur.close()
    return redirect("/home")


from datetime import datetime
from urllib.parse import urlparse

# @app.route("/update-entry", methods=["POST"])
# @login_required
# def update_entry():
#     entry_id   = request.form.get("entry_id")
#     project    = request.form.get("project")
#     process    = request.form.get("process")
#     sub_proc   = request.form.get("sub_process")
#     start_time = request.form.get("start_time")
#     end_time   = request.form.get("end_time")
#     ptmc_manual= (request.form.get("project_type_mc") or "").strip()

#     cur = mysql.connection.cursor()
#     cur.execute("SELECT team FROM timesheetlogs WHERE id=%s", (entry_id,))
#     row = cur.fetchone()
#     team = row[0] if row else ""

#     # parse derived fields
#     proj_code, proj_type_mc, disease, country = parse_project_fields(team, project)
#     if ptmc_manual:
#         proj_type_mc = ptmc_manual

#     # duration calc
#     def to_time_obj(t):
#         for fmt in ("%H:%M:%S", "%H:%M"):
#             try:
#                 return datetime.strptime(t, fmt)
#             except ValueError:
#                 continue
#         raise ValueError(f"Invalid time format: {t}")

#     duration = None   # decimal
#     total_hours = None
#     if start_time and end_time:
#         try:
#             start_dt = to_time_obj(start_time)
#             end_dt   = to_time_obj(end_time)
#             dur = end_dt - start_dt

#             # ✅ convert to decimal hours
#             duration = round(dur.total_seconds() / 3600, 2)
#             total_hours = duration   # keep both same, unless you want different meaning
#         except Exception as e:
#             flash(f"Time error: {e}", "error")
#             cur.close()
#             return redirect(url_for("view_team_logs"))

#     if not total_hours and total_hours != 0:
#         total_hours = None

#     cur.execute("""
#         UPDATE timesheetlogs
#         SET project=%s, process=%s, sub_process=%s,
#             start_time=%s, end_time=%s, duration=%s, total_hours=%s,
#             project_code=%s, project_type_mc=%s, disease=%s, country=%s
#         WHERE id = %s
#     """, (project, process, sub_proc, start_time, end_time, duration, total_hours,
#           proj_code, proj_type_mc, disease, country, entry_id))
#     mysql.connection.commit()
#     cur.close()

#     flash("Entry updated successfully!", "success")
#     next_url = request.form.get("next") or request.referrer or url_for("view_team_logs")
#     return redirect(next_url)
# ______________________________________________________________
# @app.route("/update-entry", methods=["POST"])
# @login_required
# def update_entry():
#     """
#     Updates a timesheet entry.
#     - duration column stores "HH:MM"
#     - total_hours stores decimal hours (e.g., 1.15)
#     """
#     entry_id    = request.form.get("entry_id")
#     project     = request.form.get("project")
#     process     = request.form.get("process")
#     sub_proc    = request.form.get("sub_process")
#     start_time  = (request.form.get("start_time") or "").strip()
#     end_time    = (request.form.get("end_time") or "").strip()
#     ptmc_manual = (request.form.get("project_type_mc") or "").strip()

#     # --- helpers ---
#     def parse_hms(s: str):
#         """Return (h, m, s) ints from 'HH:MM' or 'HH:MM:SS'. Raises ValueError on bad input."""
#         if not s:
#             raise ValueError("empty time")
#         parts = s.split(":")
#         if len(parts) not in (2, 3):
#             raise ValueError(f"Invalid time: {s}")
#         h = int(parts[0]); m = int(parts[1]); s2 = int(parts[2]) if len(parts) == 3 else 0
#         if not (0 <= h < 24 and 0 <= m < 60 and 0 <= s2 < 60):
#             raise ValueError(f"Invalid time range: {s}")
#         return h, m, s2

#     def minutes_since_midnight(h, m, s=0) -> int:
#         # round down seconds into minutes; adjust if you later want to keep seconds
#         return h * 60 + m + (s // 60)

#     def hhmm_from_minutes(total_mins: int) -> str:
#         hours = total_mins // 60
#         mins  = total_mins % 60
#         return f"{hours:02d}:{mins:02d}"

#     # --- fetch team for project parsing ---
#     cur = mysql.connection.cursor()
#     try:
#         cur.execute("SELECT team FROM timesheetlogs WHERE id=%s", (entry_id,))
#         row = cur.fetchone()
#         team = row[0] if row else ""
#     except Exception as e:
#         cur.close()
#         flash(f"DB error while reading team: {e}", "error")
#         return redirect(request.referrer or url_for("view_team_logs"))

#     # derive code/type/disease/country from "project" + team (your existing util)
#     proj_code, proj_type_mc, disease, country = parse_project_fields(team, project)
#     if ptmc_manual:
#         proj_type_mc = ptmc_manual

#     # --- duration calc (decimal + HH:MM string) ---
#     duration_dec  = None   # float hours rounded to 2 decimals (for analytics)
#     duration_hhmm = None   # "HH:MM" string (to store in timesheetlogs.duration)

#     if start_time and end_time:
#         try:
#             sh, sm, ss = parse_hms(start_time)
#             eh, em, es = parse_hms(end_time)

#             s_min = minutes_since_midnight(sh, sm, ss)
#             e_min = minutes_since_midnight(eh, em, es)

#             # handle cross-midnight by wrapping 24h
#             delta_min = (e_min - s_min) % (24 * 60)

#             # Optionally forbid zero duration
#             # if delta_min == 0:
#             #     raise ValueError("Start and End times produce 00:00 duration")

#             duration_dec  = round(delta_min / 60.0, 2)     # e.g., 1.15
#             duration_hhmm = hhmm_from_minutes(delta_min)   # e.g., "01:09"

#         except Exception as e:
#             cur.close()
#             flash(f"Time error: {e}", "error")
#             return redirect(request.referrer or url_for("view_team_logs"))

#     # keep total_hours (decimal) for analytics, store HH:MM in duration
#     total_hours = duration_dec if duration_dec is not None else None

#     # --- build UPDATE payload ---
#     params = [
#         project, process, sub_proc,
#         (start_time or None), (end_time or None),
#         (duration_hhmm or None),  # <-- store "HH:MM"
#         total_hours,              # <-- decimal in total_hours
#         proj_code, proj_type_mc, disease, country,
#         entry_id
#     ]

#     try:
#         cur.execute("""
#             UPDATE timesheetlogs
#             SET project=%s, process=%s, sub_process=%s,
#                 start_time=%s, end_time=%s,
#                 duration=%s,          -- "HH:MM"
#                 total_hours=%s,       -- decimal
#                 project_code=%s, project_type_mc=%s, disease=%s, country=%s
#             WHERE id=%s
#         """, params)
#         mysql.connection.commit()
#     except Exception as e:
#         mysql.connection.rollback()
#         cur.close()
#         flash(f"DB error while updating entry: {e}", "error")
#         return redirect(request.referrer or url_for("view_team_logs"))

#     cur.close()
#     flash("Entry updated successfully!", "success")
#     next_url = request.form.get("next") or request.referrer or url_for("view_team_logs")
#     return redirect(next_url)



# from datetime import datetime, timedelta, time

# @app.route("/team-logs", methods=["GET", "POST"])
# @role_required("superadmin", "admin")
# def view_team_logs():
#     current_user = User.query.filter_by(username=session["username"]).first()
#     team = current_user.team

#     filter_user = request.form.get("username") if request.method == "POST" else None
#     filter_project = request.form.get("project") if request.method == "POST" else None
#     filter_process = request.form.get("process") if request.method == "POST" else None
#     filter_sub_process = request.form.get("sub_process") if request.method == "POST" else None
#     filter_date = request.form.get("date") if request.method == "POST" else None  # Optional: date filter
#     editing_id = request.args.get("editing_id")  # ✅ added for edit-row logic

#     query = """
#         SELECT name, date, day, project, team, process, sub_process,
#                start_time, end_time, duration, duration, id
#         FROM timesheetlogs
#         WHERE team = %s
#     """
#     values = [team]

#     if filter_user:
#         query += " AND name = %s"
#         values.append(filter_user)
#     if filter_project:
#         query += " AND project = %s"
#         values.append(filter_project)
#     if filter_process:
#         query += " AND process = %s"
#         values.append(filter_process)
#     if filter_sub_process:
#         query += " AND sub_process = %s"
#         values.append(filter_sub_process)
#     if filter_date:
#         query += " AND date = %s"
#         values.append(filter_date)

#     query += " ORDER BY id DESC LIMIT 50"

#     cur = mysql.connection.cursor()
#     cur.execute(query, tuple(values))
#     raw_logs = cur.fetchall()

#     # Fetch distinct dropdown values
#     cur.execute("SELECT DISTINCT project FROM timesheetlogs WHERE team = %s", (team,))
#     projects = [r[0] for r in cur.fetchall() if r[0]]

#     cur.execute("SELECT DISTINCT process FROM timesheetlogs WHERE team = %s", (team,))
#     processes = [r[0] for r in cur.fetchall() if r[0]]

#     cur.execute("SELECT DISTINCT sub_process FROM timesheetlogs WHERE team = %s", (team,))
#     sub_processes = [r[0] for r in cur.fetchall() if r[0]]

#     cur.close()

#     # Format time
#     logs = []
#     for row in raw_logs:
#         row = list(row)
#         row[7] = format_time_for_input(row[7])
#         row[8] = format_time_for_input(row[8])
#         logs.append(row)

#     users = User.query.filter_by(team=team).all()

#     return render_template(
#         "team_logs.html",
#         logs=logs,
#         users=users,
#         projects=projects,
#         processes=processes,
#         sub_processes=sub_processes,
#         username=current_user.username,
#         role=current_user.role,
#         editing_id=editing_id  # ✅ pass this to Jinja
#     )
from datetime import datetime, timedelta, time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from flask import request, redirect, url_for, flash, render_template, session

# ---------- helpers ----------
def format_time_for_input(val):
    """
    Return 'HH:MM' for a DB time value.
    Accepts None, 'HH:MM', 'HH:MM:SS', datetime.time, datetime.datetime.
    """
    if val is None:
        return ""
    # If it's a datetime.time
    if isinstance(val, time):
        return f"{val.hour:02d}:{val.minute:02d}"
    # If it's a datetime
    if isinstance(val, datetime):
        return f"{val.hour:02d}:{val.minute:02d}"
    # Else assume string
    s = str(val).strip()
    if not s:
        return ""
    parts = s.split(":")
    try:
        h = int(parts[0])
        m = int(parts[1]) if len(parts) > 1 else 0
        return f"{h:02d}:{m:02d}"
    except Exception:
        # best-effort fallback
        return s[:5] if len(s) >= 5 else s

def safe_parse_project_fields(team, project):
    """
    Use your existing parse_project_fields(team, project) if present.
    Returns (proj_code, proj_type_mc, disease, country)
    """
    try:
        return parse_project_fields(team, project)  # your util
    except NameError:
        return (None, None, None, None)

def _strip_param(url, param_name="editing_id"):
    """Remove a query param from url."""
    try:
        pu = urlparse(url)
        q = [(k, v) for (k, v) in parse_qsl(pu.query, keep_blank_values=True) if k != param_name]
        return urlunparse((pu.scheme, pu.netloc, pu.path, pu.params, urlencode(q), pu.fragment))
    except Exception:
        return url

# ---------- UPDATE ENTRY ----------
@app.route("/update-entry", methods=["POST"])
@login_required
def update_entry():
    """
    Updates a timesheet entry.
    - duration: stores 'HH:MM'
    - total_hours: decimal hours (e.g., 1.25)
    """
    entry_id    = (request.form.get("entry_id") or "").strip()
    project     = (request.form.get("project") or "").strip()
    process     = (request.form.get("process") or "").strip()
    sub_proc    = (request.form.get("sub_process") or "").strip()
    start_time  = (request.form.get("start_time") or "").strip()
    end_time    = (request.form.get("end_time") or "").strip()
    ptmc_manual = (request.form.get("project_type_mc") or "").strip()
    next_url    = (request.form.get("next") or request.referrer or url_for("view_team_logs"))

    # Current user + permissions
    current_user = User.query.filter_by(username=session.get("username")).first()
    if not current_user:
        flash("Not authenticated.", "error")
        return redirect(url_for("view_team_logs"))

    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT team FROM timesheetlogs WHERE id=%s", (entry_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            flash("Entry not found.", "error")
            return redirect(url_for("view_team_logs"))
        entry_team = row[0]

        # Enforce: admin can only edit their team; superadmin can edit any
        if current_user.role != "superadmin" and current_user.team != entry_team:
            cur.close()
            flash("You don't have permission to edit this entry.", "error")
            return redirect(url_for("view_team_logs"))
    except Exception as e:
        cur.close()
        flash(f"DB error while reading entry: {e}", "error")
        return redirect(url_for("view_team_logs"))

    # Basic validations
    if not (project and process and sub_proc and start_time and end_time):
        cur.close()
        flash("All fields are required.", "error")
        # stay in edit mode
        return redirect(url_for("view_team_logs", editing_id=entry_id))

    # time helpers
    def parse_hms(s: str):
        parts = s.split(":")
        if len(parts) not in (2, 3):
            raise ValueError(f"Invalid time: {s}")
        h = int(parts[0]); m = int(parts[1]); s2 = int(parts[2]) if len(parts) == 3 else 0
        if not (0 <= h < 24 and 0 <= m < 60 and 0 <= s2 < 60):
            raise ValueError(f"Invalid time range: {s}")
        return h, m, s2

    def minutes_since_midnight(h, m, s=0) -> int:
        return h * 60 + m + (s // 60)

    def hhmm_from_minutes(total_mins: int) -> str:
        hours = total_mins // 60
        mins  = total_mins % 60
        return f"{hours:02d}:{mins:02d}"

    # derive code/type/disease/country
    proj_code, proj_type_mc, disease, country = safe_parse_project_fields(entry_team, project)
    if ptmc_manual:
        proj_type_mc = ptmc_manual

    # duration calc (supports cross-midnight)
    try:
        sh, sm, ss = parse_hms(start_time)
        eh, em, es = parse_hms(end_time)
        s_min = minutes_since_midnight(sh, sm, ss)
        e_min = minutes_since_midnight(eh, em, es)
        delta_min = (e_min - s_min) % (24 * 60)
        duration_hhmm = hhmm_from_minutes(delta_min)
        total_hours = round(delta_min / 60.0, 2)
    except Exception as e:
        cur.close()
        flash(f"Time error: {e}", "error")
        return redirect(url_for("view_team_logs", editing_id=entry_id))

    # UPDATE (also guard by team for admins)
    try:
        if current_user.role == "superadmin":
            where_clause = "WHERE id=%s"
            where_params = (entry_id,)
        else:
            where_clause = "WHERE id=%s AND team=%s"
            where_params = (entry_id, entry_team)

        params = [
            project, process, sub_proc,
            start_time, end_time,
            duration_hhmm, total_hours,
            proj_code, proj_type_mc, disease, country
        ] + list(where_params)

        cur.execute(f"""
            UPDATE timesheetlogs
               SET project=%s,
                   process=%s,
                   sub_process=%s,
                   start_time=%s,
                   end_time=%s,
                   duration=%s,            -- 'HH:MM'
                   total_hours=%s,         -- decimal
                   project_code=%s,
                   project_type_mc=%s,
                   disease=%s,
                   country=%s
             {where_clause}
        """, tuple(params))
        mysql.connection.commit()
    except Exception as e:
        mysql.connection.rollback()
        flash(f"DB error while updating entry: {e}", "error")
        cur.close()
        return redirect(url_for("view_team_logs", editing_id=entry_id))
    finally:
        cur.close()

    # Ensure we return WITHOUT editing_id even if frontend didn't set 'next'
    next_url = _strip_param(next_url, "editing_id")
    flash("Entry updated successfully!", "success")
    return redirect(next_url)


# ---------- TEAM LOGS (fixed total_hours in SELECT) ----------
from math import ceil
from datetime import datetime, timedelta, time

@app.route("/team-logs", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def view_team_logs():
    current_user = User.query.filter_by(username=session["username"]).first()
    team = current_user.team

    # ---- Filters (GET/POST la irundhalum pick pannuvom) ----
    is_post = (request.method == "POST")
    getf = request.form.get if is_post else request.args.get

    filter_user       = (request.form.get("username") if is_post else request.args.get("username")) or None
    filter_project    = (request.form.get("project")  if is_post else request.args.get("project"))  or None
    filter_process    = (request.form.get("process")  if is_post else request.args.get("process"))  or None
    filter_sub_process= (request.form.get("sub_process") if is_post else request.args.get("sub_process")) or None
    filter_date       = (request.form.get("date")     if is_post else request.args.get("date"))     or None
    editing_id        = request.args.get("editing_id")

    # ---- Pagination params ----
    def _to_int(x, d):  # safe int
        try: return int(x)
        except: return d

    page = _to_int((request.form.get("page") or request.args.get("page")), 1)
    per_page = _to_int((request.form.get("per_page") or request.args.get("per_page")), 50)

    # clamp per_page to allowed options
    allowed_pp = {50, 100, 200, 500, 1000}
    if per_page not in allowed_pp:
        per_page = 50
    if page < 1:
        page = 1

    # ---- Build base WHERE + values once (reuse for COUNT + SELECT) ----
    where_sql = ["team = %s"]
    values = [team]

    if filter_user:
        where_sql.append("name = %s"); values.append(filter_user)
    if filter_project:
        where_sql.append("project = %s"); values.append(filter_project)
    if filter_process:
        where_sql.append("process = %s"); values.append(filter_process)
    if filter_sub_process:
        where_sql.append("sub_process = %s"); values.append(filter_sub_process)
    if filter_date:
        where_sql.append("date = %s"); values.append(filter_date)

    where_clause = " AND ".join(where_sql)

    cur = mysql.connection.cursor()

    # ---- COUNT(*) for total pages ----
    count_q = f"SELECT COUNT(*) FROM timesheetlogs WHERE {where_clause}"
    cur.execute(count_q, tuple(values))
    total_rows = cur.fetchone()[0] if cur.rowcount != -1 else 0

    total_pages = max(1, ceil(total_rows / per_page)) if total_rows else 1
    if page > total_pages:
        page = total_pages

    offset = (page - 1) * per_page

    # ---- Main SELECT with LIMIT/OFFSET (IMPORTANT CHANGE) ----
    select_q = f"""
        SELECT name, date, day, project, team, process, sub_process,
               start_time, end_time, duration, total_hours, id
        FROM timesheetlogs
        WHERE {where_clause}
        ORDER BY id DESC
        LIMIT %s OFFSET %s
    """
    cur.execute(select_q, tuple(values + [per_page, offset]))
    raw_logs = cur.fetchall()

    # ---- Dropdown values (unchanged) ----
    cur.execute("SELECT DISTINCT project FROM timesheetlogs WHERE team = %s", (team,))
    projects = [r[0] for r in cur.fetchall() if r[0]]

    cur.execute("SELECT DISTINCT process FROM timesheetlogs WHERE team = %s", (team,))
    processes = [r[0] for r in cur.fetchall() if r[0]]

    cur.execute("SELECT DISTINCT sub_process FROM timesheetlogs WHERE team = %s", (team,))
    sub_processes = [r[0] for r in cur.fetchall() if r[0]]

    cur.close()

    # ---- Format time fields for inputs ----
    logs = []
    for row in raw_logs:
        row = list(row)
        row[7] = format_time_for_input(row[7])  # start_time
        row[8] = format_time_for_input(row[8])  # end_time
        logs.append(row)

    users = User.query.filter_by(team=team).all()

    # Pass pagination vars to template
    return render_template(
        "team_logs.html",
        logs=logs,
        users=users,
        projects=projects,
        processes=processes,
        sub_processes=sub_processes,
        username=current_user.username,
        role=current_user.role,
        editing_id=editing_id,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_rows=total_rows
    )


# # 🔧 Time formatting helper
# def format_time_for_input(val):
#     try:
#         if isinstance(val, time):
#             return val.strftime("%H:%M")
#         elif isinstance(val, datetime):
#             return val.time().strftime("%H:%M")
#         elif isinstance(val, timedelta):
#             return (datetime.min + val).strftime("%H:%M")
#         elif isinstance(val, str) and ":" in val:
#             return val[:5]
#     except:
#         pass
#     return ""
# Example model fields assumed:
# ProjectCode(id, code, status, team, start_date, end_date, hold_on)

from flask import request, jsonify
from datetime import date

@app.post("/project-codes/update-status", endpoint="update_project_status")
@role_required("superadmin", "admin")
def update_project_status():
    me = User.query.filter_by(username=session["username"]).first()
    data = request.get_json(silent=True) or {}
    rec_id = data.get("id")
    new_status = (data.get("status") or "").strip()

    if not rec_id or new_status not in {"WIP","YTI","Hold","Closed"}:
        return jsonify(ok=False, message="Invalid id or status"), 400

    rec = ProjectCode.query.get(rec_id)
    if not rec:
        return jsonify(ok=False, message="Record not found"), 404

    # team guard: admin can only touch their team; superadmin can touch all
    if me.role != "superadmin":
        if me.team and rec.team and rec.team != me.team:
            return jsonify(ok=False, message="Forbidden for this team"), 403

    today = date.today()
    prev_status = rec.status
    rec.status = new_status

    # date rules
    if new_status == "WIP" and not rec.start_date:
        rec.start_date = today
    if new_status == "Closed" and not rec.end_date:
        rec.end_date = today
    if new_status == "Hold" and not rec.hold_on:
        rec.hold_on = today

    # leaving Hold -> clear hold_on
    if prev_status == "Hold" and new_status != "Hold":
        rec.hold_on = None
    # NEW: leaving YTI → set yti_end_date once
    if prev_status == "YTI" and new_status != "YTI" and not rec.yti_end_date:
        rec.yti_end_date = today

    db.session.commit()

    return jsonify(
        ok=True,
        id=rec.id,
        status=rec.status,
        start_date=rec.start_date.isoformat() if rec.start_date else "",
        end_date=rec.end_date.isoformat() if rec.end_date else "",
        hold_on=rec.hold_on.isoformat() if rec.hold_on else "",
        yti_end_date=rec.yti_end_date.isoformat() if rec.yti_end_date else "" 
    ), 200

#── USER ↔ PROJECT ACCESS (per-user assignment manager) ───────────────────
@app.route("/admin/user-access", methods=["GET", "POST"], endpoint="user_access")
@role_required("superadmin", "admin")
def user_access():
    me = User.query.filter_by(username=session["username"]).first()

    # Team-scoped users/codes for admins; superadmin sees all
    users_q = User.query
    codes_q = ProjectCode.query.filter(ProjectCode.status.in_(["WIP", "YTI", "Hold"]))  # show active-ish codes
    if me.role != "superadmin" and me.team:
        users_q = users_q.filter_by(team=me.team)
        codes_q = codes_q.filter_by(team=me.team)

    users = users_q.order_by(User.username.asc()).all()
    codes = codes_q.order_by(ProjectCode.code.asc()).all()

    # Which user are we looking at?
    selected_user_id = request.values.get("user_id", type=int)
    selected_user = User.query.get(selected_user_id) if selected_user_id else (users[0] if users else None)

    # On POST: add/remove selections
    if request.method == "POST" and selected_user:
        action = request.form.get("action")
        code_ids = request.form.getlist("code_ids")  # list of strings
        code_ids = [int(cid) for cid in code_ids]

        added, removed = 0, 0
        if action == "add":
            for cid in code_ids:
                already = (UserProjectAssignment.query
                           .filter_by(user_id=selected_user.id, project_id=cid, is_active=True)
                           .first())
                if not already:
                    db.session.add(UserProjectAssignment(
                        user_id=selected_user.id,
                        project_id=cid,
                        assigned_by_id=me.id,
                        start_date=datetime.utcnow().date(),
                        is_active=True
                    ))
                    added += 1
            db.session.commit()
            flash(f"Added {added} project(s) to {selected_user.username}.", "success")

        elif action == "remove":
            # End active assignments for those codes
            rows = (UserProjectAssignment.query
                    .filter(UserProjectAssignment.user_id == selected_user.id,
                            UserProjectAssignment.project_id.in_(code_ids),
                            UserProjectAssignment.is_active == True)
                    .all())
            for r in rows:
                r.is_active = False
                r.end_date  = datetime.utcnow().date()
                removed += 1
            db.session.commit()
            flash(f"Removed {removed} project(s) from {selected_user.username}.", "success")

        return redirect(url_for("user_access", user_id=selected_user.id))

    # Build current active assignments for the selected user
    assigned_ids = set()
    assigned_rows = []
    if selected_user:
        rows = (UserProjectAssignment.query
                .join(ProjectCode, UserProjectAssignment.project_id == ProjectCode.id)
                .filter(UserProjectAssignment.user_id == selected_user.id,
                        UserProjectAssignment.is_active == True)
                .order_by(ProjectCode.code.asc())
                .all())
        for r in rows:
            assigned_ids.add(r.project_id)
            assigned_rows.append(r)
    # ---- build avatar map (email -> image) and selected avatar ----
    # ---- avatar map + selected user's role/team from profile ----
    emails = [u.email for u in users if u.email]
    email_to_img = {}
    if emails:
        rows = (db.session.query(UserProfile.Email_ID, UserProfile.Image_URL)
                .filter(UserProfile.Email_ID.in_(emails)).all())
        email_to_img = {e: url for e, url in rows if url}

    fallback_img = url_for('static', filename='img/avatar-default.png')
    avatar_map = {u.id: (email_to_img.get(u.email) or gravatar_url(u.email, 96) or fallback_img)
                  for u in users}
    selected_avatar = fallback_img
    selected_role = None
    selected_team = None
    if selected_user:
        # prefer profile values; fallback to desktop_userstable
        pr_role, pr_team, pr_img = get_profile_for_email(selected_user.email)
        selected_role = pr_role or selected_user.role
        selected_team = pr_team or selected_user.team
        selected_avatar = pr_img or avatar_map.get(selected_user.id, fallback_img)

    return render_template(
        "user_access.html",
        users=users,
        codes=codes,
        selected_user=selected_user,
        assigned_ids=assigned_ids,
        assigned_rows=assigned_rows,
        username=me.username,
        role=me.role,
        avatar_map=avatar_map,            # 👈
        selected_avatar=selected_avatar,
        selected_role=selected_role,      # 👈 pass role from profile
        selected_team=selected_team   # 👈

    )

@app.route("/admin/user-project-matrix", methods=["GET"], endpoint="user_project_matrix")
@role_required("superadmin", "admin")
def user_project_matrix():
    me = User.query.filter_by(username=session["username"]).first()

    # Team scope: admin → own team; superadmin → all
    users_q = User.query.order_by(User.username.asc())
    if me.role != "superadmin" and me.team:
        users_q = users_q.filter_by(team=me.team)
    users = users_q.all()

    # pull all active assignments for these users in one shot
    user_ids = [u.id for u in users]
    assignments = []
    if user_ids:
        assignments = (
            UserProjectAssignment.query
            .join(ProjectCode, UserProjectAssignment.project_id == ProjectCode.id)
            .filter(UserProjectAssignment.user_id.in_(user_ids),
                    UserProjectAssignment.is_active == True)
            .order_by(ProjectCode.code.asc())
            .all()
        )

    # map: user_id -> [ (code, status) ... ]
    mapping = {u.id: [] for u in users}
    for r in assignments:
        mapping.setdefault(r.user_id, []).append((r.project.code, r.project.status))

    return render_template(
        "user_project_matrix.html",
        users=users,
        mapping=mapping,
        username=me.username,
        role=me.role
    )

from datetime import datetime, timedelta

@app.route("/admin/admin/dashboard", methods=["GET", "POST"])
@role_required("superadmin", "admin")
def admin_dashboard():
    current_user = User.query.filter_by(username=session["username"]).first()
    team_filter = "" if current_user.role == "superadmin" else f"WHERE team = '{current_user.team}'"

    date_filter = ""
    if request.method == "POST":
        start = request.form.get("start_date")
        end = request.form.get("end_date")
        if start and end:
            date_filter = f" AND date BETWEEN '{start}' AND '{end}'"
    
    cur = mysql.connection.cursor()

    # Apply filters
    where_clause = f"{team_filter} {date_filter}".strip()
    if where_clause and not where_clause.lower().startswith("where"):
        where_clause = "WHERE " + where_clause

    # Use where_clause for all queries...
    cur.execute(f"SELECT COUNT(*) FROM timesheetlogs {where_clause}")
    total_entries = cur.fetchone()[0]

    cur.execute(f"SELECT COUNT(DISTINCT name) FROM timesheetlogs {where_clause}")
    total_users = cur.fetchone()[0]

    cur.execute(f"SELECT SUM(duration) FROM timesheetlogs {where_clause}")
    total_hours = cur.fetchone()[0] or 0

    cur.execute(f"SELECT DISTINCT project FROM timesheetlogs {team_filter}")
    active_projects = [row[0] for row in cur.fetchall()]

    cur.execute(f"""
        SELECT project_type, COUNT(*) FROM timesheetlogs {where_clause} GROUP BY project_type
    """)
    project_type_data = cur.fetchall()

    cur.execute(f"""
        SELECT process, COUNT(*) FROM timesheetlogs {where_clause} GROUP BY process
    """)
    process_data = cur.fetchall()

    cur.execute(f"""
        SELECT date, SUM(duration) FROM timesheetlogs {where_clause}
        GROUP BY date ORDER BY date DESC LIMIT 7
    """)
    daily_data = cur.fetchall()

    cur.execute(f"""
        SELECT name, SUM(duration) FROM timesheetlogs {where_clause}
        GROUP BY name ORDER BY SUM(duration) DESC
    """)
    user_hours = cur.fetchall()

    cur.execute(f"""
        SELECT name, date, project, process, sub_process, duration FROM timesheetlogs {where_clause}
        ORDER BY date DESC LIMIT 100
    """)
    table_data = cur.fetchall()
    cur.execute("SELECT DISTINCT name FROM timesheetlogs")
    users = [u[0] for u in cur.fetchall()]

    cur.close()

    return render_template("admin_dashboard.html",
    total_entries=total_entries,
    total_users=total_users,
    total_hours=round(total_hours, 2),
    active_projects=active_projects,
    project_type_data=project_type_data,
    process_data=process_data,
    daily_data=daily_data,
    user_hours=user_hours,
    table_data=table_data,
    users=users
)


# ── MAIN ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    promote_first_user()   # ensure tables + first user -> superadmin (once)
    # db.create_all() is already called inside promote_first_user
    app.run(debug=True, port=8003)
