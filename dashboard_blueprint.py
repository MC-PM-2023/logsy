# dashboard_blueprint.py
import pandas as pd
from sqlalchemy import create_engine, text
from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for
from datetime import date, timedelta
from typing import Dict, Any, List, Tuple
from functools import wraps
from urllib.parse import quote_plus
import os
# # ----------------- Database and Configuration -----------------
# db_config = {
#     'host': '34.93.75.171',
#     'port': 3306,
#     'user': 'appsadmin',
#     'password': 'appsadmin2025',
#     'database': 'timesheet'
# }

# engine = create_engine(
#     f"mysql+pymysql://{db_config['user']}:{db_config['password']}@"
#     f"{db_config['host']}:{db_config['port']}/{db_config['database']}"
# )
# ----------------- Database and Configuration deploy ------------------
db_config = {
    "user":     os.environ.get("DB_USER", "appsadmin"),
    "password": os.environ.get("DB_PASS", "appsadmin2025"),
    "database": os.environ.get("DB_NAME", "timesheet"),
    "unix_socket": os.environ.get(
        "INSTANCE_UNIX_SOCKET",
        "/cloudsql/theta-messenger-459613-p7:asia-south1:appsadmin"
    ),
}

# unix socket path la '/' irukkum, adhunaala safe side escape pannalam
socket_escaped = quote_plus(db_config["unix_socket"])

DB_URI = (
    f"mysql+pymysql://{db_config['user']}:{db_config['password']}@/"
    f"{db_config['database']}?unix_socket={socket_escaped}"
)

engine = create_engine(DB_URI)
#_________________________end__________________________________


# # ----------------- Blueprint Initialization -----------------
dashboard_bp = Blueprint('dashboard_bp', __name__, template_folder='dashboard_templates')

# ----------------- Auth wrapper -----------------
def check_dashboard_access(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_dashboard_api = (
            request.blueprint == "dashboard_bp"
            and request.endpoint == "dashboard_bp.get_dashboard_data"
        )
        if "username" not in session:
            if is_dashboard_api:
                return jsonify({"error": "Unauthorized Access", "details": "Login required."}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# ----------------- Helpers -----------------
def seconds_to_hhmmss(total_seconds: float | int | None) -> str:
    if total_seconds is None:
        return "00:00:00"
    s = int(round(total_seconds))
    h = s // 3600
    m = (s % 3600) // 60
    sec = s % 60
    return f"{h:02d}:{m:02d}:{sec:02d}"

FILTER_KEYS: List[str] = ['project', 'process', 'team', 'sub_process', 'name', 'project_type']

def get_default_dates() -> Tuple[str, str]:
    default_start = '2000-01-01'
    future_date = date.today() + timedelta(days=5 * 365)
    default_end = future_date.strftime('%Y-%m-%d')
    return default_start, default_end

def fetch_and_process_data_from_db(start_date: str, end_date: str, user_role: str, user_team: str) -> Dict[str, Any]:
    role_norm = (user_role or '').strip().lower()
    team_norm = (user_team or '').strip()

    where_clauses = ["`date` BETWEEN :start AND :end"]
    params = {"start": start_date, "end": end_date}

    # 🛠️ lock to team for non-superadmin
    if role_norm != 'superadmin' and team_norm:
        where_clauses.append("team = :team")
        params["team"] = team_norm

    where_clause = " AND ".join(where_clauses)

    query = f"""
        SELECT
            id,
            name,
            team,
            `date`,
            project,
            process,
            sub_process,
            project_type_mc,
            start_time,
            end_time,
            TIMESTAMPDIFF(
                SECOND,
                CONCAT(`date`, ' ', start_time),
                IF(end_time >= start_time,
                    CONCAT(`date`, ' ', end_time),
                    DATE_ADD(CONCAT(`date`, ' ', end_time), INTERVAL 1 DAY)
                )
            ) AS duration_seconds
        FROM timesheet.timesheetlogs
        WHERE {where_clause}
        ORDER BY `date`, name, id;
    """

    print(f"--- DB [{start_date} -> {end_date}] (role={role_norm}, team={team_norm or 'ALL'})")
    print(f"WHERE: {where_clause} | Params: {params}")

    data_payload: Dict[str, Any] = {}

    try:
        with engine.connect() as conn:
            df = pd.read_sql(text(query), conn, params=params)
    except Exception as e:
        print(f"DB error: {e}")
        return {"error": str(e)}

    if df.empty:
        data_payload['details'] = []
        data_payload['filters'] = {key: [] for key in FILTER_KEYS}
        data_payload['overall_totals'] = {key: [] for key in FILTER_KEYS}
        return data_payload

    df['date'] = pd.to_datetime(df['date']).dt.strftime('%Y-%m-%d')
    df['duration_seconds'] = df['duration_seconds'].fillna(0).astype(int)
    df['duration_hhmmss'] = df['duration_seconds'].apply(seconds_to_hhmmss)
    df.rename(columns={'project_type_mc': 'project_type'}, inplace=True)

    cols_order = [
        'id', 'team', 'name', 'date', 'project', 'process', 'sub_process',
        'project_type', 'start_time', 'end_time', 'duration_seconds', 'duration_hhmmss'
    ]
    df_detailed = df[cols_order].copy()

    # 🛠️ ensure JSON-serializable strings
    df_detailed['start_time'] = df_detailed['start_time'].astype(str)
    df_detailed['end_time']   = df_detailed['end_time'].astype(str)

    filter_options = {key: sorted(df[key].dropna().astype(str).unique().tolist()) for key in FILTER_KEYS}

    overall_totals = {}
    for key in FILTER_KEYS:
        grp = (
            df.groupby(key, dropna=False)['duration_seconds']
              .sum()
              .reset_index()
              .rename(columns={'duration_seconds': 'total_seconds'})
        )
        grp[key] = grp[key].fillna('')
        grp['total_hhmmss'] = grp['total_seconds'].apply(seconds_to_hhmmss)
        overall_totals[key] = grp.to_dict('records')

    data_payload['details'] = df_detailed.to_dict('records')
    data_payload['filters'] = filter_options
    data_payload['overall_totals'] = overall_totals
    return data_payload

# ----------------- Routes -----------------
@dashboard_bp.route('/')
@check_dashboard_access
def index():
    default_start, default_end = get_default_dates()
    user_role = (session.get('role', 'user') or '').strip().lower()
    user_team = (session.get('team') or '').strip()

    return render_template(
        'index.html',                      # <- make sure your HTML is saved as dashboard_templates/index.html
        filter_keys=FILTER_KEYS,
        default_start_date=default_start,
        default_end_date=default_end,
        user_role=user_role,               # used by JS to lock/unlock Team select
        user_team=user_team
    )

@dashboard_bp.route('/api/data', methods=['GET'])
@check_dashboard_access
def get_dashboard_data():
    default_start, default_end = get_default_dates()
    start_date = request.args.get('start', default_start)
    end_date   = request.args.get('end',   default_end)

    user_role = (session.get('role', 'user') or '').strip().lower()
    user_team = (session.get('team') or '').strip()

    processed = fetch_and_process_data_from_db(start_date, end_date, user_role, user_team)
    if "error" in processed:
        return jsonify({"error": "Error loading data from the database.", "details": processed["error"]}), 500
    return jsonify(processed)
