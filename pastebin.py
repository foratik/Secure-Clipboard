import sqlite3
import secrets
import os
import json
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)

# Load a local .env file placed next to this script (if present).
# This will NOT fetch remote content; it only reads a local file named ".env" next to pastebin.py.
def load_local_env(env_filename='.env'):
    env_path = os.path.join(os.path.dirname(__file__), env_filename)
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                key, val = line.split('=', 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                # Do not overwrite existing environment variables
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass

load_local_env()

DB_NAME = "clipboard.db"
KEY_FILE = "encryption.key"
APP_SECRET_FILE = "app_secret.key"

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 40
RATE_LIMIT_BUCKETS = {}
ADMIN_ALLOWED_IPS = {
    ip.strip()
    for ip in os.environ.get('ADMIN_ALLOWED_IPS', '127.0.0.1,::1').split(',')
    if ip.strip()
}

# Admin configuration - load from local .env if present.
# SECRET PATH (required to make admin non-guessable). Set e.g. ADMIN_SECRET_PATH=qs8eYzT2
ADMIN_SECRET_PATH = os.environ.get('ADMIN_SECRET_PATH', '').strip()
# Admin username and password (store these in the local .env next to the project)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', '').strip()
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '').strip()

# If you prefer token-based access, you can still use ADMIN_ACCESS_TOKEN in .env
ADMIN_ACCESS_TOKEN = os.environ.get('ADMIN_ACCESS_TOKEN', '').strip()

def to_farsi_filter(text):
    if not text:
        return text
    mapping = {
        '0': '۰', '1': '۱', '2': '۲', '3': '۳', '4': '۴',
        '5': '۵', '6': '۶', '7': '۷', '8': '۸', '9': '۹'
    }
    return str(text).translate(str.maketrans(mapping))

app.jinja_env.filters['to_farsi'] = to_farsi_filter

def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

def load_or_generate_app_secret():
    env_secret = os.environ.get('APP_SECRET_KEY')
    if env_secret:
        return env_secret

    if os.path.exists(APP_SECRET_FILE):
        with open(APP_SECRET_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()

    new_secret = secrets.token_urlsafe(64)
    with open(APP_SECRET_FILE, "w", encoding="utf-8") as f:
        f.write(new_secret)
    return new_secret

app.secret_key = load_or_generate_app_secret()

cipher_suite = Fernet(load_or_generate_key())

def get_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token

app.jinja_env.globals['csrf_token'] = get_csrf_token

@app.context_processor
def inject_admin_visibility():
    return {
        'admin_dashboard_visible': is_admin_ip_allowed(),
    }

def get_client_ip():
    x_forwarded_for = request.headers.get('X-Forwarded-For', '')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.remote_addr or 'unknown'

def get_request_ip(trust_forwarded=True):
    if trust_forwarded:
        return get_client_ip()
    return request.remote_addr or 'unknown'

def is_admin_ip_allowed():
    current_ip = get_request_ip(trust_forwarded=False)
    return current_ip in ADMIN_ALLOWED_IPS

def require_admin_access(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not is_admin_ip_allowed():
            return 'Forbidden', 403

        if not session.get('admin_authenticated'):
            return redirect(url_for('admin_login'))

        return view_func(*args, **kwargs)

    return wrapped

def is_rate_limited(scope):
    now = datetime.now().timestamp()
    bucket_key = f"{scope}:{get_client_ip()}"
    bucket = RATE_LIMIT_BUCKETS.get(bucket_key, [])
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    bucket = [t for t in bucket if t >= window_start]

    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        RATE_LIMIT_BUCKETS[bucket_key] = bucket
        return True

    bucket.append(now)
    RATE_LIMIT_BUCKETS[bucket_key] = bucket

    if len(RATE_LIMIT_BUCKETS) > 5000:
        for key in list(RATE_LIMIT_BUCKETS.keys()):
            RATE_LIMIT_BUCKETS[key] = [t for t in RATE_LIMIT_BUCKETS[key] if t >= window_start]
            if not RATE_LIMIT_BUCKETS[key]:
                del RATE_LIMIT_BUCKETS[key]

    return False

@app.before_request
def validate_csrf_for_post_requests():
    if request.method != 'POST':
        return

    sent_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    session_token = session.get('_csrf_token')

    if not sent_token or not session_token or sent_token != session_token:
        flash('درخواست نامعتبر است. لطفاً دوباره تلاش کنید.', 'error')
        return redirect(url_for('index'))

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS clips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT UNIQUE NOT NULL,
                    content_encrypted TEXT NOT NULL,
                    password_hash TEXT,
                    expire_at DATETIME,
                    is_one_time BOOLEAN DEFAULT 0,
                    is_client_encrypted BOOLEAN DEFAULT 0,
                    was_viewed BOOLEAN DEFAULT 0,
                    creator_ip TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')

    # Separate table to log one-time clip creations for statistics (without storing content)
    c.execute('''CREATE TABLE IF NOT EXISTS one_time_clips_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    is_client_encrypted BOOLEAN DEFAULT 0,
                    creator_ip TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    viewed_at DATETIME
                )''')

    columns = [row[1] for row in c.execute("PRAGMA table_info(clips)").fetchall()]
    if 'is_client_encrypted' not in columns:
        c.execute('ALTER TABLE clips ADD COLUMN is_client_encrypted BOOLEAN DEFAULT 0')
    if 'creator_ip' not in columns:
        c.execute('ALTER TABLE clips ADD COLUMN creator_ip TEXT')
    if 'was_viewed' not in columns:
        c.execute('ALTER TABLE clips ADD COLUMN was_viewed BOOLEAN DEFAULT 0')

    c.execute('CREATE INDEX IF NOT EXISTS idx_clips_created_at ON clips(created_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_clips_creator_ip ON clips(creator_ip)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_one_time_log_created_at ON one_time_clips_log(created_at)')

    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_NAME, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

def calculate_expire_time(duration_str):
    now = datetime.now()
    if duration_str == '5m':
        return now + timedelta(minutes=5)
    elif duration_str == '10m':
        return now + timedelta(minutes=10)
    elif duration_str == '30m':
        return now + timedelta(minutes=30)
    elif duration_str == '1h':
        return now + timedelta(hours=1)
    elif duration_str == '12h':
        return now + timedelta(hours=12)
    elif duration_str == '1d':
        return now + timedelta(days=1)
    elif duration_str == '1w':
        return now + timedelta(weeks=1)
    elif duration_str == '1M':
        return now + timedelta(days=30)
    return None

def is_valid_client_payload(payload_text):
    try:
        payload = json.loads(payload_text)
    except (TypeError, json.JSONDecodeError):
        return False

    required_keys = {'v', 'alg', 'kdf', 'iter', 'salt', 'iv', 'ct'}
    if not isinstance(payload, dict) or not required_keys.issubset(payload.keys()):
        return False

    if payload.get('alg') != 'AES-GCM' or payload.get('kdf') != 'PBKDF2':
        return False

    return True

def parse_db_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None

def parse_date_filter(value, end_of_day=False):
    if not value:
        return None
    try:
        base_date = datetime.strptime(value, '%Y-%m-%d')
        if end_of_day:
            return base_date + timedelta(days=1)
        return base_date
    except ValueError:
        return None

def get_stats_range():
    end_date = parse_date_filter(request.args.get('end_date'), end_of_day=True)
    start_date = parse_date_filter(request.args.get('start_date'))

    if not end_date:
        end_date = datetime.now() + timedelta(days=1)
    if not start_date:
        start_date = end_date - timedelta(days=7)

    if start_date > end_date:
        start_date, end_date = end_date - timedelta(days=7), end_date

    return start_date, end_date

def fetch_admin_stats(start_dt, end_dt):
    conn = get_db_connection()
    start_value = start_dt.isoformat(sep=' ')
    end_value = end_dt.isoformat(sep=' ')

    summary = conn.execute(
        '''SELECT
               COUNT(*) AS total_clips,
               SUM(CASE WHEN is_one_time = 1 THEN 1 ELSE 0 END) AS one_time_clips,
               SUM(CASE WHEN is_client_encrypted = 1 THEN 1 ELSE 0 END) AS client_encrypted_clips,
               COUNT(DISTINCT creator_ip) AS unique_creator_ips
           FROM clips
           WHERE created_at >= ? AND created_at < ?''',
        (start_value, end_value)
    ).fetchone()

    # Count one-time clips that were already viewed and deleted from logs
    one_time_viewed = conn.execute(
        '''SELECT COUNT(*) AS viewed_one_time FROM one_time_clips_log
           WHERE created_at >= ? AND created_at < ?''',
        (start_value, end_value)
    ).fetchone()

    daily_rows = conn.execute(
        '''SELECT date(created_at) AS bucket, COUNT(*) AS total
           FROM clips
           WHERE created_at >= ? AND created_at < ?
           GROUP BY bucket
           ORDER BY bucket''',
        (start_value, end_value)
    ).fetchall()

    # Add one-time clips from log to daily stats
    daily_log_rows = conn.execute(
        '''SELECT date(created_at) AS bucket, COUNT(*) AS total
           FROM one_time_clips_log
           WHERE created_at >= ? AND created_at < ?
           GROUP BY bucket
           ORDER BY bucket''',
        (start_value, end_value)
    ).fetchall()

    hourly_rows = conn.execute(
        '''SELECT strftime('%H', created_at) AS bucket, COUNT(*) AS total
           FROM clips
           WHERE created_at >= ? AND created_at < ?
           GROUP BY bucket
           ORDER BY bucket''',
        (start_value, end_value)
    ).fetchall()

    ip_rows = conn.execute(
        '''SELECT COALESCE(creator_ip, 'unknown') AS ip_address, COUNT(*) AS total
           FROM clips
           WHERE created_at >= ? AND created_at < ?
           GROUP BY ip_address
           ORDER BY total DESC, ip_address ASC
           LIMIT 15''',
        (start_value, end_value)
    ).fetchall()

    # Also get IP stats from one-time log
    ip_log_rows = conn.execute(
        '''SELECT COALESCE(creator_ip, 'unknown') AS ip_address, COUNT(*) AS total
           FROM one_time_clips_log
           WHERE created_at >= ? AND created_at < ?
           GROUP BY ip_address''',
        (start_value, end_value)
    ).fetchall()

    # Merge IP stats from both tables
    ip_totals = {}
    for row in ip_rows:
        ip_totals[row['ip_address']] = row['total']
    for row in ip_log_rows:
        ip_totals[row['ip_address']] = ip_totals.get(row['ip_address'], 0) + row['total']
    
    # Sort by total DESC
    top_ips_sorted = sorted(ip_totals.items(), key=lambda x: x[1], reverse=True)[:15]

    total_count = summary['total_clips'] or 0
    total_one_time_viewed = one_time_viewed['viewed_one_time'] or 0
    total_one_time = (summary['one_time_clips'] or 0) + total_one_time_viewed
    # Total clips includes both active and deleted one-time clips
    total_count_all = total_count + total_one_time_viewed
    
    # Count server-encrypted clips (non-client-encrypted clips)
    server_encrypted = conn.execute(
        '''SELECT COUNT(*) AS count FROM clips
           WHERE created_at >= ? AND created_at < ? AND is_client_encrypted = 0''',
        (start_value, end_value)
    ).fetchone()['count'] or 0

    conn.close()

    daily_labels = [row['bucket'] for row in daily_rows]
    daily_values = [row['total'] for row in daily_rows]
    
    # Merge daily log data into daily values
    daily_log_map = {row['bucket']: row['total'] for row in daily_log_rows}
    for i, label in enumerate(daily_labels):
        if label in daily_log_map:
            daily_values[i] += daily_log_map[label]
    
    # Add any date-only entries from log that aren't in clips
    for row in daily_log_rows:
        if row['bucket'] not in daily_labels:
            daily_labels.append(row['bucket'])
            daily_values.append(row['total'])
    
    # Sort by date
    if daily_labels:
        sorted_pairs = sorted(zip(daily_labels, daily_values))
        daily_labels, daily_values = zip(*sorted_pairs)
        daily_labels, daily_values = list(daily_labels), list(daily_values)
    
    hourly_map = {row['bucket']: row['total'] for row in hourly_rows}
    hourly_labels = [f'{i:02d}' for i in range(24)]
    hourly_values = [hourly_map.get(f'{i:02d}', 0) for i in range(24)]

    return {
        'summary': {
            'total_clips': total_count_all,
            'one_time_clips': total_one_time,
            'client_encrypted_clips': summary['client_encrypted_clips'] or 0,
            'server_encrypted_clips': server_encrypted,
            'unique_creator_ips': summary['unique_creator_ips'] or 0,
        },
        'daily': {
            'labels': daily_labels,
            'values': daily_values,
        },
        'hourly': {
            'labels': hourly_labels,
            'values': hourly_values,
        },
        'top_ips': [
            {
                'ip_address': ip_addr,
                'total': total,
                'share': round((total / total_count_all) * 100, 2) if total_count_all else 0,
            }
            for ip_addr, total in top_ips_sorted
        ],
    }

def handle_clip_view(code, password_input=None, is_submit=False):
    conn = get_db_connection()
    clip = conn.execute('SELECT * FROM clips WHERE code = ?', (code,)).fetchone()
    
    if not clip:
        conn.close()
        return None, False, 'کد وارد شده معتبر نیست.'

    expire_at_dt = parse_db_datetime(clip['expire_at'])
    if expire_at_dt and datetime.now() > expire_at_dt:
        conn.execute('DELETE FROM clips WHERE code = ?', (code,))
        conn.commit()
        conn.close()
        return None, False, 'این کلیپ منقضی شده است.'

    if clip['is_client_encrypted']:
        payload = clip['content_encrypted']

        # If one-time, log it and delete
        if clip['is_one_time']:
            conn.execute('INSERT INTO one_time_clips_log (is_client_encrypted, creator_ip, created_at, viewed_at) VALUES (?, ?, ?, ?)',
                        (clip['is_client_encrypted'], clip['creator_ip'], clip['created_at'], datetime.now().isoformat(sep=' ')))
            conn.execute('DELETE FROM clips WHERE code = ?', (code,))
            conn.commit()

        conn.close()
        return {
            'payload': payload,
            'code': code,
            'initial_password': '',
            'is_one_time': bool(clip['is_one_time'])
        }, False, None

    if clip['password_hash']:
        if is_submit:
            if not password_input or not check_password_hash(clip['password_hash'], password_input):
                conn.close()
                return None, True, 'رمز عبور اشتباه است.'
        else:
            conn.close()
            return None, True, None

    decrypted_content = cipher_suite.decrypt(clip['content_encrypted']).decode('utf-8')

    # If one-time, log it and delete
    if clip['is_one_time']:
        conn.execute('INSERT INTO one_time_clips_log (is_client_encrypted, creator_ip, created_at, viewed_at) VALUES (?, ?, ?, ?)',
                    (clip['is_client_encrypted'], clip['creator_ip'], clip['created_at'], datetime.now().isoformat(sep=' ')))
        conn.execute('DELETE FROM clips WHERE code = ?', (code,))
        conn.commit()
    
    conn.close()
    return decrypted_content, False, None

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/', methods=['GET', 'POST'])
def index():
    active_tab = 'create'
    if request.method == 'POST':
        if is_rate_limited('post-index'):
            flash('تعداد درخواست‌ها زیاد است. لطفاً کمی بعد تلاش کنید.', 'error')
            return redirect(url_for('index'))

        action = request.form.get('action')
        
        if action == 'create':
            content = request.form.get('content')
            duration = request.form.get('duration')
            is_one_time = request.form.get('one_time') == 'on'
            is_client_encrypted = request.form.get('is_client_encrypted') == '1'
            creator_ip = get_request_ip()

            if not content:
                flash('محتوایی وارد نشده است.', 'error')
                return redirect(url_for('index'))

            if is_client_encrypted and not is_valid_client_payload(content):
                flash('فرمت رمزنگاری سمت کاربر معتبر نیست.', 'error')
                return redirect(url_for('index'))

            expire_at = calculate_expire_time(duration)
            expire_at_value = expire_at.isoformat(sep=' ') if expire_at else None
            # For privacy, we never accept plaintext passwords on the server.
            # If the client chose client-side encryption, it sets is_client_encrypted=1
            # and sends the encrypted payload as `content`. Otherwise the server
            # performs server-side encryption of the plaintext content but does
            # not record any password hash from the user.
            password_hash = None
            if is_client_encrypted:
                encrypted_content = content
            else:
                encrypted_content = cipher_suite.encrypt(content.encode('utf-8'))
            
            code = str(secrets.randbelow(1000000)).zfill(6)

            try:
                conn = get_db_connection()
                conn.execute('INSERT INTO clips (code, content_encrypted, password_hash, expire_at, is_one_time, is_client_encrypted, creator_ip) VALUES (?, ?, ?, ?, ?, ?, ?)',
                             (code, encrypted_content, password_hash, expire_at_value, is_one_time, is_client_encrypted, creator_ip))
                conn.commit()
                conn.close()
                return render_template('index.html', created_code=code)
            except sqlite3.IntegrityError:
                flash('خطا در ایجاد کد، لطفا دوباره تلاش کنید.', 'error')
                return redirect(url_for('index'))

        elif action == 'view':
            active_tab = 'view'
            code = request.form.get('code')
            if not code:
                flash('کد وارد نشده است.', 'error')
                return render_template('index.html', active_tab=active_tab)

            return redirect(url_for('view_clip', code=code))

    return render_template('index.html', active_tab=active_tab)

def admin_login():
    if not is_admin_ip_allowed():
        return 'Forbidden', 403

    # If neither username/password nor token is configured, block access to avoid accidental exposure
    if not (ADMIN_USERNAME and ADMIN_PASSWORD) and not ADMIN_ACCESS_TOKEN:
        return 'Forbidden', 403

    if request.method == 'POST':
        # prefer username/password if provided
        if ADMIN_USERNAME and ADMIN_PASSWORD:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            if secrets.compare_digest(username, ADMIN_USERNAME) and secrets.compare_digest(password, ADMIN_PASSWORD):
                session['admin_authenticated'] = True
                return redirect(url_for('admin_dashboard'))
            flash('نام کاربری یا رمز عبور اشتباه است.', 'error')
        else:
            token = request.form.get('token', '').strip()
            if ADMIN_ACCESS_TOKEN and secrets.compare_digest(token, ADMIN_ACCESS_TOKEN):
                session['admin_authenticated'] = True
                return redirect(url_for('admin_dashboard'))
            flash('توکن مدیریتی نادرست است.', 'error')

    return render_template('admin_login.html')

@require_admin_access
def admin_logout():
    session.pop('admin_authenticated', None)
    return redirect(url_for('admin_login'))

@require_admin_access
def admin_dashboard():
    start_dt, end_dt = get_stats_range()
    dashboard_data = fetch_admin_stats(start_dt, end_dt)
    return render_template(
        'admin_dashboard.html',
        dashboard_data=dashboard_data,
        start_date=start_dt.date().isoformat(),
        end_date=(end_dt - timedelta(days=1)).date().isoformat(),
        admin_token_enabled=bool(ADMIN_ACCESS_TOKEN),
    )

@require_admin_access
def admin_api_stats():
    start_dt, end_dt = get_stats_range()
    return jsonify(fetch_admin_stats(start_dt, end_dt))

@app.route('/<code>', methods=['GET', 'POST'])
def view_clip(code):
    try:
        if request.method == 'POST' and is_rate_limited('post-view-clip'):
            flash('تعداد درخواست‌ها زیاد است. لطفاً کمی بعد تلاش کنید.', 'error')
            return redirect(url_for('index'))

        is_submit = request.method == 'POST'
        password_input = request.form.get('password_view') if is_submit else None
        
        content, requires_password, error_msg = handle_clip_view(code, password_input, is_submit=is_submit)
        
        if error_msg:
            flash(error_msg, 'error')
            if requires_password:
                return render_template('index.html', direct_code=code, requires_password=True)
            return render_template('index.html')
        
        if requires_password:
            return render_template('index.html', direct_code=code, requires_password=True)

        if isinstance(content, dict) and content.get('payload'):
            return render_template('index.html',
                                   client_encrypted_payload=content['payload'],
                                   direct_code=content['code'],
                                   client_clip_is_one_time=content.get('is_one_time', False),
                                   initial_password=content.get('initial_password', ''))
        
        return render_template('index.html', clip_content=content)
    except Exception as e:
        flash('خطایی در پردازش درخواست رخ داد.', 'error')
        return redirect(url_for('index'))

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    admin_prefix = f"/{ADMIN_SECRET_PATH}" if ADMIN_SECRET_PATH else '/admin'
    if request.path.startswith(admin_prefix):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        # Content Security Policy for admin pages (allow inline scripts since page is protected by auth + IP)
        csp = (
            "default-src 'none'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self'; "
            "font-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers['Content-Security-Policy'] = csp
    return response


# Serve a local copy of Chart.js if provided next to the project (chart.umd.min.js),
# otherwise fall back to a copy inside the static folder named 'chart.umd.min.js'.
@app.route('/static/chart.umd.min.js')
def local_chart_js():
    local_file = os.path.join(os.path.dirname(__file__), 'chart.umd.min.js')
    if os.path.exists(local_file):
        return send_from_directory(os.path.dirname(__file__), 'chart.umd.min.js', mimetype='application/javascript')
    # fallback to static folder
    return send_from_directory(os.path.join(app.root_path, 'static'), 'chart.umd.min.js', mimetype='application/javascript')


# Register admin routes under the secret path (or '/admin' fallback)
admin_base = f"/{ADMIN_SECRET_PATH}" if ADMIN_SECRET_PATH else '/admin'
app.add_url_rule(f"{admin_base}/login", endpoint='admin_login', view_func=admin_login, methods=['GET', 'POST'])
app.add_url_rule(f"{admin_base}/logout", endpoint='admin_logout', view_func=admin_logout)
app.add_url_rule(f"{admin_base}", endpoint='admin_dashboard', view_func=admin_dashboard)
app.add_url_rule(f"{admin_base}/api/stats", endpoint='admin_api_stats', view_func=admin_api_stats)

@app.route('/consume-client-clip', methods=['POST'])
def consume_client_clip():
    if is_rate_limited('post-consume-client-clip'):
        return {'ok': False, 'error': 'rate_limited'}, 429

    code = request.form.get('code')
    if not code:
        return {'ok': False}, 400

    conn = get_db_connection()
    clip = conn.execute('SELECT code, is_client_encrypted, is_one_time, creator_ip, created_at FROM clips WHERE code = ?', (code,)).fetchone()

    if clip and clip['is_one_time']:
        # Log the one-time clip and delete from main table
        conn.execute('INSERT INTO one_time_clips_log (is_client_encrypted, creator_ip, created_at, viewed_at) VALUES (?, ?, ?, ?)',
                    (clip['is_client_encrypted'], clip['creator_ip'], clip['created_at'], datetime.now().isoformat(sep=' ')))
        conn.execute('DELETE FROM clips WHERE code = ?', (code,))
        conn.commit()

    conn.close()
    return {'ok': True}

if __name__ == '__main__':
    init_db()
    context = ('cert.pem', 'key.pem')
    if os.path.exists(context[0]) and os.path.exists(context[1]):
        app.run(debug=False, host='0.0.0.0', port=5091, ssl_context=context)
    else:
        app.run(debug=False, host='0.0.0.0', port=5090)

