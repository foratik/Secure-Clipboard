import sqlite3
import secrets
import os
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)

DB_NAME = "clipboard.db"
KEY_FILE = "encryption.key"
APP_SECRET_FILE = "app_secret.key"

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 40
RATE_LIMIT_BUCKETS = {}

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

def get_client_ip():
    x_forwarded_for = request.headers.get('X-Forwarded-For', '')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.remote_addr or 'unknown'

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
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')

    columns = [row[1] for row in c.execute("PRAGMA table_info(clips)").fetchall()]
    if 'is_client_encrypted' not in columns:
        c.execute('ALTER TABLE clips ADD COLUMN is_client_encrypted BOOLEAN DEFAULT 0')

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

    if clip['is_one_time']:
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
            password = request.form.get('password')
            duration = request.form.get('duration')
            is_one_time = request.form.get('one_time') == 'on'
            is_client_encrypted = request.form.get('is_client_encrypted') == '1'

            if not content:
                flash('محتوایی وارد نشده است.', 'error')
                return redirect(url_for('index'))

            if is_client_encrypted and not is_valid_client_payload(content):
                flash('فرمت رمزنگاری سمت کاربر معتبر نیست.', 'error')
                return redirect(url_for('index'))

            expire_at = calculate_expire_time(duration)
            expire_at_value = expire_at.isoformat(sep=' ') if expire_at else None
            if is_client_encrypted:
                password_hash = None
                encrypted_content = content
            else:
                password_hash = generate_password_hash(password) if password else None
                encrypted_content = cipher_suite.encrypt(content.encode('utf-8'))
            
            code = str(secrets.randbelow(1000000)).zfill(6)

            try:
                conn = get_db_connection()
                conn.execute('INSERT INTO clips (code, content_encrypted, password_hash, expire_at, is_one_time, is_client_encrypted) VALUES (?, ?, ?, ?, ?, ?)',
                             (code, encrypted_content, password_hash, expire_at_value, is_one_time, is_client_encrypted))
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

@app.route('/consume-client-clip', methods=['POST'])
def consume_client_clip():
    if is_rate_limited('post-consume-client-clip'):
        return {'ok': False, 'error': 'rate_limited'}, 429

    code = request.form.get('code')
    if not code:
        return {'ok': False}, 400

    conn = get_db_connection()
    clip = conn.execute('SELECT code, is_client_encrypted, is_one_time FROM clips WHERE code = ?', (code,)).fetchone()

    if clip and clip['is_client_encrypted'] and clip['is_one_time']:
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

