import sqlite3
import secrets
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'u84ibhwjh8h0bnhb45hybw49rb8g3jivmwec,oera;stugeuribgr9'

DB_NAME = "clipboard.db"
KEY_FILE = "encryption.key"

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

cipher_suite = Fernet(load_or_generate_key())

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
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
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

def handle_clip_view(code, password_input=None, is_submit=False):
    conn = get_db_connection()
    clip = conn.execute('SELECT * FROM clips WHERE code = ?', (code,)).fetchone()
    
    if not clip:
        conn.close()
        return None, False, 'کد وارد شده معتبر نیست.'

    if clip['expire_at'] and datetime.now() > datetime.strptime(clip['expire_at'], '%Y-%m-%d %H:%M:%S.%f'):
        conn.execute('DELETE FROM clips WHERE code = ?', (code,))
        conn.commit()
        conn.close()
        return None, False, 'این کلیپ منقضی شده است.'

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
        action = request.form.get('action')
        
        if action == 'create':
            content = request.form.get('content')
            password = request.form.get('password')
            duration = request.form.get('duration')
            is_one_time = request.form.get('one_time') == 'on'

            if not content:
                flash('محتوایی وارد نشده است.', 'error')
                return redirect(url_for('index'))

            expire_at = calculate_expire_time(duration)
            password_hash = generate_password_hash(password) if password else None
            
            encrypted_content = cipher_suite.encrypt(content.encode('utf-8'))
            
            code = str(secrets.randbelow(1000000)).zfill(6)

            try:
                conn = get_db_connection()
                conn.execute('INSERT INTO clips (code, content_encrypted, password_hash, expire_at, is_one_time) VALUES (?, ?, ?, ?, ?)',
                             (code, encrypted_content, password_hash, expire_at, is_one_time))
                conn.commit()
                conn.close()
                return render_template('index.html', created_code=code)
            except sqlite3.IntegrityError:
                flash('خطا در ایجاد کد، لطفا دوباره تلاش کنید.', 'error')
                return redirect(url_for('index'))

        elif action == 'view':
            active_tab = 'view'
            code = request.form.get('code')
            password_input = request.form.get('password_view')
            
            content, requires_password, error_msg = handle_clip_view(code, password_input, is_submit=True)
            
            if error_msg:
                flash(error_msg, 'error')
                # return render_template('index.html', active_tab=active_tab)
                if requires_password:
                     return render_template('index.html', direct_code=code, requires_password=True)
                return render_template('index.html')
            
            return render_template('index.html', clip_content=content)

    return render_template('index.html', active_tab=active_tab)

@app.route('/<code>', methods=['GET', 'POST'])
def view_clip(code):
    try:
        is_submit = request.method == 'POST'
        password_input = request.form.get('password_view') if is_submit else None
        
        content, requires_password, error_msg = handle_clip_view(code, password_input, is_submit=is_submit)
        
        if error_msg:
            flash(error_msg, 'error')
            return render_template('index.html', direct_code=code, requires_password=requires_password)
        
        if requires_password:
            return render_template('index.html', direct_code=code, requires_password=True)
        
        return render_template('index.html', clip_content=content)
    except Exception as e:
        flash('خطایی در پردازش درخواست رخ داد.', 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    context = ('cert.pem', 'key.pem')
    if os.path.exists(context[0]) and os.path.exists(context[1]):
        app.run(debug=False, host='0.0.0.0', port=5091, ssl_context=context)
    else:
        app.run(debug=False, host='0.0.0.0', port=5090)
