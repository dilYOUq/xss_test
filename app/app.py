import os
import sqlite3
from datetime import timedelta
from markupsafe import escape
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()  # Загружает переменные из .env файла

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24).hex()),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    DATABASE=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'users.db'),
    PREFERRED_URL_SCHEME=os.environ.get('PREFERRED_URL_SCHEME', 'http')
)

# Инициализация Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Защитные заголовки
@app.after_request
def apply_security_headers(response):
    headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
    for header, value in headers.items():
        response.headers[header] = value
    return response

# Работа с БД
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    os.makedirs(app.instance_path, exist_ok=True)
    with app.app_context():
        db = get_db()
        try:
            db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    name TEXT NOT NULL,
                    failed_login_attempts INTEGER DEFAULT 0,
                    last_failed_login TIMESTAMP DEFAULT NULL
                )
            ''')
            db.commit()
        except sqlite3.Error as e:
            app.logger.error(f"Database error: {e}")
        finally:
            db.close()

init_db()

# Валидация ввода
def validate_input(data):
    if len(data.get('username', '')) < 4 or len(data.get('username', '')) > 20:
        return False
    if len(data.get('password', '')) < 8:
        return False
    return True

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('welcome'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not validate_input(request.form):
            flash('Некорректные данные!', 'error')
            return redirect(url_for('register'))
        
        username = escape(request.form['username'])
        email = escape(request.form['email'])
        password = request.form['password']
        name = escape(request.form['name'])
        
        hashed_password = generate_password_hash(password)
        
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, email, password, name) VALUES (?, ?, ?, ?)',
                     (username, email, hashed_password, name))
            db.commit()
            flash('Регистрация успешна! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Пользователь с таким логином или email уже существует!', 'error')
        except sqlite3.Error as e:
            app.logger.error(f"Database error: {e}")
            flash('Ошибка базы данных', 'error')
        finally:
            db.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = request.form['password']
        
        db = get_db()
        try:
            user = db.execute(
                'SELECT * FROM users WHERE username = ?', 
                (username,)
            ).fetchone()
            
            if user and check_password_hash(user['password'], password):
                # Сброс счетчика неудачных попыток
                db.execute(
                    'UPDATE users SET failed_login_attempts = 0 WHERE id = ?',
                    (user['id'],)
                )
                db.commit()
                
                session['username'] = user['username']
                session['name'] = user['name']
                
                # Явное сохранение сессии и перенаправление
                resp = make_response(redirect(url_for('welcome')))
                session.modified = True
                return resp
            else:
                if user:
                    db.execute(
                        'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?',
                        (user['id'],)
                    )
                    db.commit()
                flash('Неверный логин или пароль!', 'error')
        except sqlite3.Error as e:
            app.logger.error(f"Database error: {e}")
            flash('Ошибка базы данных', 'error')
        finally:
            db.close()
    
    return render_template('login.html')

@app.route('/welcome')
def welcome():
    if 'username' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect(url_for('login'))
    return render_template('welcome.html', name=escape(session['name']))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)