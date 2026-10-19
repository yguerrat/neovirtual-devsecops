# app.py (SEGURO) — expone la app Flask como 'app' (gunicorn app:app).
# Remedia: Inyeccion SQL, XSS, CSRF, Autenticacion debil y Control de acceso.
import json
import logging
import os
import re
import time
import secrets
import sqlite3
import pyotp
from flask import (Flask, request, render_template_string, session,
                   redirect, url_for, abort)
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.config.update(
    # Clave persistente desde el entorno; fallback efimero solo para no romper el lab.
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # En el laboratorio se accede por HTTP -> false. En produccion: COOKIE_SECURE=true + HTTPS.
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=1800,
)

DB = os.environ.get("DB_PATH", "database.db")
MAX_ATTEMPTS = 5
LOCK_SECONDS = 300
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
OTP_RE = re.compile(r"^\d{6}$")
CSRF_EXEMPT = {"login"}  # el login se protege con lista blanca + MFA, no con token


# ---------- Monitorizacion: eventos de seguridad en JSON por stdout ----------
logging.basicConfig(level=logging.INFO, format="%(message)s")
security_log = logging.getLogger("security")


def audit(event, **fields):
    """Una linea JSON por evento; fácil de enviar a Loki/ELK/SIEM y de alertar."""
    security_log.info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        "ip": request.remote_addr,
        **fields,
    }))


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ---------- CSRF (sin dependencias externas) ----------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


@app.before_request
def csrf_protect():
    if request.method == "POST" and request.endpoint not in CSRF_EXEMPT:
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            audit("csrf_rejected", endpoint=request.endpoint)
            abort(400, "CSRF token invalido")


@app.after_request
def security_headers(resp):
    # Defensa en profundidad para XSS y clickjacking
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"  # evita cachear paginas con datos de sesion
    return resp


@app.route("/")
def index():
    return "Welcome to the Task Manager Application!"


@app.route("/health")
def health():
    return {"status": "ok"}


LOGIN_HTML = """
<h2>SecureWeb - Ingreso</h2>
<form method="post">
  Usuario: <input name="username" pattern="[A-Za-z0-9_]{3,32}" required><br>
  Contrasena: <input type="password" name="password" required><br>
  Codigo MFA (6 digitos): <input name="otp" pattern="[0-9]{6}" maxlength="6" required><br>
  <input type="submit" value="Ingresar">
</form>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        otp = request.form.get("otp", "").strip()

        # Validacion por lista blanca: bloquea payloads SQLi y EXIGE el 2do factor
        if not USERNAME_RE.match(username) or not OTP_RE.match(otp):
            audit("login_invalid_input")
            return "Datos invalidos", 400

        conn = db()
        # Consulta SIEMPRE parametrizada (no concatena entrada del usuario)
        user = conn.execute("SELECT * FROM users WHERE username = ?",
                            (username,)).fetchone()
        now = time.time()

        if user and user["locked_until"] and now < user["locked_until"]:
            conn.close()
            audit("login_blocked_locked_account", username=username)
            return "Cuenta bloqueada temporalmente", 429

        ok = bool(
            user
            and check_password_hash(user["password_hash"], password)
            and pyotp.TOTP(user["mfa_secret"]).verify(otp, valid_window=1)
        )

        if ok:
            conn.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?",
                         (user["id"],))
            conn.commit()
            conn.close()
            session.clear()                 # evita fijacion de sesion
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            csrf_token()
            audit("login_success", username=username)
            return redirect(url_for("dashboard"))

        if user:                            # bloqueo progresivo
            n = user["failed_attempts"] + 1
            lock = now + LOCK_SECONDS if n >= MAX_ATTEMPTS else None
            conn.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                         (n, lock, user["id"]))
            conn.commit()
            if lock:
                audit("account_locked", username=username, attempts=n)
        conn.close()
        audit("login_failure", username=username)
        return "Credenciales invalidas", 401   # mensaje generico

    return render_template_string(LOGIN_HTML)


DASH_HTML = """
<h1>Bienvenido, usuario {{ user_id }}</h1>
<form action="/add_task" method="post">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <input name="task" maxlength="200" placeholder="Nueva tarea" required>
  <input type="submit" value="Agregar">
</form>
<h2>Tus tareas</h2>
<ul>
{% for t in tasks %}
  <li>{{ t['task'] }}
    <form action="/delete_task/{{ t['id'] }}" method="post" style="display:inline">
      <input type="hidden" name="_csrf" value="{{ csrf }}">
      <button type="submit">Eliminar</button>
    </form>
  </li>
{% endfor %}
</ul>
"""


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = db()
    tasks = conn.execute("SELECT * FROM tasks WHERE user_id = ?",
                        (session["user_id"],)).fetchall()
    conn.close()
    # Jinja2 autoescapa por defecto (XSS mitigado). Nunca usar |safe sobre datos de usuario.
    return render_template_string(DASH_HTML, user_id=session["user_id"],
                                 tasks=tasks, csrf=csrf_token())


@app.route("/add_task", methods=["POST"])
def add_task():
    if "user_id" not in session:
        return redirect(url_for("login"))
    task = request.form.get("task", "").strip()
    if not (1 <= len(task) <= 200):          # validacion de longitud
        return "Tarea invalida", 400
    conn = db()
    conn.execute("INSERT INTO tasks (user_id, task) VALUES (?, ?)",
                 (session["user_id"], task))
    conn.commit()
    conn.close()
    return redirect(url_for("dashboard"))


@app.route("/delete_task/<int:task_id>", methods=["POST"])  # SOLO POST: bloquea CSRF por GET
def delete_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = db()
    # Verifica propiedad del recurso: impide IDOR (borrar tareas ajenas)
    conn.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?",
                 (task_id, session["user_id"]))
    conn.commit()
    conn.close()
    return redirect(url_for("dashboard"))


@app.route("/admin")
def admin():
    if session.get("role") != "admin":      # RBAC con sesion firmada
        audit("admin_access_denied", user_id=session.get("user_id"))
        abort(403)
    return "Welcome to the admin panel!"


if __name__ == "__main__":
    # En produccion: gunicorn + HTTPS. Nunca debug=True.
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000, debug=False)
