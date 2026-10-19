# create_db.py (SEGURO) — crea el esquema que espera app.py e inicializa usuarios.
# Debe ser idempotente: la plataforma lo ejecuta al construir la imagen.
import os
import secrets
import sqlite3
import pyotp
from werkzeug.security import generate_password_hash

DB = os.environ.get("DB_PATH", "database.db")


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    # Esquema de usuarios: incluye mfa_secret (MFA) y bloqueo progresivo.
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,          -- hash fuerte con sal (scrypt/pbkdf2)
            role TEXT NOT NULL DEFAULT 'user',
            mfa_secret TEXT NOT NULL,             -- secreto TOTP por usuario
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until REAL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            task TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    # Sin contrasenas por defecto en el codigo: se inyectan por entorno (Jenkins
    # credentials / secret manager). Si faltan, se genera una aleatoria y se muestra una vez.
    admin_pw = os.environ.get("ADMIN_PW") or secrets.token_urlsafe(16)
    user_pw = os.environ.get("USER_PW") or secrets.token_urlsafe(16)
    # Opcional SOLO para demostracion: fija un secreto MFA conocido para poder
    # generar codigos faciles. Si no se define, cada usuario recibe uno aleatorio.
    fixed_secret = os.environ.get("MFA_SECRET")

    for username, pw, role in [("admin", admin_pw, "admin"), ("user", user_pw, "user")]:
        secret = fixed_secret or pyotp.random_base32()
        c.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, mfa_secret) "
            "VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(pw), role, secret),
        )
        # Muestra el secreto EFECTIVO (si el usuario ya existia, el almacenado)
        row = c.execute("SELECT mfa_secret FROM users WHERE username = ?",
                        (username,)).fetchone()
        eff = row[0] if row else secret
        print(f"[MFA] {username} ({role}) secreto={eff}")
        print(f"      otpauth://totp/SecureWeb:{username}?secret={eff}&issuer=SecureWeb")

    conn.commit()
    conn.close()
    print("Base de datos segura inicializada correctamente.")


if __name__ == "__main__":
    init_db()
