"""Pruebas de seguridad: cada test cubre un hallazgo de la auditoría."""
import sqlite3
import os

import pytest

from conftest import ADMIN_PW, USER_PW


def task_ids(user_id):
    conn = sqlite3.connect(os.environ["DB_PATH"])
    rows = conn.execute("SELECT id FROM tasks WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()
    return [r[0] for r in rows]


def user_id(username):
    conn = sqlite3.connect(os.environ["DB_PATH"])
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row[0]


# ---------- Disponibilidad / monitorización ----------
def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_index_is_public(client):
    assert client.get("/").status_code == 200


def test_security_headers_present(client):
    resp = client.get("/")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert "form-action 'self'" in resp.headers["Content-Security-Policy"]
    assert "Permissions-Policy" in resp.headers
    assert resp.headers["Cache-Control"] == "no-store"


# ---------- Inyección SQL / validación de entrada ----------
@pytest.mark.parametrize("username", ["admin' --", "' OR '1'='1", "a b", "ad"])
def test_login_rejects_malformed_username(client, login, username):
    resp = login(username=username)
    assert resp.status_code == 400


def test_login_sqli_in_password_does_not_authenticate(client, login):
    resp = login(username="admin", password="' OR '1'='1")
    assert resp.status_code == 401


def test_login_requires_six_digit_otp(client, login):
    assert login(code="abc123").status_code == 400


# ---------- Autenticación ----------
def test_login_success_redirects_to_dashboard(client, login):
    resp = login()
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")


def test_login_wrong_password_is_generic_401(client, login):
    resp = login(password="incorrecta")
    assert resp.status_code == 401
    assert "Credenciales invalidas" in resp.get_data(as_text=True)


def test_login_wrong_otp_rejected(client, login):
    assert login(code="000000").status_code == 401


def test_login_unknown_user_same_response_as_wrong_password(client, login):
    resp = login(username="nadie")
    assert resp.status_code == 401


def test_account_locks_after_five_failures(client, login):
    for _ in range(5):
        assert login(password="incorrecta").status_code == 401
    # Aun con credenciales correctas, la cuenta queda bloqueada
    assert login().status_code == 429


def test_session_cookie_flags(client, login):
    resp = login()
    cookie = resp.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


# ---------- Control de acceso ----------
def test_dashboard_requires_login(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_add_task_requires_login(client):
    resp = client.post("/add_task", data={"task": "x"})
    # Sin sesion, CSRF ya lo rechaza antes de llegar a la vista
    assert resp.status_code in (302, 400)


def test_admin_forbidden_for_regular_user(client, login):
    login("user", USER_PW)
    assert client.get("/admin").status_code == 403


def test_admin_allowed_for_admin(client, login):
    login("admin", ADMIN_PW)
    assert client.get("/admin").status_code == 200


def test_admin_forbidden_when_anonymous(client):
    assert client.get("/admin").status_code == 403


# ---------- CSRF ----------
def test_add_task_without_csrf_token_rejected(client, login):
    login()
    resp = client.post("/add_task", data={"task": "tarea"})
    assert resp.status_code == 400


def test_add_task_with_wrong_csrf_token_rejected(client, login):
    login()
    resp = client.post("/add_task", data={"task": "tarea", "_csrf": "falso"})
    assert resp.status_code == 400


def test_delete_via_get_not_allowed(client, login):
    login()
    assert client.get("/delete_task/1").status_code == 405


def test_add_task_with_csrf_token_succeeds(client, login, csrf):
    login()
    client.get("/dashboard")
    resp = client.post("/add_task", data={"task": "comprar pan", "_csrf": csrf()})
    assert resp.status_code == 302
    assert "comprar pan" in client.get("/dashboard").get_data(as_text=True)


def test_add_task_rejects_empty_and_oversized(client, login, csrf):
    login()
    token = csrf()
    assert client.post("/add_task", data={"task": "  ", "_csrf": token}).status_code == 400
    assert client.post("/add_task", data={"task": "x" * 201, "_csrf": token}).status_code == 400


# ---------- XSS ----------
def test_task_output_is_escaped(client, login, csrf):
    login()
    payload = "<script>alert(1)</script>"
    client.post("/add_task", data={"task": payload, "_csrf": csrf()})
    html = client.get("/dashboard").get_data(as_text=True)
    assert payload not in html
    assert "&lt;script&gt;" in html


# ---------- IDOR ----------
def test_user_cannot_delete_another_users_task(client, login, csrf):
    # El admin crea una tarea
    login("admin", ADMIN_PW)
    client.post("/add_task", data={"task": "tarea del admin", "_csrf": csrf()})
    admin_tasks = task_ids(user_id("admin"))
    assert len(admin_tasks) == 1

    # Un usuario normal intenta borrarla
    with client.session_transaction() as s:
        s.clear()
    login("user", USER_PW)
    resp = client.post(f"/delete_task/{admin_tasks[0]}", data={"_csrf": csrf()})
    assert resp.status_code == 302
    assert task_ids(user_id("admin")) == admin_tasks


def test_user_can_delete_own_task(client, login, csrf):
    login()
    client.post("/add_task", data={"task": "propia", "_csrf": csrf()})
    own = task_ids(user_id("user"))
    client.post(f"/delete_task/{own[0]}", data={"_csrf": csrf()})
    assert task_ids(user_id("user")) == []


def test_delete_requires_login(client):
    resp = client.post("/delete_task/1")
    assert resp.status_code in (302, 400)
