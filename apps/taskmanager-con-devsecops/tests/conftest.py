import os
import sys
import tempfile
from pathlib import Path

import pyotp
import pytest

MFA_SECRET = pyotp.random_base32()
ADMIN_PW = "Adm1n-test-only-pw"
USER_PW = "Us3r-test-only-pw"

# Debe fijarse antes de importar app (lee DB_PATH al importarse).
_tmp = tempfile.mkdtemp(prefix="taskmanager-tests-")
os.environ["DB_PATH"] = str(Path(_tmp) / "test.db")
os.environ["MFA_SECRET"] = MFA_SECRET
os.environ["ADMIN_PW"] = ADMIN_PW
os.environ["USER_PW"] = USER_PW
os.environ["SECRET_KEY"] = "test-only-secret-key"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as app_module  # noqa: E402
import create_db  # noqa: E402


@pytest.fixture()
def client():
    db_file = Path(os.environ["DB_PATH"])
    db_file.unlink(missing_ok=True)
    create_db.init_db()
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


def otp():
    return pyotp.TOTP(MFA_SECRET).now()


@pytest.fixture()
def login(client):
    def _login(username="user", password=USER_PW, code=None):
        return client.post("/login", data={
            "username": username,
            "password": password,
            "otp": code or otp(),
        })
    return _login


@pytest.fixture()
def csrf(client):
    def _csrf():
        with client.session_transaction() as s:
            return s["_csrf"]
    return _csrf
