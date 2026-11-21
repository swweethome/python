import sqlite3

import bcrypt
import pytest

import auth


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test_users.db"

    monkeypatch.setattr(auth, "DB_PATH", db_path)
    auth.init_db()

    return db_path


def test_registration_success(test_db):
    success, message = auth.register_user(
        "testuser",
        "test@example.com",
        "SecurePass123!",
        "SecurePass123!"
    )

    assert success is True

    with sqlite3.connect(test_db) as conn:
        user = conn.execute(
            "SELECT username, email FROM users"
        ).fetchone()

    assert user == ("testuser", "test@example.com")


def test_password_hashing(test_db):
    password = "SecurePass123!"

    auth.register_user(
        "testuser",
        "test@example.com",
        password,
        password
    )

    with sqlite3.connect(test_db) as conn:
        stored_hash = conn.execute(
            "SELECT password_hash FROM users"
        ).fetchone()[0]

    assert stored_hash != password

    assert bcrypt.checkpw(
        password.encode("utf-8"),
        stored_hash.encode("utf-8")
    )


def test_duplicate_registration(test_db):
    auth.register_user(
        "testuser",
        "test@example.com",
        "SecurePass123!",
        "SecurePass123!"
    )

    success, message = auth.register_user(
        "testuser",
        "another@example.com",
        "SecurePass123!",
        "SecurePass123!"
    )

    assert success is False
    assert "зарегистрирован" in message


def test_invalid_email(test_db):
    success, message = auth.register_user(
        "testuser",
        "invalid-email",
        "SecurePass123!",
        "SecurePass123!"
    )

    assert success is False
    assert "e-mail" in message


def test_short_password(test_db):
    success, message = auth.register_user(
        "testuser",
        "test@example.com",
        "123",
        "123"
    )

    assert success is False
    assert "8 символов" in message


def test_password_mismatch(test_db):
    success, message = auth.register_user(
        "testuser",
        "test@example.com",
        "SecurePass123!",
        "DifferentPass123!"
    )

    assert success is False
    assert "не совпадают" in message


def test_login_success(test_db):
    auth.register_user(
        "testuser",
        "test@example.com",
        "SecurePass123!",
        "SecurePass123!"
    )

    user = auth.login_user(
        "testuser",
        "SecurePass123!"
    )

    assert user is not None
    assert user["username"] == "testuser"
    assert "password_hash" not in user


def test_login_wrong_password(test_db):
    auth.register_user(
        "testuser",
        "test@example.com",
        "SecurePass123!",
        "SecurePass123!"
    )

    user = auth.login_user(
        "testuser",
        "WrongPassword123!"
    )

    assert user is None


def test_sql_injection(test_db):
    auth.register_user(
        "testuser",
        "test@example.com",
        "SecurePass123!",
        "SecurePass123!"
    )

    malicious_username = "' OR 1=1 --"

    user = auth.login_user(
        malicious_username,
        "anything"
    )

    assert user is None


def test_user_settings_isolation(test_db):
    auth.register_user(
        "user_one",
        "one@example.com",
        "SecurePass123!",
        "SecurePass123!"
    )

    auth.register_user(
        "user_two",
        "two@example.com",
        "SecurePass123!",
        "SecurePass123!"
    )

    user_one = auth.login_user(
        "user_one", "SecurePass123!"
    )

    user_two = auth.login_user(
        "user_two", "SecurePass123!"
    )

    settings_one = {"years": [2024, 2025]}
    settings_two = {"years": [2026]}

    auth.save_user_settings(
        user_one["id"], settings_one
    )

    auth.save_user_settings(
        user_two["id"], settings_two
    )

    assert auth.load_user_settings(
        user_one["id"]
    ) == settings_one

    assert auth.load_user_settings(
        user_two["id"]
    ) == settings_two
