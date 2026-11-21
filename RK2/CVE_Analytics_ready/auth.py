
import json
import re
import sqlite3
from pathlib import Path

import bcrypt
import streamlit as st

DB_PATH = Path(__file__).resolve().parent / "users.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)
        conn.execute("""CREATE TABLE IF NOT EXISTS user_settings (
            user_id INTEGER PRIMARY KEY,
            settings_json TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")


def save_user_settings(user_id, settings):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO user_settings(user_id, settings_json) VALUES (?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET settings_json=excluded.settings_json",
            (user_id, json.dumps(settings, ensure_ascii=False)),
        )


def load_user_settings(user_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT settings_json FROM user_settings WHERE user_id=?", (user_id,)
        ).fetchone()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except (ValueError, TypeError):
        return None


def register_user(username, email, password, confirmation):
    username = username.strip()
    email = email.strip().lower()

    if len(username) < 3:
        return False, "Логин должен содержать минимум 3 символа."

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return False, "Введите корректный e-mail."

    if len(password) < 8:
        return False, "Пароль должен содержать минимум 8 символов."

    if password != confirmation:
        return False, "Пароли не совпадают."

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    try:
        with get_connection() as conn:
            conn.execute(
                """INSERT INTO users (username, email, password_hash)
                   VALUES (?, ?, ?)""",
                (username, email, password_hash)
            )
        return True, "Регистрация успешна! Теперь войдите."

    except sqlite3.IntegrityError:
        return False, "Логин или e-mail уже зарегистрирован."


def login_user(username, password):
    with get_connection() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username.strip(),)
        ).fetchone()

    if user is None:
        return None

    if bcrypt.checkpw(
        password.encode("utf-8"),
        user[2].encode("utf-8")
    ):
        return {"id": user[0], "username": user[1]}

    return None


def show_auth():
    st.title("Авторизация и регистрация")

    login_tab, register_tab = st.tabs(["Вход", "Регистрация"])

    with login_tab:
        with st.form("login_form"):
            username = st.text_input("Логин")
            password = st.text_input("Пароль", type="password")
            submitted = st.form_submit_button("Войти")

        if submitted:
            user = login_user(username, password)

            if user:
                st.session_state.user = user
                st.rerun()
            else:
                st.error("Неверный логин или пароль.")

    with register_tab:
        with st.form("registration_form"):
            new_username = st.text_input("Новый логин")
            email = st.text_input("E-mail")
            new_password = st.text_input("Новый пароль", type="password")
            confirmation = st.text_input(
                "Повторите пароль", type="password"
            )
            submitted = st.form_submit_button("Зарегистрироваться")

        if submitted:
            success, message = register_user(
                new_username, email, new_password, confirmation
            )

            if success:
                st.success(message)
            else:
                st.error(message)