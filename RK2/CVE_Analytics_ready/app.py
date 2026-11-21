import streamlit as st

from auth import init_db, show_auth, load_user_settings
from data_loader import load_data
from settings import default_settings, show_settings
from analytics import show_analytics


st.set_page_config(
    page_title="CVE Analytics",
    page_icon="🛡️",
    layout="wide"
)

init_db()

if "user" not in st.session_state:
    st.session_state.user = None

if "settings" not in st.session_state:
    st.session_state.settings = default_settings()


if st.session_state.user is None:
    show_auth()

else:
    if st.session_state.get("settings_user_id") != st.session_state.user["id"]:
        stored = load_user_settings(st.session_state.user["id"])
        st.session_state.settings = {**default_settings(), **(stored or {})}
        st.session_state.settings_user_id = st.session_state.user["id"]

    with st.sidebar:
        st.write(
            f"Пользователь: {st.session_state.user['username']}"
        )

        page = st.radio(
            "Навигация",
            ["Аналитика", "Настройки"]
        )

        if st.button("Выйти"):
            st.session_state.user = None
            st.session_state.settings = default_settings()
            st.session_state.pop("settings_user_id", None)
            st.rerun()

    df, errors = load_data()

    for error in errors:
        st.warning(error)

    if df.empty:
        st.error("Не удалось загрузить данные CVE.")
        st.stop()

    if page == "Аналитика":
        show_analytics(df)

    elif page == "Настройки":
        show_settings(df)