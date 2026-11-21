from auth import save_user_settings

import pandas as pd
import streamlit as st


def default_settings():
    return {
        "years": list(range(2014, 2027)),
        "attack_types": [],
        "severities": [],
        "vectors": [],
        "min_cvss": 0.0,
        "sectors": [],
        "countries": [],
        "only_exploits": False,
        "only_exploited": False
    }


def get_options(df, column):
    return sorted(df[column].dropna().astype(str).unique().tolist())


def show_settings(df):
    st.title("Настройки анализа")

    saved = st.session_state.settings

    with st.form("settings_form"):
        years = st.multiselect(
            "Выберите год",
            options=list(range(2014, 2027)),
            default=saved["years"]
        )

        attack_types = st.multiselect(
            "Выберите типы атак",
            options=get_options(df, "attack_type"),
            default=saved["attack_types"]
        )

        severities = st.multiselect(
            "Выберите уровень критичности",
            options=get_options(df, "severity"),
            default=saved["severities"]
        )

        vectors = st.multiselect(
            "Выберите вектор атаки",
            options=get_options(df, "attack_vector"),
            default=saved["vectors"]
        )

        min_cvss = st.slider(
            "Минимальный CVSS",
            min_value=0.0,
            max_value=10.0,
            value=float(saved["min_cvss"]),
            step=0.1
        )

        sectors = st.multiselect(
            "Выберите отрасль цели",
            options=get_options(df, "target_sector"),
            default=saved["sectors"]
        )

        countries = st.multiselect(
            "Выберите страну атакующего",
            options=get_options(df, "attacker_country"),
            default=saved["countries"]
        )

        only_exploits = st.checkbox(
            "Только с доступным эксплойтом",
            value=saved["only_exploits"]
        )

        only_exploited = st.checkbox(
            "Только эксплуатируемые (Exploited / Actively Exploited)",
            value=saved["only_exploited"]
        )

        save = st.form_submit_button("Сохранить настройки")

    if save:
        st.session_state.settings = {
            "years": years,
            "attack_types": attack_types,
            "severities": severities,
            "vectors": vectors,
            "min_cvss": min_cvss,
            "sectors": sectors,
            "countries": countries,
            "only_exploits": only_exploits,
            "only_exploited": only_exploited
        }
        save_user_settings(st.session_state.user["id"], st.session_state.settings)
        st.success("Настройки сохранены и будут доступны после повторного входа.")

    if st.button("Сбросить настройки"):
        st.session_state.settings = default_settings()
        save_user_settings(st.session_state.user["id"], st.session_state.settings)
        st.rerun()


def filter_data(df, settings):
    result = df[df["year"].isin(settings["years"])].copy()

    filters = {
        "attack_type": settings["attack_types"],
        "severity": settings["severities"],
        "attack_vector": settings["vectors"],
        "target_sector": settings["sectors"],
        "attacker_country": settings["countries"]
    }

    for column, selected in filters.items():
        if selected:
            result = result[result[column].isin(selected)]

    result = result[result["cvss_score"] >= settings["min_cvss"]]

    if settings["only_exploits"]:
        result = result[result["exploit_available"] == "Yes"]

    if settings["only_exploited"]:
        result = result[result["status"].isin(["Exploited", "Actively Exploited"])]

    return result
