import pandas as pd
import plotly.express as px
import streamlit as st

from settings import filter_data


def show_analytics(df):
    st.title("Анализ CVE-уязвимостей")

    settings = st.session_state.settings
    filtered_df = filter_data(df, settings)

    with st.expander("Текущие фильтры"):
        st.json(settings)

    if filtered_df.empty:
        st.warning("По выбранным фильтрам записей не найдено.")
        return

    total = len(filtered_df)
    average_cvss = filtered_df["cvss_score"].mean()

    critical_count = (
        filtered_df["severity"] == "Critical"
    ).sum()

    affected_hosts = filtered_df["affected_hosts"].sum()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Всего записей", f"{total:,}")
    col2.metric("Средний CVSS", f"{average_cvss:.2f}")
    col3.metric("Critical", int(critical_count))
    col4.metric("Затронуто узлов", f"{affected_hosts:,.0f}")

    st.divider()

    st.subheader("Динамика уязвимостей по годам")

    yearly = (
        filtered_df.groupby("year")
        .size()
        .reset_index(name="count")
        .sort_values("year")
    )

    fig1 = px.line(
        yearly,
        x="year",
        y="count",
        markers=True,
        labels={
            "year": "Год",
            "count": "Количество записей"
        }
    )

    st.plotly_chart(fig1, width="stretch")

    st.subheader("Распределение по типам атак")

    attack_counts = (
        filtered_df["attack_type"]
        .value_counts()
        .reset_index()
    )

    attack_counts.columns = ["attack_type", "count"]

    fig2 = px.bar(
        attack_counts,
        x="attack_type",
        y="count",
        labels={
            "attack_type": "Тип атаки",
            "count": "Количество"
        }
    )

    st.plotly_chart(fig2, width="stretch")

    st.subheader("Топ-10 вендоров")

    vendor_counts = (
        filtered_df["vendor"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    vendor_counts.columns = ["vendor", "count"]

    fig3 = px.bar(
        vendor_counts,
        x="count",
        y="vendor",
        orientation="h",
        labels={
            "count": "Количество",
            "vendor": "Вендор"
        }
    )

    fig3.update_layout(yaxis={"categoryorder": "total ascending"})

    st.plotly_chart(fig3, width="stretch")

    st.subheader("География источников атак")

    country_counts = (
        filtered_df["attacker_country"]
        .dropna()
        .value_counts()
        .reset_index()
    )

    country_counts.columns = ["country", "count"]

    if not country_counts.empty:
        fig4 = px.choropleth(
            country_counts,
            locations="country",
            locationmode="country names",
            color="count",
            hover_name="country",
            color_continuous_scale=["#FCE7F3", "#F9A8D4", "#EC4899", "#9D174D"],
            labels={
                "count": "Количество записей",
                "country": "Страна"
            },
            title="Распределение CVE-записей по странам"
        )

        fig4.update_layout(
            geo=dict(
                showframe=False,
                showcoastlines=True,
                projection_type="natural earth"
            ),
            margin=dict(l=0, r=0, t=50, b=0)
        )

        st.plotly_chart(fig4, width="stretch")
    else:
        st.info("Нет данных о странах для построения карты.")


    st.subheader("Таблица CVE")

    search = st.text_input(
        "Поиск по CVE, вендору или продукту"
    )

    table_df = filtered_df.copy()

    if search:
        mask = (
            table_df["cve_id"].astype(str).str.contains(
                search, case=False, na=False, regex=False
            )
            |
            table_df["vendor"].astype(str).str.contains(
                search, case=False, na=False, regex=False
            )
            |
            table_df["product"].astype(str).str.contains(
                search, case=False, na=False, regex=False
            )
        )

        table_df = table_df[mask]

    st.caption(f"Найдено записей: {len(table_df)}")

    st.dataframe(
        table_df,
        width="stretch",
        hide_index=True
    )

    csv_data = table_df.to_csv(index=False).encode("utf-8-sig")

    st.download_button(
        label="Скачать CSV",
        data=csv_data,
        file_name="filtered_cve.csv",
        mime="text/csv",
        disabled=table_df.empty
    )