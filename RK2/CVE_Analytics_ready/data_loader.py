from pathlib import Path

import pandas as pd
import streamlit as st

DATA_DIR = Path(__file__).resolve().parent / "data"

REQUIRED_COLUMNS = [
    "cve_id", "date", "attack_type", "vendor", "product",
    "cvss_score", "severity", "attack_vector",
    "attacker_country", "target_sector", "affected_hosts",
    "status", "exploit_available"
]


@st.cache_data
def load_data():
    dataframes = []
    errors = []

    for year in range(2014, 2027):
        filename = DATA_DIR / f"cyberattacks_cve_{year}.csv"

        if not filename.exists():
            errors.append(
                f"Отсутствует файл: {filename.name}"
            )
            continue

        try:
            df_year = pd.read_csv(filename)

            missing = [
                col for col in REQUIRED_COLUMNS
                if col not in df_year.columns
            ]

            if missing:
                errors.append(
                    f"{filename.name}: отсутствуют столбцы {missing}"
                )
                continue

            original_count = len(df_year)


            df_year["date"] = pd.to_datetime(
                df_year["date"],
                format="%Y-%m-%d",
                errors="coerce"
            )

            df_year["cvss_score"] = pd.to_numeric(
                df_year["cvss_score"], errors="coerce"
            )

            df_year["affected_hosts"] = pd.to_numeric(
                df_year["affected_hosts"], errors="coerce"
            )

            # Проверяем обязательные значения
            required_values = [
                "date", "cvss_score",
                "affected_hosts", "cve_id"
            ]

            invalid_mask = df_year[
                required_values
            ].isna().any(axis=1)

            # Проверяем допустимые диапазоны
            invalid_mask |= ~df_year[
                "cvss_score"
            ].between(0, 10)

            invalid_mask |= (
                df_year["affected_hosts"] < 0
            )

            invalid_count = int(invalid_mask.sum())

            if invalid_count > 0:
                errors.append(
                    f"{filename.name}: обнаружено "
                    f"{invalid_count} некорректных строк "
                    f"из {original_count}. "
                    f"Некорректные строки исключены."
                )

            # Удаляем только некорректные строки
            df_year = df_year.loc[
                ~invalid_mask
            ].copy()

            df_year["year"] = (
                df_year["date"].dt.year
            )

            # Проверяем соответствие года имени файла
            wrong_year_mask = (
                df_year["year"] != year
            )

            wrong_year_count = int(
                wrong_year_mask.sum()
            )

            if wrong_year_count > 0:
                errors.append(
                    f"{filename.name}: "
                    f"{wrong_year_count} строк содержат "
                    f"дату другого года. "
                    f"Эти строки исключены."
                )

                df_year = df_year.loc[
                    ~wrong_year_mask
                ].copy()

            if df_year.empty:
                errors.append(
                    f"{filename.name}: "
                    "нет корректных записей для анализа."
                )
                continue

            dataframes.append(df_year)

        except (
            OSError,
            UnicodeError,
            pd.errors.ParserError,
            ValueError
        ) as error:
            errors.append(
                f"{filename.name}: ошибка чтения — {error}"
            )

    if not dataframes:
        return pd.DataFrame(), errors

    combined = pd.concat(
        dataframes,
        ignore_index=True
    )

    return combined, errors