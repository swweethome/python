import sys
from pathlib import Path
import types
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Streamlit is needed in the user's environment; for data-only tests this stub avoids UI initialization.
if 'streamlit' not in sys.modules:
    try:
        import streamlit
    except ImportError:
        st = types.ModuleType('streamlit')
        st.cache_data = lambda f: f
        sys.modules['streamlit'] = st
from data_loader import load_data


def test_all_years_and_rows():
    df, errors = load_data()
    assert not errors, errors
    assert len(df) == 15847
    assert set(df['year'].unique()) == set(range(2014, 2027))


def test_data_validity():
    df, _ = load_data()
    assert df['cvss_score'].between(0, 10).all()
    assert (df['affected_hosts'] >= 0).all()
    assert df['cve_id'].notna().all()


def test_search_sap_export_data():
    df, _ = load_data()
    match = df[['cve_id', 'vendor', 'product']].astype(str).apply(
        lambda col: col.str.contains('SAP', case=False, regex=False, na=False)
    ).any(axis=1)
    selected = df[match]
    assert not selected.empty
    csv = selected.to_csv(index=False)
    assert 'cve_id' in csv.splitlines()[0]
