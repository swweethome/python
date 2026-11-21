
import pandas as pd

import data_loader


def make_valid_data():
    return pd.DataFrame({
        "cve_id": ["CVE-2026-0001", "CVE-2026-0002"],
        "date": ["2026-01-10", "2026-02-15"],
        "attack_type": ["RCE", "XSS"],
        "vendor": ["Microsoft", "Adobe"],
        "product": ["Windows", "Acrobat"],
        "cvss_score": [9.8, 6.5],
        "severity": ["Critical", "Medium"],
        "attack_vector": ["Network", "Network"],
        "attacker_country": ["USA", "Germany"],
        "target_sector": ["IT", "Finance"],
        "affected_hosts": [100, 200],
        "status": ["Published", "Published"],
        "exploit_available": [True, False]
    })


def test_valid_csv(tmp_path, monkeypatch):
    df = make_valid_data()
    df.to_csv(
        tmp_path / "cyberattacks_cve_2026.csv",
        index=False
    )

    monkeypatch.setattr(data_loader, "DATA_DIR", tmp_path)
    data_loader.load_data.clear()

    result, errors = data_loader.load_data()

    assert len(result) == 2
    assert not any("некорректных строк" in e for e in errors)


def test_invalid_cvss(tmp_path, monkeypatch):
    df = make_valid_data()
    df.loc[0, "cvss_score"] = 15

    df.to_csv(
        tmp_path / "cyberattacks_cve_2026.csv",
        index=False
    )

    monkeypatch.setattr(data_loader, "DATA_DIR", tmp_path)
    data_loader.load_data.clear()

    result, errors = data_loader.load_data()

    assert len(result) == 1
    assert any("1 некорректных строк" in e for e in errors)


def test_invalid_date(tmp_path, monkeypatch):
    df = make_valid_data()
    df.loc[0, "date"] = "invalid_date"

    df.to_csv(
        tmp_path / "cyberattacks_cve_2026.csv",
        index=False
    )

    monkeypatch.setattr(data_loader, "DATA_DIR", tmp_path)
    data_loader.load_data.clear()

    result, errors = data_loader.load_data()

    assert len(result) == 1
    assert any("некорректных строк" in e for e in errors)


def test_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(data_loader, "DATA_DIR", tmp_path)
    data_loader.load_data.clear()

    result, errors = data_loader.load_data()

    assert result.empty
    assert any("Отсутствует файл" in e for e in errors)


def test_wrong_year(tmp_path, monkeypatch):
    df = make_valid_data()
    df.loc[0, "date"] = "2025-01-10"

    df.to_csv(
        tmp_path / "cyberattacks_cve_2026.csv",
        index=False
    )

    monkeypatch.setattr(data_loader, "DATA_DIR", tmp_path)
    data_loader.load_data.clear()

    result, errors = data_loader.load_data()

    assert len(result) == 1
    assert any("дату другого года" in e for e in errors)
