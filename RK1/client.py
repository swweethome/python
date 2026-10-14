from typing import Dict, List, Optional

import httpx
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

BASE_URL = "http://193.233.171.205:8000"
LOGIN = "student"
PASSWORD = "student_pass"

class Row(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: int

    @field_validator("id", mode="before")
    @classmethod
    def check_id(cls, v):
        if v is None or isinstance(v, bool):
            raise ValueError("bad id")
        return v

    @field_validator("*", mode="before")
    @classmethod
    def clean(cls, v, info):
        if info.field_name == "id" or v is None:
            return v
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v if x is not None)
        v = str(v).strip()
        if v.lower() in ("", "null", "none", "nan"):
            return None
        return v


class IdentificationRow(Row):
    title: Optional[str] = Field(default=None, alias="Title")
    category: Optional[str] = Field(default=None, alias="Category")
    attack_type: Optional[str] = Field(default=None, alias="Attack Type")


class AttackDescriptionRow(Row):
    scenario_description: Optional[str] = Field(default=None, alias="Scenario Description")
    attack_steps: Optional[str] = Field(default=None, alias="Attack Steps")
    tools_used: Optional[str] = Field(default=None, alias="Tools Used")


class TargetVulnerabilityRow(Row):
    target_type: Optional[str] = Field(default=None, alias="Target Type")
    vulnerability: Optional[str] = Field(default=None, alias="Vulnerability")
    mitre_technique: Optional[str] = Field(default=None, alias="MITRE Technique")


class ImpactProtectionRow(Row):
    impact: Optional[str] = Field(default=None, alias="Impact")
    detection_method: Optional[str] = Field(default=None, alias="Detection Method")
    solution: Optional[str] = Field(default=None, alias="Solution")


class MetadataRow(Row):
    tags: Optional[str] = Field(default=None, alias="Tags")
    source: Optional[str] = Field(default=None, alias="Source")


class APIError(Exception):
    pass


class APIClient:
    def __init__(self, base_url, login, password, timeout=30):
        self.client = httpx.Client(
            base_url=base_url,
            auth=(login, password),
            timeout=timeout,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.client.close()

    def _get_json(self, path) -> List[Dict]:
        try:
            r = self.client.get(path)
        except httpx.TimeoutException:
            raise APIError(f"timeout: {path}")
        except httpx.RequestError as e:
            raise APIError(f"request error {path}: {e}")

        if r.status_code == 401:
            raise APIError("401 - wrong login or password")
        if r.status_code == 403:
            raise APIError(f"403 - access denied to {path}")
        if r.status_code == 404:
            raise APIError(f"404 - {path} not found")
        if r.status_code >= 500:
            raise APIError(f"{r.status_code} - server error on {path}")
        if r.status_code != 200:
            raise APIError(f"{r.status_code} on {path}")

        try:
            data = r.json()
        except ValueError:
            raise APIError(f"{path} returned not json")

        if isinstance(data, dict):
            data = data.get("data", [])
        if not isinstance(data, list):
            raise APIError(f"{path} returned not a list")

        return [x for x in data if isinstance(x, dict)]

    def _load(self, path, model):
        result = []
        bad = 0
        for item in self._get_json(path):
            try:
                result.append(model.model_validate(item))
            except ValidationError:
                bad += 1
        print(f"{path}: {len(result)} ok, {bad} skipped")
        return result

    def fetch_identification(self) -> List[IdentificationRow]:
        return self._load("/api/identification", IdentificationRow)

    def fetch_attack_description(self) -> List[AttackDescriptionRow]:
        return self._load("/api/attack_description", AttackDescriptionRow)

    def fetch_target_vulnerability(self) -> List[TargetVulnerabilityRow]:
        return self._load("/api/target_vulnerability", TargetVulnerabilityRow)

    def fetch_impact_protection(self) -> List[ImpactProtectionRow]:
        return self._load("/api/impact_protection", ImpactProtectionRow)

    def fetch_metadata(self) -> List[MetadataRow]:
        return self._load("/api/metadata", MetadataRow)

    def fetch_all(self) -> pd.DataFrame:
        groups = [
            (self.fetch_identification(), IdentificationRow),
            (self.fetch_attack_description(), AttackDescriptionRow),
            (self.fetch_target_vulnerability(), TargetVulnerabilityRow),
            (self.fetch_impact_protection(), ImpactProtectionRow),
            (self.fetch_metadata(), MetadataRow),
        ]

        df = None
        for rows, model in groups:
            if rows:
                part = pd.DataFrame([r.model_dump() for r in rows])
            else:
                part = pd.DataFrame(columns=list(model.model_fields.keys()))
            part = part.drop_duplicates(subset="id")
            df = part if df is None else pd.merge(df, part, on="id", how="inner")

        if df is None or df.empty:
            raise APIError("не удалось собрать ни одной строки для объединения")

        return df.sort_values("id").reset_index(drop=True)

if __name__ == "__main__":
    try:
        with APIClient(BASE_URL, LOGIN, PASSWORD) as api:
            df = api.fetch_all()
    except APIError as e:
        print("Error:", e)
    else:
        df.to_csv("sql_injections_merged.csv", index=False)
        print(f"saved: {df.shape[0]} rows, {df.shape[1]} cols")
        print("columns:", list(df.columns))