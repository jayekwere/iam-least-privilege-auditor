"""Strict YAML configuration. Suppressions remain visible in every report."""

from datetime import date
from pathlib import Path

import yaml
from pydantic import Field, field_validator

from iam_auditor.models import Model, RuleId


class Thresholds(Model):
    unused_days: int = Field(default=90, ge=1, le=400, strict=True)
    key_unused_days: int = Field(default=90, ge=1, le=3650, strict=True)
    key_rotation_days: int = Field(default=90, ge=1, le=3650, strict=True)
    inactive_days: int = Field(default=90, ge=1, le=400, strict=True)


class Suppression(Model):
    rule_id: RuleId
    resource: str = Field(min_length=1)
    account_id: str | None = Field(default=None, pattern=r"^\d{12}$")
    reason: str
    expires_on: date | None = None

    @field_validator("reason")
    @classmethod
    def reason_required(cls, value: str) -> str:
        if len(value.strip()) < 10:
            raise ValueError("Provide a meaningful suppression reason of at least 10 characters")
        return value.strip()


class Config(Model):
    thresholds: Thresholds = Field(default_factory=Thresholds)
    trusted_accounts: list[str] = Field(default_factory=list)
    suppressions: list[Suppression] = Field(default_factory=list)

    @field_validator("trusted_accounts")
    @classmethod
    def account_ids(cls, values: list[str]) -> list[str]:
        if any(len(value) != 12 or not value.isascii() or not value.isdigit() for value in values):
            raise ValueError("trusted_accounts must contain quoted 12-digit account IDs")
        return values


def load_config(path: Path | None) -> Config:
    if path is None:
        return Config()
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return Config.model_validate({} if data is None else data)
