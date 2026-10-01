"""HTTP 请求模型（时间一律为带时区的 ISO8601 字符串）。"""
from __future__ import annotations

from pydantic import BaseModel, Field


class RootImportIn(BaseModel):
    version: str = Field(min_length=1, max_length=64, description="信任根版本，如 2026Q3")
    description: str = Field(default="", max_length=512)
    pem: str = Field(description="一个或多个自签名信任根 PEM")


class ChainImportIn(BaseModel):
    pem: str = Field(description="PEM 证书链，第一张为叶子证书，其余为中间 CA")


class WindowIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    fingerprint: str = Field(min_length=32, description="叶子证书 SHA256 指纹（hex）")
    start_at: str
    end_at: str


class PlanIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    root_version: str = Field(min_length=1, max_length=64)
    eval_start: str
    eval_end: str
