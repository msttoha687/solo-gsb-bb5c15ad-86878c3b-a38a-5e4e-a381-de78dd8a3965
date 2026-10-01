"""SQLite 连接管理与表结构初始化。"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_roots (
    id          INTEGER PRIMARY KEY,
    version     TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    pem         TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id            INTEGER PRIMARY KEY,
    fingerprint   TEXT NOT NULL UNIQUE,
    subject_cn    TEXT NOT NULL DEFAULT '',
    issuer_cn     TEXT NOT NULL DEFAULT '',
    serial        TEXT NOT NULL DEFAULT '',
    not_before    TEXT NOT NULL,
    not_after     TEXT NOT NULL,
    chain_pem     TEXT NOT NULL,
    imported_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS windows (
    id            INTEGER PRIMARY KEY,
    domain        TEXT NOT NULL,
    cert_fp       TEXT NOT NULL REFERENCES certificates(fingerprint),
    start_at      TEXT NOT NULL,
    end_at        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    UNIQUE(domain, cert_fp)
);
CREATE INDEX IF NOT EXISTS idx_windows_domain ON windows(domain);

CREATE TABLE IF NOT EXISTS plans (
    id          INTEGER PRIMARY KEY,
    domain      TEXT NOT NULL,
    root_version TEXT NOT NULL,
    eval_start  TEXT NOT NULL,
    eval_end    TEXT NOT NULL,
    status      TEXT NOT NULL,            -- gap | gap_free | pending_review
    decision    TEXT NOT NULL DEFAULT '', -- 最近一次判定快照 JSON
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_plans_domain ON plans(domain);

CREATE TABLE IF NOT EXISTS approvals (
    id           INTEGER PRIMARY KEY,
    plan_id      INTEGER NOT NULL REFERENCES plans(id),
    domain       TEXT NOT NULL,
    root_version TEXT NOT NULL,
    eval_start   TEXT NOT NULL,
    eval_end     TEXT NOT NULL,
    decision     TEXT NOT NULL,          -- 批准时刻冻结的完整判定 JSON
    approved_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_plan ON approvals(plan_id);
"""


def _connect() -> sqlite3.Connection:
    settings.ensure_dirs()
    conn = sqlite3.connect(settings.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)
