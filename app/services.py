"""服务层：导入、登记、计划生命周期、批准冻结。"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from . import x509_utils
from .db import get_conn
from .errors import conflict, invalid_window, not_found
from .evaluation import evaluate_plan
from .timeutils import isoformat, now_utc, parse_utc, validate_window


# --------------------------------------------------------------- 信任根

def import_root(version: str, description: str, pem: str) -> dict:
    certs = x509_utils.parse_pem_chain(pem, what="信任根 PEM")
    x509_utils.assert_root_bundle(certs)
    created = isoformat(now_utc())
    canonical = x509_utils.canonical_pem(certs)
    with get_conn() as conn:
        exists = conn.execute(
            "SELECT 1 FROM trust_roots WHERE version = ?", (version,)
        ).fetchone()
        if exists:
            raise conflict("duplicate_root_version", f"信任根版本 {version!r} 已存在")
        cur = conn.execute(
            "INSERT INTO trust_roots(version, description, pem, created_at) VALUES(?,?,?,?)",
            (version, description, canonical, created),
        )
        new_version = version
    # 新版本信任根入库：现存已批准计划全部待复核（历史判定保留在 approvals）
    _mark_approved_pending_review(reason=f"信任根版本 {new_version} 已换版导入")
    return {
        "id": cur.lastrowid,
        "version": new_version,
        "description": description,
        "certificate_count": len(certs),
        "fingerprints": [x509_utils.fingerprint_hex(c) for c in certs],
        "created_at": created,
    }


def list_roots() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, version, description, created_at FROM trust_roots ORDER BY id"
        ).fetchall()
        out = []
        for r in rows:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM trust_roots WHERE id = ?", (r["id"],)
            ).fetchone()["n"]
            # 每张 PEM 约等于一个 BEGIN 标记
            pem = conn.execute("SELECT pem FROM trust_roots WHERE id = ?", (r["id"],)).fetchone()["pem"]
            out.append({
                "id": r["id"],
                "version": r["version"],
                "description": r["description"],
                "certificate_count": pem.count("-----BEGIN CERTIFICATE-----"),
                "created_at": r["created_at"],
            })
    return out


# --------------------------------------------------------------- 证书

def import_chain(pem: str) -> dict:
    certs = x509_utils.parse_pem_chain(pem, what="证书链 PEM")
    leaf = certs[0]
    fp = x509_utils.fingerprint_hex(leaf)
    meta = x509_utils.cert_meta(leaf)
    created = isoformat(now_utc())
    with get_conn() as conn:
        dup = conn.execute(
            "SELECT fingerprint FROM certificates WHERE fingerprint = ?", (fp,)
        ).fetchone()
        if dup:
            raise conflict("duplicate_certificate_fingerprint",
                           f"叶子证书指纹 {fp} 已存在，重复导入被拒绝")
        conn.execute(
            """INSERT INTO certificates
               (fingerprint, subject_cn, issuer_cn, serial, not_before, not_after,
                chain_pem, imported_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (fp, meta["subject_cn"], meta["issuer_cn"], meta["serial"],
             isoformat(meta["not_before"]), isoformat(meta["not_after"]),
             x509_utils.canonical_pem(certs), created),
        )
    return {
        "fingerprint": fp,
        "subject_cn": meta["subject_cn"],
        "issuer_cn": meta["issuer_cn"],
        "serial_hex": meta["serial"],
        "not_before": isoformat(meta["not_before"]),
        "not_after": isoformat(meta["not_after"]),
        "chain_length": len(certs),
        "imported_at": created,
    }


def list_certificates() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT fingerprint, subject_cn, issuer_cn, serial, not_before, not_after,
                      imported_at, chain_pem
                 FROM certificates ORDER BY id"""
        ).fetchall()
    return [{
        "fingerprint": r["fingerprint"],
        "subject_cn": r["subject_cn"],
        "issuer_cn": r["issuer_cn"],
        "serial_hex": r["serial"],
        "not_before": r["not_before"],
        "not_after": r["not_after"],
        "imported_at": r["imported_at"],
        "chain_length": r["chain_pem"].count("-----BEGIN CERTIFICATE-----"),
    } for r in rows]


# --------------------------------------------------------------- 服务窗口

def register_window(domain: str, fingerprint: str,
                    start_in: str, end_in: str) -> dict:
    start = parse_utc(start_in, "窗口开始")
    end = parse_utc(end_in, "窗口结束")
    validate_window(start, end)

    with get_conn() as conn:
        cert = conn.execute(
            "SELECT subject_cn FROM certificates WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if cert is None:
            raise not_found("unknown_certificate",
                            f"证书指纹 {fingerprint} 未导入，请先导入证书链")
        dup = conn.execute(
            "SELECT id FROM windows WHERE domain = ? AND cert_fp = ?",
            (domain, fingerprint),
        ).fetchone()
        if dup:
            raise conflict("duplicate_window",
                           f"域名 {domain} 已登记证书 {fingerprint} 的服务窗口；"
                           f"如需调整请删除后重新登记")
        created = isoformat(now_utc())
        cur = conn.execute(
            """INSERT INTO windows(domain, cert_fp, start_at, end_at, created_at)
               VALUES(?,?,?,?,?)""",
            (domain, fingerprint, isoformat(start), isoformat(end), created),
        )
        window_id = cur.lastrowid

    _mark_domain_approved_pending_review(
        domain, reason=f"域名 {domain} 的服务窗口发生登记/变动"
    )
    return {
        "id": window_id,
        "domain": domain,
        "fingerprint": fingerprint,
        "subject_cn": cert["subject_cn"],
        "start_at": isoformat(start),
        "end_at": isoformat(end),
        "created_at": created,
    }


def list_windows(domain: Optional[str] = None) -> list[dict]:
    q = ("""SELECT w.id, w.domain, w.cert_fp, w.start_at, w.end_at, w.created_at,
                   c.subject_cn
              FROM windows w JOIN certificates c ON c.fingerprint = w.cert_fp""")
    args: tuple = ()
    if domain:
        q += " WHERE w.domain = ?"
        args = (domain,)
    q += " ORDER BY w.domain, w.start_at"
    with get_conn() as conn:
        rows = conn.execute(q, args).fetchall()
    return [{
        "id": r["id"],
        "domain": r["domain"],
        "fingerprint": r["cert_fp"],
        "subject_cn": r["subject_cn"],
        "start_at": r["start_at"],
        "end_at": r["end_at"],
        "created_at": r["created_at"],
    } for r in rows]


def delete_window(window_id: int) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM windows WHERE id = ?", (window_id,)).fetchone()
        if row is None:
            raise not_found("window_not_found", f"服务窗口 #{window_id} 不存在")
        conn.execute("DELETE FROM windows WHERE id = ?", (window_id,))
        domain = row["domain"]
    _mark_domain_approved_pending_review(
        domain, reason=f"域名 {domain} 的服务窗口 #{window_id} 被删除"
    )
    return {"id": window_id, "domain": domain, "deleted": True}


# --------------------------------------------------------------- 待复核标记

def _mark_domain_approved_pending_review(domain: str, reason: str) -> None:
    with get_conn() as conn:
        conn.execute(
            """UPDATE plans
                  SET status = 'pending_review', updated_at = ?
                WHERE domain = ? AND status = 'gap_free'
                  AND id IN (SELECT DISTINCT plan_id FROM approvals)""",
            (isoformat(now_utc()), domain),
        )
        if conn.total_changes:
            conn.execute(
                """UPDATE plans SET decision = json_set(COALESCE(decision,'{}'),
                       '$.review_reason', ?)
                    WHERE domain = ? AND status = 'pending_review'""",
                (reason, domain),
            )


def _mark_approved_pending_review(reason: str) -> None:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT id FROM plans
                WHERE status = 'gap_free'
                  AND id IN (SELECT DISTINCT plan_id FROM approvals)"""
        ).fetchall()
        ts = isoformat(now_utc())
        for r in rows:
            conn.execute(
                """UPDATE plans SET status = 'pending_review',
                       decision = json_set(COALESCE(decision,'{}'), '$.review_reason', ?),
                       updated_at = ?
                     WHERE id = ?""",
                (reason, ts, r["id"]),
            )


# --------------------------------------------------------------- 计划

def _store_decision(conn, plan_id: Optional[int], decision: dict,
                    domain: str, version: str,
                    eval_start: datetime, eval_end: datetime) -> int:
    status = "gap_free" if not decision["has_gap"] else "gap"
    ts = isoformat(now_utc())
    payload = json.dumps(decision, ensure_ascii=False)
    if plan_id is None:
        cur = conn.execute(
            """INSERT INTO plans(domain, root_version, eval_start, eval_end,
                                 status, decision, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (domain, version, isoformat(eval_start), isoformat(eval_end),
             status, payload, ts, ts),
        )
        return cur.lastrowid
    conn.execute(
        """UPDATE plans SET root_version = ?, eval_start = ?, eval_end = ?,
               status = ?, decision = ?, updated_at = ?
             WHERE id = ?""",
        (version, isoformat(eval_start), isoformat(eval_end), status, payload, ts, plan_id),
    )
    return plan_id


def create_plan(domain: str, root_version: str,
                eval_start_in: str, eval_end_in: str) -> dict:
    eval_start = parse_utc(eval_start_in, "评估开始")
    eval_end = parse_utc(eval_end_in, "评估结束")
    validate_window(eval_start, eval_end)
    decision = evaluate_plan(domain, root_version,
                             isoformat(eval_start), isoformat(eval_end))
    with get_conn() as conn:
        plan_id = _store_decision(conn, None, decision, domain, root_version,
                                  eval_start, eval_end)
    return {"plan_id": plan_id, "status": decision_to_status(decision), "decision": decision}


def decision_to_status(decision: dict) -> str:
    return "gap_free" if not decision["has_gap"] else "gap"


def reevaluate_plan(plan_id: int) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
    if row is None:
        raise not_found("plan_not_found", f"计划 #{plan_id} 不存在")
    decision = evaluate_plan(row["domain"], row["root_version"],
                             row["eval_start"], row["eval_end"])
    with get_conn() as conn:
        _store_decision(conn, plan_id, decision,
                        row["domain"], row["root_version"],
                        parse_utc(row["eval_start"]), parse_utc(row["eval_end"]))
    return {"plan_id": plan_id, "status": decision_to_status(decision), "decision": decision}


def approve_plan(plan_id: int) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
        if row is None:
            raise not_found("plan_not_found", f"计划 #{plan_id} 不存在")
        if row["status"] != "gap_free":
            raise conflict(
                "plan_not_approvable",
                f"计划 #{plan_id} 当前状态为 {row['status']}，仅无断档(gap_free)的计划可批准；"
                f"待复核计划须先重新评估且无断档",
            )
        decision = json.loads(row["decision"])
        # 冻结：各叶子证书指纹 + 信任根版本 + 完整判定
        frozen = {
            "frozen_at": isoformat(now_utc()),
            "root_version": row["root_version"],
            "root_fingerprints": sorted({
                c["chain"]["root_fingerprint"]
                for c in decision.get("certificates", [])
                if c["chain"].get("root_fingerprint")
            }),
            "certificate_fingerprints": sorted({
                c["fingerprint"] for c in decision.get("certificates", [])
            }),
            "domain": row["domain"],
            "evaluation_interval": decision["evaluation_interval"],
            "decision": decision,
        }
        approved_at = frozen["frozen_at"]
        cur = conn.execute(
            """INSERT INTO approvals(plan_id, domain, root_version, eval_start, eval_end,
                                     decision, approved_at)
               VALUES(?,?,?,?,?,?,?)""",
            (plan_id, row["domain"], row["root_version"],
             row["eval_start"], row["eval_end"],
             json.dumps(frozen, ensure_ascii=False), approved_at),
        )
        approval_id = cur.lastrowid
    return {
        "approval_id": approval_id,
        "plan_id": plan_id,
        "approved_at": approved_at,
        "frozen": frozen,
    }


def _plan_out(row, conn) -> dict:
    try:
        decision = json.loads(row["decision"]) if row["decision"] else None
    except json.JSONDecodeError:
        decision = None
    approvals = conn.execute(
        "SELECT id, approved_at FROM approvals WHERE plan_id = ? ORDER BY id",
        (row["id"],),
    ).fetchall()
    return {
        "plan_id": row["id"],
        "domain": row["domain"],
        "root_version": row["root_version"],
        "evaluation_interval": {"start": row["eval_start"], "end": row["eval_end"]},
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "approvals": [{"approval_id": a["id"], "approved_at": a["approved_at"]} for a in approvals],
        "decision": decision,
    }


def get_plan(plan_id: int) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
        if row is None:
            raise not_found("plan_not_found", f"计划 #{plan_id} 不存在")
        return _plan_out(row, conn)


def list_plans(domain: Optional[str] = None) -> list[dict]:
    q = "SELECT * FROM plans"
    args: tuple = ()
    if domain:
        q += " WHERE domain = ?"
        args = (domain,)
    q += " ORDER BY id"
    with get_conn() as conn:
        rows = conn.execute(q, args).fetchall()
        return [_plan_out(r, conn) for r in rows]


def get_approval(approval_id: int) -> dict:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM approvals WHERE id = ?", (approval_id,)
        ).fetchone()
        if row is None:
            raise not_found("approval_not_found", f"批准记录 #{approval_id} 不存在")
        return {
            "approval_id": row["id"],
            "plan_id": row["plan_id"],
            "domain": row["domain"],
            "root_version": row["root_version"],
            "evaluation_interval": {"start": row["eval_start"], "end": row["eval_end"]},
            "approved_at": row["approved_at"],
            "frozen": json.loads(row["decision"]),
        }


def list_approvals(plan_id: Optional[int] = None) -> list[dict]:
    q = "SELECT id, plan_id, domain, root_version, eval_start, eval_end, approved_at FROM approvals"
    args: tuple = ()
    if plan_id is not None:
        q += " WHERE plan_id = ?"
        args = (plan_id,)
    q += " ORDER BY id"
    with get_conn() as conn:
        rows = conn.execute(q, args).fetchall()
    return [{
        "approval_id": r["id"],
        "plan_id": r["plan_id"],
        "domain": r["domain"],
        "root_version": r["root_version"],
        "evaluation_interval": {"start": r["eval_start"], "end": r["eval_end"]},
        "approved_at": r["approved_at"],
    } for r in rows]
