"""核心业务逻辑：在评估区间内逐时刻判断是否有验证通过的在岗证书。

区间表示全部为 UTC 半开区间 [开始, 结束)；端点相接（[a,b)+[b,c)）不算断档，
因此只需在有限个断点切出的时间片上取“左端点时刻”判定即可：
若每个时间片起点都有可用证书，则任意时刻都有可用证书。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from . import x509_utils
from .db import get_conn
from .errors import conflict, invalid_window, not_found
from .timeutils import isoformat, intervals_overlap, parse_utc, validate_window


# --------------------------------------------------------------- 数据装配

def _load_root_version(conn, version: str):
    row = conn.execute(
        "SELECT * FROM trust_roots WHERE version = ?", (version,)
    ).fetchone()
    if row is None:
        raise not_found("unknown_root_version", f"未知的信任根版本: {version!r}")
    return row


def _windows_with_certs(conn, domain: str) -> list[dict]:
    rows = conn.execute(
        """SELECT w.id AS w_id, w.start_at AS w_start, w.end_at AS w_end,
                  c.fingerprint, c.chain_pem
             FROM windows w
             JOIN certificates c ON c.fingerprint = w.cert_fp
            WHERE w.domain = ?
            ORDER BY w.start_at""",
        (domain,),
    ).fetchall()
    out = []
    for r in rows:
        out.append({
            "window_id": r["w_id"],
            "start": parse_utc(r["w_start"], "窗口开始"),
            "end": parse_utc(r["w_end"], "窗口结束"),
            "fingerprint": r["fingerprint"],
            "chain": x509_utils.parse_pem_chain(r["chain_pem"], what=f"证书 {r['fingerprint']} 链"),
        })
    return out


def _clip_to_eval(start: datetime, end: datetime,
                  eval_start: datetime, eval_end: datetime) -> Optional[tuple[datetime, datetime]]:
    s = max(start, eval_start)
    e = min(end, eval_end)
    return (s, e) if s < e else None


# --------------------------------------------------------------- 判定

def evaluate_plan(domain: str, root_version: str,
                  eval_start_in: str, eval_end_in: str) -> dict[str, Any]:
    eval_start = parse_utc(eval_start_in, "评估开始")
    eval_end = parse_utc(eval_end_in, "评估结束")
    validate_window(eval_start, eval_end)

    with get_conn() as conn:
        root_row = _load_root_version(conn, root_version)
        windows = _windows_with_certs(conn, domain)

    roots = x509_utils.parse_pem_chain(root_row["pem"], what=f"信任根 {root_version}")

    # 同一叶子证书可能只有一条窗口（DB 唯一约束），按指纹聚合
    by_fp: dict[str, dict] = {}
    for w in windows:
        entry = by_fp.setdefault(w["fingerprint"], {"window": w, "chain": w["chain"]})
    if not by_fp:
        return _empty_result(domain, root_version, eval_start, eval_end)

    # 只评估与评估区间有交集的窗口
    active: list[dict] = []
    for fp, data in by_fp.items():
        w = data["window"]
        clip = _clip_to_eval(w["start"], w["end"], eval_start, eval_end)
        if clip is None:
            continue
        chain = data["chain"]
        leaf, inters = chain[0], chain[1:]
        cr = x509_utils.verify_chain(leaf, inters, roots)
        san_ok, san_reason = x509_utils.domain_matches_san(leaf, domain)
        static_errors = list(cr.errors)
        if not san_ok:
            static_errors.append({"code": "san_mismatch", "reason": san_reason})
        active.append({
            "fp": fp,
            "window": w,
            "clip": clip,
            "leaf": leaf,
            "chain_result": cr,
            "static_errors": static_errors,
        })

    if not active:
        return _empty_result(domain, root_version, eval_start, eval_end)

    # 断点：评估起止 + 各窗口在评估区间内的裁剪端点
    points = {eval_start, eval_end}
    for a in active:
        points.add(a["clip"][0])
        points.add(a["clip"][1])
    points = sorted(points)
    segments = list(zip(points[:-1], points[1:]))

    # 每张证书在评估区间内的不可用片段：[(start,end,code,detail)]
    cert_bad: dict[str, list[tuple[datetime, datetime, str, str]]] = {a["fp"]: [] for a in active}

    gap_segments: list[tuple[datetime, datetime]] = []

    for seg_s, seg_e in segments:
        t = seg_s  # 半开区间，取片段左端点即可代表整个片段
        available_fps: set[str] = set()
        seg_reasons: dict[str, list[dict]] = {}

        for a in active:
            ws, we = a["clip"]
            in_window = ws <= t < we
            if not in_window:
                continue  # 不在服务窗口 => 该证书在此片段不承担服务，不计入不可用
            errs: list[dict] = list(a["static_errors"])
            if not a["static_errors"]:
                cr = a["chain_result"]
                if t < cr.not_before or t >= cr.not_after:
                    if t < cr.not_before:
                        errs.append({"code": "not_yet_valid",
                                     "reason": f"证书链 {isoformat(cr.not_before)} 起才生效"})
                    else:
                        errs.append({"code": "expired",
                                     "reason": f"证书链 {isoformat(cr.not_after)} 已到期"})
            if errs:
                seg_reasons[a["fp"]] = errs
                for e in errs:
                    cert_bad[a["fp"]].append((seg_s, seg_e, e["code"], e["reason"]))
            else:
                available_fps.add(a["fp"])

        if not available_fps:
            gap_segments.append((seg_s, seg_e))

    merged_gaps = _merge_adjacent(gap_segments)

    gaps_out = []
    for gs, ge in merged_gaps:
        contributors = {}
        for fp, items in cert_bad.items():
            pieces = [
                {"start": isoformat(s), "end": isoformat(e), "code": code, "reason": reason}
                for (s, e, code, reason) in items
                if s < ge and e > gs  # 与该断档片段相交
            ]
            if pieces:
                contributors[fp] = pieces
        gaps_out.append({
            "start": isoformat(gs),
            "end": isoformat(ge),
            "unavailable": contributors,
        })

    certificates_out = []
    for a in sorted(active, key=lambda x: x["clip"][0]):
        leaf = a["leaf"]
        meta = x509_utils.cert_meta(leaf)
        cr = a["chain_result"]
        certificates_out.append({
            "fingerprint": a["fp"],
            "subject_cn": meta["subject_cn"],
            "window": {
                "start": isoformat(a["window"]["start"]),
                "end": isoformat(a["window"]["end"]),
            },
            "window_in_eval": {
                "start": isoformat(a["clip"][0]),
                "end": isoformat(a["clip"][1]),
            },
            "static_verification_passed": not a["static_errors"],
            "static_errors": a["static_errors"],
            "chain": {
                "root_fingerprint": cr.root_fp,
                "path_fingerprints": cr.path_fps,
                "path_subjects": cr.path_subjects,
                "chain_validity_envelope": {
                    "not_before": isoformat(cr.not_before) if cr.not_before else None,
                    "not_after": isoformat(cr.not_after) if cr.not_after else None,
                },
            },
            "unavailable_intervals": _merge_reason_intervals(cert_bad[a["fp"]]),
        })

    return {
        "domain": domain,
        "root_version": root_version,
        "evaluation_interval": {"start": isoformat(eval_start), "end": isoformat(eval_end)},
        "has_gap": bool(merged_gaps),
        "gap_count": len(merged_gaps),
        "gaps": gaps_out,
        "certificates": certificates_out,
    }


def _merge_adjacent(segs: list[tuple[datetime, datetime]]) -> list[tuple[datetime, datetime]]:
    """端点相接的片段合并：[a,b)+[b,c) -> [a,c)。"""
    if not segs:
        return []
    segs = sorted(segs)
    merged = [segs[0]]
    for s, e in segs[1:]:
        ls, le = merged[-1]
        if s == le:
            merged[-1] = (ls, e)
        else:
            merged.append((s, e))
    return merged


def _merge_reason_intervals(
    items: list[tuple[datetime, datetime, str, str]],
) -> list[dict]:
    """把同一原因的相邻/重叠片段合并，输出每个不可用区间。"""
    by_reason: dict[tuple[str, str], list[tuple[datetime, datetime]]] = {}
    for s, e, code, reason in items:
        by_reason.setdefault((code, reason), []).append((s, e))

    out: list[dict] = []
    for (code, reason), segs in by_reason.items():
        segs.sort()
        cur_s, cur_e = segs[0]
        for s, e in segs[1:]:
            if s <= cur_e:
                cur_e = max(cur_e, e)
            else:
                out.append({"start": isoformat(cur_s), "end": isoformat(cur_e),
                            "code": code, "reason": reason})
                cur_s, cur_e = s, e
        out.append({"start": isoformat(cur_s), "end": isoformat(cur_e),
                    "code": code, "reason": reason})
    out.sort(key=lambda d: (d["start"], d["code"]))
    return out


def _empty_result(domain: str, version: str,
                  eval_start: datetime, eval_end: datetime) -> dict:
    return {
        "domain": domain,
        "root_version": version,
        "evaluation_interval": {"start": isoformat(eval_start), "end": isoformat(eval_end)},
        "has_gap": True,
        "gap_count": 1,
        "gaps": [{
            "start": isoformat(eval_start),
            "end": isoformat(eval_end),
            "unavailable": {},
        }],
        "certificates": [],
    }
