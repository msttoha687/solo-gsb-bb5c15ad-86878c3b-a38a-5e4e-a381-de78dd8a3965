"""UTC 时间处理：所有窗口与评估区间均为 [开始, 结束) 半开区间。"""
from __future__ import annotations

from datetime import datetime, timezone

from .errors import invalid_window


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime) -> str:
    """统一输出带 Z 后缀的 UTC ISO8601。"""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: str, field: str = "时间") -> datetime:
    """解析 ISO8601 时间，强制要求显式时区，内部统一为 UTC 感知时间。"""
    if not isinstance(value, str):
        raise invalid_window(f"{field}必须是 ISO8601 字符串")
    text = value.strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise invalid_window(f"{field}不是合法的 ISO8601 时间: {value!r}") from exc
    if dt.tzinfo is None:
        raise invalid_window(f"{field}必须显式指定时区（建议 UTC，例如 2026-04-01T00:00:00Z）: {value!r}")
    return dt.astimezone(timezone.utc)


def validate_window(start: datetime, end: datetime) -> None:
    if start >= end:
        raise invalid_window(
            f"服务窗口必须满足 开始 < 结束（半开区间 [开始,结束)），"
            f"收到 {isoformat(start)} ~ {isoformat(end)}"
        )


def intervals_overlap(a_start: datetime, a_end: datetime,
                      b_start: datetime, b_end: datetime) -> bool:
    return a_start < b_end and b_start < a_end
