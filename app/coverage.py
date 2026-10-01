"""评估区间覆盖（断档）计算。

所有区间均为半开区间 [start, end)：前一区间的 end 与后一区间的 start
相接（相等）时视为连续，不构成断档。
"""
from __future__ import annotations

from datetime import datetime


def compute_gaps(
    eval_start: datetime,
    eval_end: datetime,
    intervals: list[tuple[datetime, datetime]],
) -> list[tuple[datetime, datetime]]:
    """返回 [eval_start, eval_end) 内未被 intervals 覆盖的全部断档区间。"""
    gaps: list[tuple[datetime, datetime]] = []
    cursor = eval_start
    for start, end in sorted(intervals):
        start = max(start, eval_start)
        end = min(end, eval_end)
        if end <= cursor:
            continue
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
        if cursor >= eval_end:
            break
    if cursor < eval_end:
        gaps.append((cursor, eval_end))
    return gaps
