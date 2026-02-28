# app/http_metrics.py
import os
import time
import threading
from collections import deque
from typing import Any, Dict, List, Tuple


class HttpMetricStore:
    """
    Rolling store of recent request outcomes for quick ops visibility.
    Not durable; resets on deploy. Safe-by-default: no bodies, no headers.
    Items are tuples: (ts_ns, method, route_template, status_code, duration_ms)
    """

    def __init__(self, maxlen: int = 4000):
        self._lock = threading.Lock()
        self._items = deque(maxlen=maxlen)

    def add(self, ts_ns: int, method: str, route: str, status: int, dur_ms: int) -> None:
        with self._lock:
            self._items.append((int(ts_ns), str(method), str(route), int(status), int(dur_ms)))

    def snapshot(self) -> List[Tuple[int, str, str, int, int]]:
        with self._lock:
            return list(self._items)


def percentile(values: List[int], p: float) -> int:
    if not values:
        return 0
    vs = sorted(values)
    if p <= 0:
        return int(vs[0])
    if p >= 100:
        return int(vs[-1])
    k = (len(vs) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(vs) - 1)
    if f == c:
        return int(vs[f])
    d0 = vs[f] * (c - k)
    d1 = vs[c] * (k - f)
    return int(round(d0 + d1))


def summarize_http_metrics(
    items: List[Tuple[int, str, str, int, int]],
    *,
    window_sec: int,
    limit: int,
) -> Dict[str, Any]:
    now_ns = time.time_ns()
    window_ns = max(1, int(window_sec)) * 1_000_000_000
    cut = now_ns - window_ns

    filtered = [x for x in items if x[0] >= cut]
    total = len(filtered)

    durations = [x[4] for x in filtered]
    s5xx = sum(1 for x in filtered if 500 <= x[3] <= 599)
    s4xx = sum(1 for x in filtered if 400 <= x[3] <= 499)

    by_route: Dict[str, Dict[str, Any]] = {}
    for _, method, route, status, dur_ms in filtered:
        key = f"{method} {route}"
        b = by_route.get(key)
        if b is None:
            b = {"count": 0, "durations": [], "5xx": 0, "4xx": 0}
            by_route[key] = b
        b["count"] += 1
        b["durations"].append(int(dur_ms))
        if 500 <= status <= 599:
            b["5xx"] += 1
        if 400 <= status <= 499:
            b["4xx"] += 1

    rows: List[Dict[str, Any]] = []
    for k, b in by_route.items():
        ds = b["durations"]
        rows.append(
            {
                "route": k,
                "count": int(b["count"]),
                "p50_ms": percentile(ds, 50),
                "p95_ms": percentile(ds, 95),
                "avg_ms": float(sum(ds) / len(ds)) if ds else 0.0,
                "rate_5xx": float(b["5xx"] / b["count"]) if b["count"] else 0.0,
                "rate_4xx": float(b["4xx"] / b["count"]) if b["count"] else 0.0,
            }
        )

    rows.sort(key=lambda r: (r["rate_5xx"], r["p95_ms"], r["count"]), reverse=True)
    rows = rows[: max(1, min(200, int(limit)))]

    return {
        "window_sec": int(window_sec),
        "events_total": int(total),
        "p50_ms": percentile(durations, 50),
        "p95_ms": percentile(durations, 95),
        "avg_ms": float(sum(durations) / len(durations)) if durations else 0.0,
        "rate_5xx": float(s5xx / total) if total else 0.0,
        "rate_4xx": float(s4xx / total) if total else 0.0,
        "routes": rows,
    }


HTTP_METRICS = HttpMetricStore(maxlen=int(os.getenv("HTTP_METRICS_MAXLEN", "4000") or "4000"))
