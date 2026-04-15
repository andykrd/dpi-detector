"""
TCP Latency Scanner — серия tcping-проб для измерения качества соединения.
Определяет: потери, латенси (P50/P95/P99), джиттер, признаки throttling.
"""

import asyncio
import socket
import time
import statistics
from typing import Tuple, List, Optional, Dict


async def _tcp_probe(ip: str, port: int, timeout: float) -> Tuple[bool, float]:
    """
    Одна TCP-проба (tcping). Возвращает (success, latency_sec).
    success=True если соединение установлено, latency — время SYN→SYN-ACK.
    """
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, family=socket.AF_INET),
            timeout=timeout,
        )
        elapsed = time.monotonic() - start
        writer.close()
        await writer.wait_closed()
        return (True, elapsed)
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        elapsed = time.monotonic() - start
        return (False, elapsed)


def _percentile(sorted_data: List[float], pct: float) -> Optional[float]:
    """Вычисляет перцентиль из отсортированного списка."""
    if not sorted_data:
        return None
    n = len(sorted_data)
    k = (pct / 100.0) * (n - 1)
    f = int(k)
    c = f + 1
    if c >= n:
        return sorted_data[-1]
    d = k - f
    return sorted_data[f] + d * (sorted_data[c] - sorted_data[f])


def _fmt_ms(seconds: float) -> str:
    """Форматирует секунды в миллисекунды."""
    return f"{seconds * 1000:.0f}"


def _fmt_ms_f1(seconds: float) -> str:
    """Форматирует секунды в миллисекунды с 1 десятичным."""
    return f"{seconds * 1000:.1f}"


def classify_quality(
    loss_pct: float,
    p50_ms: Optional[float],
    p95_ms: Optional[float],
    jitter_ms: Optional[float],
) -> Tuple[str, str]:
    """
    Классифицирует качество соединения.
    Возвращает (label_rich, diagnosis).
    """
    if p50_ms is None:
        return ("[bold red]НЕДОСТУПНО[/bold red]", "Все пробы неуспешны")

    issues = []
    severity = "ok"

    # Потери
    if loss_pct >= 20:
        issues.append(f"потери {loss_pct:.0f}%")
        severity = "bad"
    elif loss_pct >= 5:
        issues.append(f"потери {loss_pct:.0f}%")
        severity = "warn"
    elif loss_pct > 0:
        issues.append(f"потери {loss_pct:.1f}%")

    # Латенси
    if p50_ms > 500:
        issues.append(f"P50 {p50_ms:.0f}ms")
        severity = "bad"
    elif p50_ms > 200:
        issues.append(f"P50 {p50_ms:.0f}ms")
        if severity == "ok":
            severity = "warn"

    # Throttle: P95 >> P50
    if p95_ms is not None and p50_ms > 0:
        ratio = p95_ms / p50_ms
        if ratio > 5:
            issues.append(f"P95/P50={ratio:.1f}x")
            severity = "bad"
        elif ratio > 2.5:
            issues.append(f"P95/P50={ratio:.1f}x")
            if severity == "ok":
                severity = "warn"

    # Джиттер
    if jitter_ms is not None:
        if jitter_ms > 500:
            issues.append(f"джиттер {jitter_ms:.0f}ms")
            severity = "bad"
        elif jitter_ms > 200:
            issues.append(f"джиттер {jitter_ms:.0f}ms")
            if severity == "ok":
                severity = "warn"

    if severity == "bad":
        label = "[bold red]ПЛОХО[/bold red]"
    elif severity == "warn":
        label = "[yellow]ПРОБЛЕМЫ[/yellow]"
    else:
        label = "[green]НОРМА[/green]"

    diagnosis = ", ".join(issues) if issues else "Стабильное соединение"
    return (label, diagnosis)


async def probe_target(
    ip: str,
    port: int,
    count: int = 20,
    timeout: float = 5.0,
    interval: float = 0.5,
    semaphore: asyncio.Semaphore = None,
) -> Dict:
    """
    Выполняет серию TCP-проб к одной цели.
    Возвращает словарь со статистикой:
      ip, port, total, success, failed, loss_pct,
      latencies (список ms), p50, p95, p99, min, max,
      jitter (stdev ms), label, diagnosis
    """
    if semaphore:
        async with semaphore:
            return await probe_target(ip, port, count, timeout, interval, semaphore=None)

    latencies_sec: List[float] = []
    failed = 0

    for i in range(count):
        success, latency = await _tcp_probe(ip, port, timeout)
        if success:
            latencies_sec.append(latency)
        else:
            failed += 1
        # Интервал между пробами (кроме последней)
        if i < count - 1:
            await asyncio.sleep(interval)

    total = count
    success = len(latencies_sec)
    loss_pct = (failed / total) * 100 if total > 0 else 0

    latencies_ms = sorted([l * 1000 for l in latencies_sec])

    p50 = _percentile(latencies_ms, 50)
    p95 = _percentile(latencies_ms, 95)
    p99 = _percentile(latencies_ms, 99)
    min_ms = latencies_ms[0] if latencies_ms else None
    max_ms = latencies_ms[-1] if latencies_ms else None

    jitter_ms = statistics.stdev(latencies_ms) if len(latencies_ms) >= 2 else None

    quality_label, diagnosis = classify_quality(
        loss_pct,
        p50,
        p95,
        jitter_ms,
    )

    return {
        "ip": ip,
        "port": port,
        "total": total,
        "success": success,
        "failed": failed,
        "loss_pct": loss_pct,
        "latencies_ms": latencies_ms,
        "p50": p50,
        "p95": p95,
        "p99": p99,
        "min": min_ms,
        "max": max_ms,
        "jitter": jitter_ms,
        "quality_label": quality_label,
        "diagnosis": diagnosis,
    }
