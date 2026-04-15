from typing import Tuple
import re
import sys
import socket
import asyncio

import httpx
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from utils import config
from cli.console import console
from cli.ui import clean_hostname, build_domain_row
from core.tls_scanner import check_domain_tls, check_http_injection, create_dpi_client
from core.tcp16_scanner import check_tcp_16_20, check_tcp_16_20_with_rtt
from core.telegram_scanner import run_telegram_test as _run_telegram_test
from core.latency_scanner import probe_target, _fmt_ms, _fmt_ms_f1
from utils.network import get_resolved_ip


# ── Воркеры ──────────────────────────────────────────────────────────────────

async def _resolve_worker(domain_raw: str, semaphore: asyncio.Semaphore, stub_ips: set) -> dict:
    """
    Фаза 0: DNS-резолв (IPv4).
    dns_fake: False = чисто, True = заглушка, None = DNS FAIL.

    Замечание по stub_ips: stub_ips собирается через прямой UDP к публичным серверам.
    Если провайдер подменяет только системный резолвер (DoH/DoT на уровне ОС),
    а прямой UDP честный — stub_ips будет пустой и подмена здесь не обнаружится.
    Для полной картины смотри результаты DNS-теста (тест 1).
    """
    domain = clean_hostname(domain_raw)

    async with semaphore:
        resolved_ipv4 = await get_resolved_ip(domain, family=socket.AF_INET)

    entry = {
        "domain":       domain,
        "resolved_ipv4": resolved_ipv4,
        "dns_fake":     False,
        "ip_blocked":   False,
        "t13v4_res":    ("[dim]—[/dim]", "", 0.0),
        "t12_res":      ("[dim]—[/dim]", "", 0.0),
        "http_res":     ("[dim]—[/dim]", ""),
    }

    if resolved_ipv4 is None:
        fail = "[yellow]DNS FAIL[/yellow]"
        entry["t13v4_res"] = (fail, "Домен не найден", 0.0)
        entry["t12_res"]   = (fail, "Домен не найден", 0.0)
        entry["http_res"]  = (fail, "Домен не найден")
        entry["dns_fake"]  = None
        return entry

    if stub_ips and resolved_ipv4 in stub_ips:
        fake = "[bold red]DNS FAKE[/bold red]"
        detail = f"DNS подмена -> {resolved_ipv4}"
        entry["t13v4_res"] = (fake, detail, 0.0)
        entry["t12_res"]   = (fake, detail, 0.0)
        entry["http_res"]  = (fake, detail)
        entry["dns_fake"]  = True
        return entry

    # TCP pre-check: быстрая проверка доступности IP по порту 443
    # Пропускаем если настроен прокси — трафик пойдёт через него, прямой TCP не показателен
    if not getattr(config, "PROXY_URL", None):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(resolved_ipv4, 443),
                timeout=3.0
            )
            writer.close()
            await writer.wait_closed()
        except Exception:
            blocked = "[bold red]IP BLOCKED[/bold red]"
            detail = f"TCP connect к {resolved_ipv4}:443 недоступен"
            entry["t13v4_res"] = (blocked, detail, 0.0)
            entry["t12_res"]   = (blocked, detail, 0.0)
            entry["http_res"]  = (blocked, detail)
            entry["ip_blocked"] = True
            return entry

    return entry


async def _tls_worker(
    entry: dict,
    client: httpx.AsyncClient,
    tls_key: str,
    semaphore: asyncio.Semaphore,
    stub_ips: set = None,
) -> None:
    """Фаза TLS: пишет результат в entry in-place."""
    if entry["dns_fake"] is not False or entry.get("ip_blocked"):
        return
    try:
        result = await check_domain_tls(
            entry["domain"], client, semaphore,
            stub_ips=stub_ips, resolved_ip=entry.get("resolved_ipv4")
        )
    except Exception:
        result = ("[dim]ERR[/dim]", "Unknown error", 0.0)
    entry[tls_key] = result


async def _http_worker(
    entry: dict,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    stub_ips: set = None,
) -> None:
    """Фаза HTTP: пишет результат в entry in-place."""
    if entry["dns_fake"] is not False or entry.get("ip_blocked"):
        return
    async with semaphore:
        try:
            result = await check_http_injection(entry["domain"], client, semaphore, stub_ips=stub_ips)
        except Exception:
            result = ("[dim]ERR[/dim]", "Unknown error")
    entry["http_res"] = result


async def _tcp16_worker(item: dict, semaphore: asyncio.Semaphore) -> list:
    ip   = item["ip"]
    port = int(item.get("port", 443))
    sni  = None if port == 80 else (item.get("sni") or config.FAT_DEFAULT_SNI)

    alive_str, status, detail = await check_tcp_16_20(ip, port, sni, semaphore)

    asn_raw = str(item.get("asn", "")).strip()
    asn_str = (
        f"AS{asn_raw}"
        if asn_raw and not asn_raw.upper().startswith("AS")
        else asn_raw.upper()
    ) or "-"

    return [item["id"], asn_str, item["provider"], alive_str, status, detail]


# ── Хелпер прогресс-бара ─────────────────────────────────────────────────────

async def _run_with_progress(tasks: list, description: str) -> list:
    results = []
    total = len(tasks)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_id = progress.add_task(description, total=total)
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            done = len(results)
            progress.update(task_id, completed=done, description=f"{description} ({done}/{total})...")
    return results


async def _run_phase_with_progress(tasks: list, description: str) -> None:
    total = len(tasks)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_id = progress.add_task(description, total=total)
        completed = 0
        for future in asyncio.as_completed(tasks):
            await future
            completed += 1
            progress.update(task_id, completed=completed, description=f"{description} ({completed}/{total})...")


# ── Тест 2: домены ────────────────────────────────────────────────────────────

async def run_domains_test(semaphore: asyncio.Semaphore, stub_ips: set, domains: list) -> dict:
    """Тест 2: TLS1.3 IPv4 → TLS1.2 → HTTP injection."""
    console.print(
        f"\n[bold]Проверка доступности доменов[/bold]  "
        f"[dim]Целей: {len(domains)} | timeout: {config.CONNECT_TIMEOUT}s[/dim]\n"
    )

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("Домен",   style="cyan", no_wrap=True, width=18)
    table.add_column("HTTP",    justify="center")
    table.add_column("TLS1.2",  justify="center")
    table.add_column("TLS1.3",  justify="center")
    table.add_column("Детали",  style="dim", no_wrap=True)

    # Фаза 0: DNS-резолв
    entries = await _run_with_progress(
        [_resolve_worker(d, semaphore, stub_ips) for d in domains],
        "Фаза 0/3: DNS + TCP pre-check..."
    )

    client_t13 = create_dpi_client("TLSv1.3")
    client_t12 = create_dpi_client("TLSv1.2")
    client_http = create_dpi_client()

    try:
        await _run_phase_with_progress(
            [_tls_worker(e, client_t13, "t13v4_res", semaphore, stub_ips) for e in entries],
            "Фаза 1/3: TLS 1.3..."
        )
        await _run_phase_with_progress(
            [_tls_worker(e, client_t12, "t12_res", semaphore, stub_ips) for e in entries],
            "Фаза 2/3: TLS 1.2..."
        )
        await _run_phase_with_progress(
            [_http_worker(e, client_http, semaphore, stub_ips) for e in entries],
            "Фаза 3/3: HTTP..."
        )
    finally:
        await client_t13.aclose()
        await client_t12.aclose()
        await client_http.aclose()

    rows = sorted([build_domain_row(e) for e in entries], key=lambda x: x[0])

    dns_fail_count = 0
    resolved_ips_counter: dict = {}
    for r in rows:
        resolved_ip = r[5] if len(r) > 5 else None
        if resolved_ip and stub_ips and resolved_ip in stub_ips:
            resolved_ips_counter[resolved_ip] = resolved_ips_counter.get(resolved_ip, 0) + 1
        if any("DNS FAIL" in r[col] for col in (1, 2, 3)):
            dns_fail_count += 1

    for r in rows:
        table.add_row(*r[:5])
    console.print(table)

    confirmed_stubs = {ip: c for ip, c in resolved_ips_counter.items() if stub_ips and ip in stub_ips}
    if confirmed_stubs or dns_fail_count > 0:
        console.print(f"\n[bold yellow][i][!] НА ВАШЕМ УСТРОЙСТВЕ/РОУТЕРЕ НЕ НАСТРОЕН DoH:[/bold yellow]")
        if confirmed_stubs:
            ips_text = [f"[red]{ip}[/red] у {c} доменов" for ip, c in confirmed_stubs.items()]
            console.print(f"DNS вернул IP заглушки: {', '.join(ips_text)}")
        if dns_fail_count > 0:
            console.print(f"У {dns_fail_count} сайтов обнаружен DNS FAIL (Домен не найден)")
        console.print("[yellow]Рекомендация: Настройте DoH на вашем устройстве и роутере[/yellow]\n")
        console.print("После настройки сбросьте кеш DNS:")
        console.print("Windows: [dim]ipconfig /flushdns[/dim]")
        console.print("MacOS: [dim]sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder[/dim]")
        console.print("Linux: [dim]sudo resolvectl flush-caches[/dim]\n")

    block_markers = ("TLS DPI", "TLS MITM", "TLS BLOCK", "ISP PAGE", "BLOCKED", "TCP RST", "TCP ABORT")
    return {
        "total":    len(domains),
        "ok":       sum(1 for r in rows if "OK" in r[3] or "OK" in r[2]),
        "blocked":  sum(1 for r in rows if any(m in r[c] for c in (1,2,3) for m in block_markers)),
        "timeout":  sum(1 for r in rows if "TIMEOUT" in r[3] or "TIMEOUT" in r[2]),
        "dns_fail": sum(1 for r in rows if "DNS FAIL" in r[3]),
    }


# ── Тест 3: TCP 16-20KB ───────────────────────────────────────────────────────

async def run_tcp_test(semaphore: asyncio.Semaphore, tcp_items: list) -> dict:
    """Тест 3: FAT-header TCP блокировка."""
    console.print(
        f"\n[bold]Проверка TCP 16-20KB блокировки[/bold]  "
        f"[dim]Целей: {len(tcp_items)} | timeout: {config.FAT_CONNECT_TIMEOUT}s[/dim]"
    )

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("ID",        style="white")
    table.add_column("ASN",       style="yellow")
    table.add_column("Провайдер", style="cyan")
    table.add_column("Alive",     justify="center")
    table.add_column("Статус",    justify="center")
    table.add_column("Детали",    style="dim")

    tcp_results = await _run_with_progress(
        [_tcp16_worker(item, semaphore) for item in tcp_items],
        "Проверка..."
    )

    def _provider_group(provider_str: str) -> str:
        clean = re.sub(r'[^\w\s\.-]', '', provider_str).strip()
        parts = clean.split()
        return parts[0] if parts else clean

    provider_counts: dict = {}
    for row in tcp_results:
        group = _provider_group(row[2])
        provider_counts[group] = provider_counts.get(group, 0) + 1

    def _sort_key(row):
        group = _provider_group(row[2])
        try:
            id_num = int(row[0].split('-')[-1])
        except (ValueError, IndexError):
            id_num = 99999
        return (-provider_counts.get(group, 0), group, id_num)

    tcp_results.sort(key=_sort_key)

    passed  = sum(1 for r in tcp_results if "OK"       in r[4])
    blocked = sum(1 for r in tcp_results if "DETECTED" in r[4])
    mixed   = sum(1 for r in tcp_results if "MIXED"    in r[4])

    for r in tcp_results:
        table.add_row(*r[:6])
    console.print(table)

    if mixed > 0:
        console.print("[dim]Смешанные результаты указывают на балансировку DPI у провайдера[/dim]")

    return {"total": len(tcp_items), "ok": passed, "blocked": blocked, "mixed": mixed}

# ── Тест 4: Поиск белых SNI для ASN ──────────────────────────────────────────

_SNI_BATCH_SIZE = 5
_SNI_TOP_N = 3


async def run_whitelist_sni_test(semaphore: asyncio.Semaphore, tcp_items: list, whitelist_sni: list) -> None:
    """Тест 4: Поиск белых SNI для ASN.

    Алгоритм:
      1. Берём все IP с портом 443.
      2. Базовая проверка — находим DETECTED IP для каждой AS.
         Если у AS несколько IP — берём DETECTED с наименьшим RTT.
      3. Для каждой DETECTED AS перебираем SNI батчами по _SNI_BATCH_SIZE:
         - батч запускается весь параллельно,
         - ждём завершения всех задач батча,
         - из тех, что вернули OK, берём первый по порядку в файле.
      4. Прогресс показывается одной перезаписываемой строкой (через \\r).
         Результат каждой AS печатается отдельной строкой сразу по завершению.
    """
    port443_items = [item for item in tcp_items if int(item.get("port", 443)) == 443]

    if not port443_items:
        console.print("[yellow]Нет целей с портом 443 для теста белых SNI.[/yellow]")
        return

    # Строим индекс SNI -> номер в файле (1-based)
    sni_index: dict = {}
    clean_sni_list = []
    num = 0
    for line in whitelist_sni:
        s = line.strip()
        if s and not s.startswith('#'):
            num += 1
            sni_index[s] = num
            clean_sni_list.append(s)

    from collections import defaultdict
    asn_to_items: dict = defaultdict(list)
    for item in port443_items:
        asn_raw = str(item.get("asn", "")).strip()
        asn_key = asn_raw.upper().lstrip("AS") if asn_raw else item["ip"]
        asn_to_items[asn_key].append(item)

    console.print(
        f"\n[bold]Поиск белых SNI для ASN[/bold]  "
        f"[dim]AS: {len(asn_to_items)} | IP: {len(port443_items)}"
        f" | SNI: {len(clean_sni_list)} | батч: {_SNI_BATCH_SIZE}[/dim]"
    )

    # ── Фаза 1: базовая проверка всех IP ─────────────────────────────────────
    async def _base_worker(item: dict) -> dict:
        ip      = item["ip"]
        sni     = item.get("sni") or config.FAT_DEFAULT_SNI
        asn_raw = str(item.get("asn", "")).strip()
        asn_str = (
            f"AS{asn_raw}"
            if asn_raw and not asn_raw.upper().startswith("AS")
            else asn_raw.upper()
        ) or "-"
        asn_key = asn_raw.upper().lstrip("AS") if asn_raw else ip
        alive_str, status, detail, rtt = await check_tcp_16_20_with_rtt(ip, 443, sni, semaphore)
        return {
            "item":     item,
            "id":       item.get("id", ip),
            "asn_str":  asn_str,
            "asn_key":  asn_key,
            "provider": item["provider"],
            "alive":    alive_str,
            "status":   status,
            "detail":   detail,
            "rtt":      rtt,
        }

    base_rows = await _run_with_progress(
        [_base_worker(item) for item in port443_items],
        "Фаза 1/2: Базовая проверка...",
    )

    # Для каждой AS выбираем DETECTED IP с наименьшим RTT
    asn_candidate: dict = {}
    for row in base_rows:
        if "DETECTED" not in row["status"]:
            continue
        ak = row["asn_key"]
        if ak not in asn_candidate:
            asn_candidate[ak] = row
        else:
            prev_rtt = asn_candidate[ak]["rtt"] or 9999
            curr_rtt = row["rtt"] or 9999
            if curr_rtt < prev_rtt:
                asn_candidate[ak] = row

    detected_rows = list(asn_candidate.values())

    if not detected_rows:
        console.print("[green]Ни одна AS не заблокирована — перебор SNI не нужен.[/green]")
        return


    total_sni  = len(clean_sni_list)
    print_lock = asyncio.Lock()

    console.print(
        f"[dim]Фаза 2/2: Параллельный перебор SNI для {len(detected_rows)} AS "
        f"(батч {_SNI_BATCH_SIZE}, топ-{_SNI_TOP_N})...[/dim]\n"
    )

    # ── Воркер одной AS ──────────────────────────────────────────────────────
    async def _probe_as(row: dict) -> bool:
        """Перебирает SNI для одной AS параллельно. Возвращает True если найден хоть один."""
        ip       = row["item"]["ip"]
        asn_str  = row["asn_str"]
        provider = row["provider"]
        hint     = row["rtt"]

        found: list      = []   # (label, num)
        ban_detected     = False
        ban_detail       = ""

        # Шаг 0: без SNI
        try:
            _a, st0, d0 = await check_tcp_16_20(ip, 443, "", semaphore, hint_rtt=hint)
            if "OK" in st0:
                found.append(("(без SNI)", 0))
            elif "DETECTED" not in st0 and "at " not in d0:
                ban_detected = True
                ban_detail   = st0
        except Exception:
            pass

        if len(found) < _SNI_TOP_N and not ban_detected:
            batches = [
                clean_sni_list[i:i + _SNI_BATCH_SIZE]
                for i in range(0, total_sni, _SNI_BATCH_SIZE)
            ]

            for batch in batches:
                if len(found) >= _SNI_TOP_N:
                    break

                async def _one(sni: str):
                    _a, s, d = await check_tcp_16_20(ip, 443, sni, semaphore, hint_rtt=hint)
                    return sni, s, d

                results = await asyncio.gather(
                    *[_one(sni) for sni in batch],
                    return_exceptions=True
                )

                # Если весь батч — connect-level (нет "at Xkb" и не DETECTED) — бан
                connect_fails = sum(
                    1 for res in results
                    if not isinstance(res, tuple)
                    or ("OK" not in res[1] and "DETECTED" not in res[1] and "at " not in res[2])
                )
                if connect_fails == len(batch):
                    ban_detected = True
                    for res in results:
                        if isinstance(res, tuple):
                            ban_detail = res[1]
                            break
                    break

                # Собираем OK в порядке файла
                for sni in batch:
                    if len(found) >= _SNI_TOP_N:
                        break
                    for res in results:
                        if isinstance(res, tuple) and res[0] == sni and "OK" in res[1]:
                            found.append((sni, sni_index.get(sni, 0)))
                            break

        async with print_lock:
            if found:
                parts = []
                for label, n in found:
                    safe  = label.replace(".", "\u200b.")
                    n_str = f" [dim]#{n}[/dim]" if n else ""
                    parts.append(f"[bold green]{safe}[/bold green]{n_str}")
                suffix = "  [dim yellow]⚠ бан после[/dim yellow]" if ban_detected else ""
                console.print(
                    f"  [cyan]{provider}[/cyan] [dim]{asn_str}[/dim]  "
                    f"[green]✓[/green] {'  '.join(parts)}{suffix}"
                )
            elif ban_detected:
                import re as _re
                clean_st = _re.sub(r'\[.*?\]', '', ban_detail).strip()
                console.print(
                    f"  [cyan]{provider}[/cyan] [dim]{asn_str}[/dim]  "
                    f"[yellow]⚠ бан/рейт-лимит[/yellow] [dim]({clean_st})[/dim]"
                )
            else:
                console.print(
                    f"  [cyan]{provider}[/cyan] [dim]{asn_str}[/dim]  "
                    f"[red]✗ SNI не найден[/red] [dim](все заблокированы)[/dim]"
                )

        return bool(found)

    # ── Запускаем все AS параллельно ─────────────────────────────────────────
    probe_results = await asyncio.gather(
        *[_probe_as(row) for row in sorted(detected_rows, key=lambda r: r["provider"].lower())],
        return_exceptions=True
    )

    found_count = sum(1 for r in probe_results if r is True)

    console.print()
    if found_count > 0:
        console.print(
            f"[green]Найдено белых SNI: у {found_count} из {len(detected_rows)} заблокированных AS[/green]"
        )
    else:
        console.print(
            f"[yellow]Белые SNI не найдены ни для одной из {len(detected_rows)} заблокированных AS[/yellow]"
        )

# ── Тест 5: Telegram ──────────────────────────────────────────────────────────

async def run_telegram_test(semaphore: asyncio.Semaphore) -> dict:
    from core.telegram_scanner import run_telegram_test as _run_scanner
    return await _run_scanner(semaphore)


# ── Тест 7: TCP Latency ──────────────────────────────────────────────────────

async def run_latency_test(semaphore: asyncio.Semaphore) -> dict:
    """Тест 7: TCP Latency — серия tcping-проб для измерения качества соединения."""
    targets = getattr(config, "LATENCY_TARGETS", [])
    if not targets:
        console.print("[yellow]LATENCY_TARGETS не задан в config.yml — тест 7 пропущен.[/yellow]")
        return {"total": 0, "ok": 0, "warn": 0, "bad": 0}

    probe_count = getattr(config, "LATENCY_PROBE_COUNT", 20)
    probe_timeout = getattr(config, "LATENCY_PROBE_TIMEOUT", 5.0)
    probe_interval = getattr(config, "LATENCY_PROBE_INTERVAL", 0.5)

    console.print(
        f"\n[bold]TCP Latency тест[/bold]  "
        f"[dim]Целей: {len(targets)} | проб: {probe_count} | "
        f"timeout: {probe_timeout}s | интервал: {probe_interval}s[/dim]\n"
    )

    async def _latency_worker(target: list) -> dict:
        ip = target[0]
        port = int(target[1])
        label = target[2] if len(target) > 2 else f"{ip}:{port}"
        result = await probe_target(
            ip, port,
            count=probe_count,
            timeout=probe_timeout,
            interval=probe_interval,
            semaphore=semaphore,
        )
        result["label"] = label
        return result

    results = await _run_with_progress(
        [_latency_worker(t) for t in targets],
        "Пробирование..."
    )

    # Таблица результатов
    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("Цель",       style="cyan", no_wrap=True)
    table.add_column("IP:порт",    style="dim", no_wrap=True)
    table.add_column("Качество",   justify="center")
    table.add_column("Потери",     justify="center")
    table.add_column("P50",        justify="right")
    table.add_column("P95",        justify="right")
    table.add_column("Max",        justify="right")
    table.add_column("Джиттер",    justify="right")
    table.add_column("Диагноз",    style="dim", no_wrap=True)

    ok_count = warn_count = bad_count = 0

    for r in results:
        loss_str = f"{r['loss_pct']:.0f}%" if r['loss_pct'] > 0 else "[green]0%[/green]"
        if r['loss_pct'] >= 5:
            loss_str = f"[red]{r['loss_pct']:.0f}%[/red]"
        elif r['loss_pct'] > 0:
            loss_str = f"[yellow]{r['loss_pct']:.1f}%[/yellow]"

        p50_str = f"{r['p50']:.0f}ms" if r['p50'] is not None else "—"
        p95_str = f"{r['p95']:.0f}ms" if r['p95'] is not None else "—"
        max_str = f"{r['max']:.0f}ms" if r['max'] is not None else "—"
        jitter_str = f"{r['jitter']:.0f}ms" if r['jitter'] is not None else "—"

        # Color latency values
        if r['p50'] is not None:
            if r['p50'] > 500:
                p50_str = f"[red]{p50_str}[/red]"
            elif r['p50'] > 200:
                p50_str = f"[yellow]{p50_str}[/yellow]"
            else:
                p50_str = f"[green]{p50_str}[/green]"

        if r['p95'] is not None:
            if r['p95'] > 1000:
                p95_str = f"[red]{p95_str}[/red]"
            elif r['p95'] > 500:
                p95_str = f"[yellow]{p95_str}[/yellow]"

        if r['max'] is not None:
            if r['max'] > 2000:
                max_str = f"[red]{max_str}[/red]"
            elif r['max'] > 1000:
                max_str = f"[yellow]{max_str}[/yellow]"

        table.add_row(
            r["label"],
            f"{r['ip']}:{r['port']}",
            r["quality_label"],
            loss_str,
            p50_str,
            p95_str,
            max_str,
            jitter_str,
            r["diagnosis"],
        )

        if "ПЛОХО" in r["quality_label"]:
            bad_count += 1
        elif "ПРОБЛЕМЫ" in r["quality_label"]:
            warn_count += 1
        else:
            ok_count += 1

    console.print(table)

    # Диагностика
    if bad_count > 0 or warn_count > 0:
        console.print()
        if bad_count > 0:
            console.print("[bold red][!] Обнаружены серьёзные проблемы с качеством соединения[/bold red]")
            console.print("[dim]Возможные причины: DPI throttling, плохой роутинг, перегрузка хостера[/dim]")
        if warn_count > 0:
            console.print("[bold yellow][!] Некоторые цели имеют нестабильное соединение[/bold yellow]")
            console.print("[dim]Проверьте: не меняется ли качество в разное время суток[/dim]")

    return {"total": len(results), "ok": ok_count, "warn": warn_count, "bad": bad_count}