#!/usr/bin/env python3
"""
CF 优选IP 扫描管理台 (Web 图形界面)

以 SQLite 数据库为后端的常驻扫描管理台:
  * 后台持续扫描(多端口+TLS确认+优质邻域加权+冷却复测+地区补全)
  * 实时看板: 已测/存活/已验证/带宽/平均延迟 + 机房与延迟分布图表
  * 可排序/筛选的结果表, 一键导出 ADD.txt / CSV
  * 扫描参数可随时调整并重启

运行: python3 cf_web.py [--db cf_ips.db] [--host 127.0.0.1] [--port 8787]
  --no-browser 不自动打开浏览器

端点:
  GET  /                管理台页面
  POST /api/control     控制扫描  {action:start|stop, ...参数}
  GET  /api/status      扫描器状态
  GET  /api/stats       数据库统计 + 图表数据
  GET  /api/table       结果表数据 (?sort=&region=&minbw=&maxlat=&verified=&q=&port=&limit=)
  GET  /api/export      导出 (?fmt=txt|csv&...)
"""
import argparse
import asyncio
import json
import os
import queue
import re
import socket
import sqlite3
import sys
import threading
import time
import types
import webbrowser
from collections import OrderedDict, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import cf_db
import route_probe

COV_TOTAL = sum(1 << (32 - int(r.split("/")[1])) for r in cf_db.FALLBACK_RANGES)
VERSION = "1.3.0"

COLO_COUNTRY = {
    "LAX": "美国", "SJC": "美国", "SEA": "美国", "PDX": "美国",
    "DEN": "美国", "ORD": "美国", "DFW": "美国", "IAD": "美国",
    "ATL": "美国", "MIA": "美国", "JFK": "美国", "EWR": "美国",
    "PHX": "美国", "SFO": "美国", "YYZ": "加拿大", "YVR": "加拿大",
    "HKG": "中国香港", "TPE": "中国台湾", "NRT": "日本", "KIX": "日本",
    "SEL": "韩国", "SIN": "新加坡", "BKK": "泰国", "KUL": "马来西亚",
    "SGN": "越南", "HAN": "越南", "MNL": "菲律宾", "CGK": "印尼",
    "LHR": "英国", "FRA": "德国", "MUC": "德国", "AMS": "荷兰",
    "PAR": "法国", "MAD": "西班牙", "MXP": "意大利", "WAW": "波兰",
    "ARN": "瑞典", "HEL": "芬兰", "OSL": "挪威", "CPH": "丹麦",
    "ZRH": "瑞士", "VIE": "奥地利", "PRG": "捷克", "BUD": "匈牙利",
    "SOF": "保加利亚", "ATH": "希腊", "IST": "土耳其", "DXB": "阿联酋",
    "MCT": "阿曼", "TLV": "以色列", "JNB": "南非", "CPT": "南非",
    "LOS": "尼日利亚", "GIG": "巴西", "GRU": "巴西", "EZE": "阿根廷",
    "LIM": "秘鲁", "BOG": "哥伦比亚", "MEX": "墨西哥", "SYD": "澳大利亚",
    "MEL": "澳大利亚", "PER": "澳大利亚", "AKL": "新西兰",
    "BOM": "印度", "BLR": "印度", "DEL": "印度", "MAA": "印度", "HYD": "印度",
    "KBP": "乌克兰", "FCO": "意大利", "MIL": "意大利", "BCN": "西班牙",
    "KWI": "科威特", "RUH": "沙特", "JED": "沙特", "DOH": "卡塔尔",
    "BEY": "黎巴嫩", "AMM": "约旦", "GDL": "墨西哥", "SCL": "智利",
    "PTY": "巴拿马", "CCS": "委内瑞拉", "KGL": "卢旺达", "NBO": "肯尼亚",
    "MBA": "肯尼亚", "CPT": "南非",
}

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cf_settings.json")
SETTINGS_KEYS = ["operator", "ports", "count", "concurrency", "verify", "bench",
                 "bench_parallel", "backfill", "recheck", "exploit", "max_latency", "tls_check",
                 "bench_host", "route_check", "route_budget", "route_stale_hours", "ipv6"]


def load_settings():
    try:
        with open(SETTINGS_FILE) as fh:
            d = json.load(fh)
        return {k: d[k] for k in SETTINGS_KEYS if k in d}
    except Exception:
        return {}


def save_settings(d):
    cur = load_settings()
    for k in SETTINGS_KEYS:
        if k in d:
            cur[k] = d[k]
    with open(SETTINGS_FILE, "w") as fh:
        json.dump(cur, fh, ensure_ascii=False, indent=2)
    return cur


def country(colo):
    return COLO_COUNTRY.get((colo or "").upper(), colo or "UNK")

STATE = {
    "lock": threading.Lock(),
    "running": False,
    "stop": threading.Event(),
    "round": 0,
    "last_ok": 0,
    "started_at": None,
    "last_cycle": None,
    "label": "官方地址池",
    "msg": "待命",
    "db": None,
    "stage": "idle",
    "probed": 0,
    "total": 0,
    "ok_now": 0,
    "log": [],
}


def set_state(**kw):
    with STATE["lock"]:
        for k, v in kw.items():
            STATE[k] = v


def get_state():
    with STATE["lock"]:
        d = dict(STATE)
        d.pop("lock", None)
        d.pop("stop", None)
        return d


def log_event(msg):
    with STATE["lock"]:
        STATE["log"].append((time.time(), str(msg)))
        if len(STATE["log"]) > 150:
            del STATE["log"][:-150]


def db_conn(path, ro=False):
    if ro:
        return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    return sqlite3.connect(path, timeout=10)


def q_rows(path, sql, params=()):
    try:
        conn = db_conn(path, ro=True)
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def q_one(path, sql, params=()):
    try:
        conn = db_conn(path, ro=True)
        row = conn.execute(sql, params).fetchone()
        conn.close()
        return row
    except Exception:
        return None


def build_where(q):
    where = ["ok_count > 0", "latency_ms IS NOT NULL"]
    params = []
    if q.get("verified", [""])[0] in ("1", "true"):
        where.append("colo IS NOT NULL AND loc IS NOT NULL")
    minbw = q.get("minbw", [""])[0]
    if minbw:
        try:
            where.append("bw_last_mbps >= ?")
            params.append(float(minbw))
        except ValueError:
            pass
    if q.get("hasbw", [""])[0] in ("1", "true"):
        where.append("bw_last_mbps IS NOT NULL AND bw_last_mbps>0")
    maxlat = q.get("maxlat", [""])[0]
    if maxlat:
        try:
            where.append("latency_ms <= ?")
            params.append(float(maxlat))
        except ValueError:
            pass
    region = (q.get("region", [""])[0] or "").strip()
    if region:
        keep = [r.strip().upper() for r in region.split(",") if r.strip()]
        if keep:
            ph = ",".join("?" for _ in keep)
            where.append(f"(colo IN ({ph}) OR loc IN ({ph}))")
            params.extend(keep)
            params.extend(keep)
    port = q.get("port", [""])[0]
    if port and port.isdigit():
        where.append("port = ?")
        params.append(int(port))
    rq = (q.get("route", [""])[0] or "").strip()
    if rq:
        keep = [r.strip() for r in rq.split(",") if r.strip()]
        if keep:
            ph = ",".join("?" for _ in keep)
            where.append(f"route_class IN ({ph})")
            params.extend(keep)
    ipq = (q.get("q", [""])[0] or "").strip()
    if ipq:
        where.append("ip LIKE ?")
        params.append(f"%{ipq}%")
    if q.get("v6", [""])[0] in ("1", "true"):
        where.append("instr(ip, ':') > 0")
    if q.get("v4", [""])[0] in ("1", "true"):
        where.append("instr(ip, ':') = 0")
    return " AND ".join(where), params


def build_order(q):
    sort = q.get("sort", [""])[0]
    if sort == "lat":
        return "latency_ms ASC"
    if sort == "colo":
        return "colo ASC, latency_ms ASC"
    if sort == "loc":
        return "loc ASC, latency_ms ASC"
    if sort == "port":
        return "port ASC, latency_ms ASC"
    if sort == "time":
        return "tested_at DESC"
    # route_class 仅作筛选标签, 不参与排序权重 (红线4)
    return "(CASE WHEN bw_last_mbps IS NULL THEN -1 ELSE bw_last_mbps END) DESC, latency_ms ASC"


def api_stats(db):
    now = time.time()
    total = q_one(db, "SELECT COUNT(*) FROM ips")
    total = total[0] if total else 0
    alive = q_one(db, "SELECT COUNT(*) FROM ips WHERE ok_count>0")
    alive = alive[0] if alive else 0
    verified = q_one(db, "SELECT COUNT(*) FROM ips WHERE verified_at IS NOT NULL")
    verified = verified[0] if verified else 0
    withbw = q_one(db, "SELECT COUNT(*) FROM ips WHERE bandwidth_mbps IS NOT NULL AND bandwidth_mbps>0")
    withbw = withbw[0] if withbw else 0
    avglat = q_one(db, "SELECT ROUND(AVG(latency_ms),1) FROM ips WHERE ok_count>0")
    avglat = avglat[0] if avglat else None
    maxbw = q_one(db, "SELECT ROUND(MAX(bw_last_mbps),1) FROM ips WHERE bw_last_mbps IS NOT NULL")
    maxbw = maxbw[0] if maxbw else None
    bwbest = q_one(db, "SELECT ROUND(MAX(bandwidth_mbps),1) FROM ips WHERE bandwidth_mbps IS NOT NULL")
    bwbest = bwbest[0] if bwbest else None
    minlat = q_one(db, "SELECT ROUND(MIN(latency_ms),1) FROM ips WHERE ok_count>0")
    minlat = minlat[0] if minlat else None

    colos = q_rows(db, "SELECT colo, COUNT(*) FROM ips WHERE ok_count>0 AND colo IS NOT NULL "
                       "GROUP BY colo ORDER BY COUNT(*) DESC LIMIT 12")
    locs = q_rows(db, "SELECT loc, COUNT(*) FROM ips WHERE ok_count>0 AND loc IS NOT NULL "
                      "GROUP BY loc ORDER BY COUNT(*) DESC LIMIT 10")
    ports = q_rows(db, "SELECT port, COUNT(*) FROM ips WHERE ok_count>0 GROUP BY port "
                       "ORDER BY COUNT(*) DESC LIMIT 8")
    route_rows = q_rows(db, "SELECT route_class, COUNT(*) FROM ips WHERE route_class IS NOT NULL "
                            "GROUP BY route_class ORDER BY COUNT(*) DESC LIMIT 12")
    route_done = q_one(db, "SELECT COUNT(*) FROM ips WHERE route_class IS NOT NULL")
    route_done = route_done[0] if route_done else 0
    premium = q_one(db, "SELECT COUNT(*) FROM ips WHERE route_class='premium'")
    premium = premium[0] if premium else 0

    lat_buckets = [0] * 8
    lat_labels = ["<50", "50-100", "100-200", "200-300", "300-500", "500-800", "800-1500", ">1500"]
    for (lat,) in q_rows(db, "SELECT latency_ms FROM ips WHERE ok_count>0 AND latency_ms IS NOT NULL"):
        if lat < 50:
            lat_buckets[0] += 1
        elif lat < 100:
            lat_buckets[1] += 1
        elif lat < 200:
            lat_buckets[2] += 1
        elif lat < 300:
            lat_buckets[3] += 1
        elif lat < 500:
            lat_buckets[4] += 1
        elif lat < 800:
            lat_buckets[5] += 1
        elif lat < 1500:
            lat_buckets[6] += 1
        else:
            lat_buckets[7] += 1

    bw_buckets = [0] * 6
    bw_labels = ["0-50", "50-100", "100-200", "200-400", "400-800", ">800"]
    for (bw,) in q_rows(db, "SELECT bw_last_mbps FROM ips WHERE bw_last_mbps IS NOT NULL AND bw_last_mbps>0"):
        if bw < 50:
            bw_buckets[0] += 1
        elif bw < 100:
            bw_buckets[1] += 1
        elif bw < 200:
            bw_buckets[2] += 1
        elif bw < 400:
            bw_buckets[3] += 1
        elif bw < 800:
            bw_buckets[4] += 1
        else:
            bw_buckets[5] += 1

    from collections import defaultdict
    c_agg = defaultdict(int)
    for c, n in colos:
        c_agg[country(c or "UNK")] += n
    countries = sorted([{"name": k, "count": v} for k, v in c_agg.items()],
                       key=lambda x: x["count"], reverse=True)[:12]
    return {
        "total": total, "alive": alive, "verified": verified, "withbw": withbw,
        "avglat": avglat, "maxbw": maxbw, "bwbest": bwbest, "minlat": minlat,
        "coverage": round(total / COV_TOTAL * 100, 3) if COV_TOTAL else 0,
        "route_done": route_done, "premium": premium,
        "routes": [{"name": route_probe.get_class_label(r) if r else "未知",
                    "class": r, "count": n, "premium": 1 if r == "premium" else 0}
                   for r, n in route_rows],
        "colos": [{"name": c or "UNK", "count": n} for c, n in colos],
        "countries": countries,
        "locs": [{"name": l or "UNK", "count": n} for l, n in locs],
        "ports": [{"name": str(p), "count": n} for p, n in ports],
        "lat": {"labels": lat_labels, "data": lat_buckets},
        "bw": {"labels": bw_labels, "data": bw_buckets},
        "now": now,
    }


def api_table(db, q):
    where, params = build_where(q)
    order = build_order(q)
    order_params = []
    top_ips = [s.strip() for s in (q.get("top", [""])[0] or "").split(",") if s.strip()]
    if top_ips:
        order = ("(CASE " + " ".join(f"WHEN ip=? THEN {i}" for i in range(len(top_ips))) +
                 " ELSE 10000 END), " + order)
        order_params = list(top_ips)
    try:
        limit = max(1, min(int(q.get("limit", [""])[0] or 100), 500))
    except ValueError:
        limit = 100
    try:
        offset = max(0, int(q.get("offset", [""])[0] or 0))
    except ValueError:
        offset = 0
    total_row = q_one(db, f"SELECT COUNT(*) FROM ips WHERE {where}", params)
    total = total_row[0] if total_row else 0
    sql = (f"SELECT ip, port, colo, loc, latency_ms, bandwidth_mbps, bw_last_mbps, bw_last_at, "
           f"tested_at, ok_count, fail_count, route_as_list, route_class, route_hops "
           f"FROM ips WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?")
    rows = q_rows(db, sql, params + order_params + [limit, offset])
    out = []
    for ip, port, colo, loc, lat, bw, bw_last, bw_last_at, tested, okc, failc, rasl, rclass, rhops in rows:
        out.append({"ip": ip, "port": port, "colo": colo or "UNK",
                    "country": country(colo or "UNK"), "loc": loc or "UNK",
                    "latency": round(lat, 1) if lat is not None else None,
                    "bandwidth": bw_last if bw_last is not None else None,
                    "bw_best": bw if bw is not None else None,
                    "bw_last_at": bw_last_at,
                    "route_class": rclass, "route_as_list": rasl,
                    "route_hops": rhops,
                    "tested": tested, "ok": okc, "fail": failc})
    return {"rows": out, "total": total, "offset": offset, "limit": limit}


def api_copy(db, q):
    ips = [s.strip() for s in re.split(r"[,;\n\r]+", q.get("ips", [""])[0]) if s.strip()]
    if not ips:
        return {"rows": []}
    ph = ",".join("?" * len(ips))
    rows = q_rows(db, f"SELECT ip, port, colo, loc, route_class FROM ips WHERE ip IN ({ph})", ips)
    out = []
    for ip, p, c, l, rclass in rows:
        if c:
            name = country(c)
        elif l:
            name = l
        else:
            name = "未知"
        out.append({"ip": ip, "port": p, "country": name, "route_class": rclass})
    return {"rows": out}


def api_optimize(db, q):
    """手动优选: 从本地库抽候选 -> 现场重测(探测+识别+测速) -> 取最优 N 条。
    prio=bw 优先带宽(bw↓,lat↑) / prio=lat 优先延迟(lat↑,bw↓)。
    重测结果会写入 ips (正常测试记录), 但"优选清单"本身不保存, 仅返回展示。"""
    try:
        n = max(1, min(int(q.get("count", [""])[0] or 10), 200))
    except ValueError:
        n = 10
    prio = ((q.get("prio", [""])[0] or "bw").strip().lower() or "bw")
    where, params = build_where(q)
    cand_order = "latency_ms ASC, (CASE WHEN bw_last_mbps IS NULL THEN -1 ELSE bw_last_mbps END) DESC" if prio == "lat" else build_order(q)
    m = min(max(n * 5, 20), 150)
    cand_rows = q_rows(db, f"SELECT ip, port FROM ips WHERE {where} "
                           f"ORDER BY {cand_order} LIMIT ?", params + [m])
    if not cand_rows:
        return {"rows": [], "live": 0, "cands": 0}
    flat = load_settings()
    flat["count"] = "1"
    flat["bench"] = "1"
    flat["verify"] = str(m)
    flat["ipv6"] = "0"
    for k in ("count", "region", "route", "hasbw", "v6", "sort"):
        v = (q.get(k, [""])[0] or "").strip()
        if v:
            flat[k] = v
    args = scan_args(flat, db)
    loop = asyncio.new_event_loop()
    try:
        live = loop.run_until_complete(_optimize_live(args, cand_rows, db))
    finally:
        loop.close()
    if prio == "lat":
        live.sort(key=lambda x: (x["latency"], -(x["bandwidth"] or 0)))
    top = live[:n]
    out = []
    for r in top:
        ip, port, lat, colo, loc, bw = (r["ip"], r["port"], r["latency"],
                                        r["colo"], r["loc"], r["bandwidth"])
        if colo:
            name = country(colo)
        elif loc:
            name = loc
        else:
            name = "未知"
        out.append({"ip": ip, "port": port, "colo": colo or "UNK", "country": name,
                    "latency": round(lat, 1) if lat is not None else None,
                    "bandwidth": bw})
    if out:
        ph = ",".join("?" for _ in out)
        rcmap = {r[0]: r[1] for r in q_rows(
            db, f"SELECT ip, route_class FROM ips WHERE ip IN ({ph})", [r["ip"] for r in out])}
        for r in out:
            r["route_class"] = rcmap.get(r["ip"])
    return {"rows": out, "live": len(live), "cands": len(cand_rows)}


async def _optimize_live(args, cands, db):
    """现场重测候选: 探测连通 -> 识别地区 -> 实测带宽; 结果写回 ips 并排序返回"""
    sem = asyncio.Semaphore(min(20, len(cands)))

    async def one(item):
        ip, port = item
        async with sem:
            try:
                r = await cf_db.probe_ip(ip, [port], args)
            except Exception:
                return None
            if r is None or r[1] is None:
                return None
            _, p, lat, _ = r
            args_ns = types.SimpleNamespace(
                bench_size=args.bench_size, bench_timeout=args.bench_timeout,
                bench_parallel=args.bench_parallel, bench_host=args.bench_host)
            info = None
            try:
                info = await cf_db.identify(ip, p, args_ns, latency=lat)
            except Exception:
                info = None
            bw = None
            if info:
                try:
                    bw = await cf_db.bench_bandwidth(ip, p, args_ns)
                except Exception:
                    bw = None
            return {"ip": ip, "port": p, "latency": lat,
                    "colo": info["colo"] if info else None,
                    "loc": info["loc"] if info else None, "bandwidth": bw}

    results = await asyncio.gather(*(one(c) for c in cands))
    conn = cf_db.open_db(db)
    for r in results:
        if r is None:
            continue
        rec = {"ip": r["ip"], "port": r["port"], "ok": True, "latency": r["latency"],
               "colo": r["colo"], "loc": r["loc"], "bandwidth": r["bandwidth"],
               "tested_at": time.time(),
               "verified_at": time.time() if r["colo"] else None}
        cf_db.upsert(conn, rec)
    conn.commit()
    conn.close()
    live = [r for r in results if r is not None]
    live.sort(key=lambda x: (-(x["bandwidth"] or 0), x["latency"]))
    return live


def export_body(db, q, fmt):
    where, params = build_where(q)
    sql = (f"SELECT ip, port, colo, loc, latency_ms, bandwidth_mbps, route_class FROM ips "
           f"WHERE {where} ORDER BY {build_order(q)} LIMIT 2000")
    rows = q_rows(db, sql, params)
    if fmt == "csv":
        lines = ["rank,ip,port,latency_ms,bandwidth_mbps,colo,loc,route_class"]
        for i, (ip, p, c, l, lat, bw, rclass) in enumerate(rows, 1):
            lines.append(f"{i},{ip},{p},{lat if lat is not None else ''},{bw if bw is not None else ''},{c or ''},{l or ''},{rclass or ''}")
        return "\n".join(lines) + "\n", "text/csv", "cf_optimizer.csv"
    lines = []
    for i, (ip, p, c, l, lat, bw, rclass) in enumerate(rows, 1):
        lines.append(f"{ip}:{p}#{c or 'UNK'}-{l or 'UNK'}-{i}")
    return "\n".join(lines) + "\n", "text/plain; charset=utf-8", "ADD.txt"


# ---------------------------------------------------------------- scanner
def scan_args(params, db):
    def num(k, d, t=float):
        try:
            return t(params.get(k, d))
        except (ValueError, TypeError):
            return d

    ports = [int(x) for x in str(params.get("ports", "")).split(",") if x.strip().isdigit()]
    if not ports:
        ports = list(cf_db.PORTS_DEFAULT)
    return types.SimpleNamespace(
        db=db,
        operator=(params.get("operator") or None),
        count=max(1, int(num("count", 5000, int))),
        verify=max(0, int(num("verify", 400, int))),
        bench=max(0, int(num("bench", 20, int))),
        backfill=max(0, int(num("backfill", 300, int))),
        recheck=max(0, int(num("recheck", 200, int))),
        concurrency=max(1, int(num("concurrency", 400, int))),
        ping_timeout=max(0.1, num("ping_timeout", 1.2)),
        max_latency=max(1, num("max_latency", 2000)),
        port=int(num("port", 443, int)),
        ports=tuple(ports),
        tls_check=str(params.get("tls_check", "1")) not in ("0", "false", ""),
        exploit=min(1.0, max(0.0, num("exploit", 0.6))),
        cooldown=max(1, num("cooldown", 3600)),
        bench_size=int(max(1_000_000, min(num("bench_size", 30_000_000, int), 80_000_000))),
        bench_timeout=max(1, num("bench_timeout", 10)),
        bench_parallel=max(1, int(num("bench_parallel", 6, int))),
        bench_host=str(params.get("bench_host", "")).strip() or cf_db.SPEED_HOST,
        route_check=str(params.get("route_check", "1")) not in ("0", "false", ""),
        route_budget=max(0, int(num("route_budget", 100, int))),
        route_stale_hours=max(1, num("route_stale_hours", 6)),
        ipv6=str(params.get("ipv6", "0")) not in ("0", "false", ""),
        cycles=0, gap=max(1, num("gap", 5)), once=False, reverify=0,
    )


def scanner_worker(args):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    stop = STATE["stop"]
    q = queue.Queue()
    try:
        conn = cf_db.open_db(args.db)
        known = cf_db.load_known(conn)
        nets, label = cf_db.fetch_networks(args.operator, args.port)
        nets6 = cf_db.fetch_networks_v6(args.operator or "") if args.ipv6 else []
        set_state(label=label, db=os.path.abspath(args.db),
                  msg=f"已启动: {label} | 抽样{args.count} 并发{args.concurrency} | "
                      f"端口{','.join(map(str, args.ports))} | TLS确认{'开' if args.tls_check else '关'} | "
                      f"IPv6{'开' if args.ipv6 else '关'} | "
                      f"线路检测{'开' if args.route_check else '关'}({args.route_budget}/轮)")

        pend_count = 0

        def flush():
            nonlocal pend_count
            if pend_count:
                conn.commit()
                pend_count = 0

        def handle(rec):
            nonlocal pend_count
            t = rec.get("type")
            if t == "result":
                cf_db.upsert(conn, rec)
                pend_count += 1
                if pend_count >= 200:
                    flush()
                with STATE["lock"]:
                    STATE["probed"] = STATE.get("probed", 0) + 1
                    if rec.get("ok"):
                        STATE["ok_now"] = STATE.get("ok_now", 0) + 1
            elif t == "cycle_start":
                set_state(stage="probe", total=rec.get("total", 0), probed=0, ok_now=0)
            elif t == "cycle_end":
                flush()
                rnd = get_state()["round"] + 1
                try:
                    ver = conn.execute("SELECT COUNT(*) FROM ips WHERE verified_at IS NOT NULL").fetchone()[0]
                    bw = conn.execute("SELECT COUNT(*) FROM ips WHERE bandwidth_mbps>0").fetchone()[0]
                except Exception:
                    ver = bw = 0
                log_event(f"第{rnd}轮完成: 达标 {rec.get('ok', 0)} | "
                          f"已验证地区 {ver} | 有带宽 {bw}")
                set_state(round=rnd, last_ok=rec.get("ok", 0),
                          last_cycle=time.time(), stage="idle", total=0, probed=0, ok_now=0)
            elif t == "error":
                flush()
                log_event(f"错误: {rec.get('msg')}")
                set_state(msg=f"错误: {rec.get('msg')}")

        async def drive():
            task = asyncio.create_task(cf_db.run_session(nets, known, q, args, stop, nets6=nets6))
            while not task.done():
                try:
                    rec = q.get_nowait()
                    handle(rec)
                except queue.Empty:
                    await asyncio.sleep(0.2)
            await task

        loop.run_until_complete(drive())
    except Exception as e:
        log_event(f"扫描异常: {e}")
        set_state(msg=f"扫描异常: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        try:
            loop.close()
        except Exception:
            pass
        log_event("扫描已停止")
        set_state(running=False, msg="已停止", stage="idle", total=0, probed=0, ok_now=0)
        stop.clear()


def start_scan(params, db):
    st = get_state()
    if st["running"]:
        return {"ok": False, "error": "正在扫描中"}
    args = scan_args(params, db)
    op_name = ({None: "官方全网", "": "官方全网", "cf": "CF官方优选",
                "ct": "电信优选", "cu": "联通优选", "cmcc": "移动优选"}.get(args.operator, args.operator))
    set_state(running=True, stop=threading.Event(), round=0, last_ok=0,
              started_at=time.time(), last_cycle=None, msg="启动中...",
              stage="start", total=0, probed=0, ok_now=0, label=op_name)
    log_event(f"开始扫描: {op_name} | 抽样{args.count} 并发{args.concurrency}"
              f" | 端口{','.join(map(str, args.ports))} | TLS {args.tls_check}")
    threading.Thread(target=scanner_worker, args=(args,), daemon=True).start()
    return {"ok": True}


def stop_scan():
    set_state(msg="正在停止...")
    STATE["stop"].set()
    return {"ok": True}


def test_ip(db, params):
    ip = (params.get("ip") or "").strip()
    act = params.get("action") or "lat"
    try:
        port = int(params.get("port") or 443)
    except ValueError:
        port = 443
    if not ip:
        return {"ok": False, "error": "缺少 ip"}
    if act not in ("lat", "bw", "route"):
        return {"ok": False, "error": "action 只能是 lat/bw/route"}
    log_event(f"手动测试: {ip}:{port} ({'延迟' if act=='lat' else '带宽' if act=='bw' else '线路'})")
    try:
        if act == "lat":
            lat = asyncio.run(cf_db.tls_probe(ip, port, 4.0))
            if lat is None:
                return {"ok": False, "error": "连接失败或超时"}
            upsert_test(db, ip, port, latency=lat)
            return {"ok": True, "latency": round(lat, 1)}
        elif act == "bw":
            ns = types.SimpleNamespace(bench_size=30_000_000, bench_timeout=12,
                                       bench_parallel=6,
                                       bench_host=(params.get("bench_host") or cf_db.SPEED_HOST))
            bw = asyncio.run(cf_db.bench_bandwidth(ip, port, ns))
            if bw is None:
                return {"ok": False, "error": "测速失败"}
            upsert_test(db, ip, port, bandwidth=bw)
            return {"ok": True, "bandwidth": bw}
        else:
            res = route_probe.classify_route(ip)
            route_class, as_list, hops = res["route_class"], res["as_list"], res["hops"]
            upsert_test(db, ip, port, route_class=route_class, route_as_list=as_list,
                        route_hops=hops)
            return {"ok": True, "route_class": route_class,
                    "label": route_probe.get_class_label(route_class),
                    "as_list": as_list, "hops": hops}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def upsert_test(db, ip, port, latency=None, bandwidth=None, route_class=None,
                route_as_list=None, route_hops=None):
    try:
        conn = sqlite3.connect(db)
        rec = {"ip": ip, "port": port, "ok": True,
               "latency": latency, "bandwidth": bandwidth,
               "route_class": route_class,
               "route_as_list": json.dumps(route_as_list) if route_as_list else None,
               "route_hops": json.dumps(route_hops, ensure_ascii=False) if route_hops else None,
               "route_at": time.time() if route_class else None,
               "tested_at": time.time()}
        cf_db.upsert(conn, rec)
        conn.commit()
        conn.close()
    except Exception:
        pass


# -------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", fname=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        if fname:
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        q = parse_qs(u.query)
        db = get_state()["db"] or DB or "cf_ips.db"
        try:
            if path == "/":
                self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            elif path == "/api/status":
                st = get_state()
                st["db"] = os.path.abspath(db)
                st["version"] = VERSION
                self._send(200, json.dumps(st).encode("utf-8"))
            elif path == "/api/stats":
                self._send(200, json.dumps(api_stats(db)).encode("utf-8"))
            elif path == "/api/table":
                self._send(200, json.dumps(api_table(db, q)).encode("utf-8"))
            elif path == "/api/settings":
                self._send(200, json.dumps(load_settings()).encode("utf-8"))
            elif path == "/api/export":
                fmt = q.get("fmt", ["txt"])[0]
                body, ctype, fname = export_body(db, q, fmt)
                self._send(200, body.encode("utf-8"), ctype, fname)
            elif path == "/api/copy":
                self._send(200, json.dumps(api_copy(db, q)).encode("utf-8"))
            elif path == "/api/optimize":
                self._send(200, json.dumps(api_optimize(db, q)).encode("utf-8"))
            else:
                self._send(404, b'{"error":"not found"}')
        except Exception as e:
            self._send(500, json.dumps({"error": str(e)}).encode("utf-8"))

    def do_POST(self):
        path = urlparse(self.path).path
        params = self._read_json()
        db = get_state()["db"] or DB or "cf_ips.db"
        try:
            if path == "/api/control":
                act = params.get("action")
                if act == "start":
                    out = start_scan(params, db)
                elif act == "stop":
                    out = stop_scan()
                else:
                    out = {"ok": False, "error": "unknown action"}
                self._send(200, json.dumps(out).encode("utf-8"))
            elif path == "/api/settings":
                saved = save_settings(params)
                self._send(200, json.dumps({"ok": True, "saved": saved}).encode("utf-8"))
            elif path == "/api/test":
                out = test_ip(db, params)
                self._send(200, json.dumps(out).encode("utf-8"))
            else:
                self._send(404, b'{"error":"not found"}')
        except Exception as e:
            self._send(500, json.dumps({"error": str(e)}).encode("utf-8"))


PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CF 优选IP 扫描管理台</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1f2630;--line:#2a323d;--txt:#d8dee6;--dim:#7d878f;
--acc:#3b82f6;--acc2:#22c55e;--warn:#f59e0b;--err:#ef4444;--purp:#a78bfa}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:"Segoe UI","Microsoft YaHei",system-ui,sans-serif;padding:22px;font-size:14px}
h1{font-size:21px;display:inline-block}
.sub{color:var(--dim);font-size:13px;margin:4px 0 16px}
.h{font-size:15px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.h .sub{font-weight:400;margin:0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px;
  transition:transform .25s ease,box-shadow .25s ease,border-color .25s ease}
.card:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.28);border-color:#333}
.head{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:6px}
.pill{font-size:12px;font-weight:700;padding:4px 12px;border-radius:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.stat{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:13px;
  transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease;position:relative;overflow:hidden;
  cursor:default}
.stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--acc);
  opacity:0;transition:opacity .2s ease}
.stat:hover{transform:translateY(-3px) scale(1.03);box-shadow:0 6px 18px rgba(0,0,0,.3);border-color:var(--acc)}
.stat:hover::before{opacity:1}
.stat:has(.v.g)::before{background:var(--acc2)}
.stat:has(.v.w)::before{background:var(--warn)}
.stat:has(.v.p)::before{background:var(--purp)}
.stat:hover:has(.v.g){border-color:var(--acc2)}
.stat:hover:has(.v.w){border-color:var(--warn)}
.stat:hover:has(.v.p){border-color:var(--purp)}
.stat::after{content:"";position:absolute;top:0;left:-80%;width:50%;height:100%;
  background:linear-gradient(105deg,transparent,rgba(255,255,255,.09),transparent);
  transform:skewX(-20deg);transition:none;pointer-events:none}
.stat:hover::after{animation:shine .7s ease}
@keyframes shine{0%{left:-80%}100%{left:130%}}
.stat .v{font-size:27px;font-weight:700;color:var(--acc)}
.stat .l{font-size:13px;color:var(--dim);margin-top:3px}
.stat .v.g{color:var(--acc2)} .stat .v.w{color:var(--warn)} .stat .v.p{color:var(--purp)}
@keyframes vPop{0%{transform:scale(.85);opacity:.4}60%{transform:scale(1.08)}100%{transform:scale(1);opacity:1}}
.stat .v{display:inline-block;animation:vPop .35s ease}

.row{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end}
.f label{display:block;font-size:12.5px;color:var(--dim);margin-bottom:4px}
.f .tip{display:inline-block;cursor:help;color:var(--acc);font-weight:700;font-size:11px;
background:var(--panel2);border:1px solid var(--line);border-radius:50%;width:14px;height:14px;
line-height:13px;text-align:center;margin-left:3px;position:relative}
.f .tip .pop{visibility:hidden;opacity:0;position:absolute;bottom:130%;left:50%;transform:translateX(-50%);
background:#0a0e14;border:1px solid var(--line);color:var(--txt);padding:8px 10px;border-radius:6px;
width:230px;font-size:12px;font-weight:400;line-height:1.5;z-index:50;transition:opacity .15s;text-align:left;
box-shadow:0 4px 14px rgba(0,0,0,.5)}
.f .tip .pop::after{content:"";position:absolute;top:100%;left:50%;transform:translateX(-50%);
border:6px solid transparent;border-top-color:var(--line)}
.f .tip:hover .pop{visibility:visible;opacity:1}
.f input,.f select{background:var(--panel2);border:1px solid var(--line);color:var(--txt);
border-radius:6px;padding:8px 9px;font-size:13.5px;outline:none;min-width:84px}
button{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:10px 18px;font-size:13.5px;
cursor:pointer;font-weight:600}
button:hover{filter:brightness(1.1)}
button.stop{background:var(--err)}
button.ghost{background:var(--panel2);border:1px solid var(--line);color:var(--txt)}
button:disabled{opacity:.4;cursor:not-allowed}
.chk{display:flex;align-items:center;gap:6px;font-size:13px;padding-bottom:8px}
.chk input{accent-color:var(--acc);width:16px;height:16px}
#f_premium:checked+label,#f_hasbw:checked+label,#f_v6:checked+label{color:var(--acc2);font-weight:700}
.optbox{white-space:pre;font-family:ui-monospace,Consolas,monospace;font-size:12px;background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:8px;max-height:220px;overflow:auto;line-height:1.6;color:var(--txt);user-select:text}
.pin{color:var(--acc2);font-size:13px;font-weight:700;cursor:pointer;user-select:none}
.pin:hover{text-decoration:underline}
footer .link{color:var(--acc2);cursor:pointer;text-decoration:underline}
.modal-mask{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:99}
.modal-mask.open{display:flex}
.modal{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px;max-width:600px;width:92%;max-height:82vh;overflow:auto;font-size:13px;line-height:1.75}
.modal h2{margin:0 0 6px;font-size:16px}
.modal h3{margin:14px 0 4px;font-size:14px;color:var(--acc2)}
.modal ul{margin:4px 0 0;padding-left:20px}
.modal a{color:var(--acc2)}
.modal .mclose{cursor:pointer;color:var(--dim);font-weight:700}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
.chart h3{font-size:14px;color:var(--dim);margin-bottom:8px;font-weight:600}
canvas{width:100%;height:250px}
#chartTip{position:fixed;z-index:9999;pointer-events:none;background:rgba(14,16,22,.95);
  border:1px solid rgba(255,255,255,.22);border-radius:10px;padding:14px 18px;min-width:220px;
  box-shadow:0 10px 30px rgba(0,0,0,.6);backdrop-filter:blur(4px);
  transform:translate(14px,12px);opacity:0;transition:opacity .12s}
#chartTip.show{opacity:1}
#chartTip .t-title{font-size:15px;font-weight:700;color:#fff;margin-bottom:8px;padding-left:12px;
  border-left:4px solid var(--acc);line-height:1.2}
#chartTip .t-row{display:flex;justify-content:space-between;gap:30px;font-size:13.5px;
  padding:3px 0;line-height:1.4}
#chartTip .t-row .k{color:#9aa6b0}
#chartTip .t-row .k.sec{width:100%;color:#5b6570;font-weight:700;letter-spacing:.5px;border-top:1px solid rgba(255,255,255,.08);padding-top:3px}
#chartTip .t-row .v{font-weight:700;color:#fff}
.toolbar{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin-bottom:10px}
.toolbar .f input{min-width:76px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--dim);font-weight:600;cursor:pointer;user-select:none;background:var(--panel)}
th:hover{color:var(--txt)}
tr:hover td{background:var(--panel2)}
tbody td{position:relative}
tbody tr{transition:transform .18s cubic-bezier(.2,.7,.3,1.2),box-shadow .18s ease}
tbody tr:hover{transform:scale(1.012);box-shadow:0 2px 14px rgba(0,0,0,.25);z-index:5}
#tabWrap.scrolling tbody tr{transition:none !important}
#tabWrap.scrolling tbody tr:hover{transform:none;box-shadow:none}
.bw{color:var(--acc2);font-weight:600;cursor:default}
.bw.muted{color:var(--dim);font-weight:400}
.lat{color:var(--warn)}
.colo{font-weight:700;color:var(--purp)}
.route{color:var(--dim);cursor:help}
 .route:hover{text-decoration:underline dotted}
.route.premium{color:var(--acc2);font-weight:700}
.route.mixed{color:var(--warn);font-weight:600}
.route.undetected{color:var(--dim);font-style:italic}
tr.route-premium-row{outline:1.5px solid var(--acc2);outline-offset:-1.5px}
tr.route-premium-row td{background:linear-gradient(90deg,rgba(34,197,94,.07),transparent)}
.route-hint{color:#7a8695;font-size:12px;line-height:1.6;background:#0f1419;
  border:1px dashed #2c3540;border-radius:8px;padding:8px 12px;margin:10px 0 4px}
.route-hint b{color:#9aa7b5}
.dead{color:var(--dim);text-align:center;padding:20px;font-size:13px}
#tabWrap{max-height:560px;overflow-y:auto;overflow-x:hidden}
.mini{font-size:12px;padding:4px 9px;border-radius:5px}
.mini.lat{background:var(--panel2);color:var(--warn);border:1px solid var(--line)}
.mini.bw{background:var(--panel2);color:var(--acc2);border:1px solid var(--line)}
.mini.route{background:var(--panel2);color:var(--purp);border:1px solid var(--line)}
.mini.route.done{color:var(--acc2)}
.mini.done{background:linear-gradient(135deg,var(--panel2),var(--panel));color:var(--txt);font-weight:700;border-color:var(--acc);transform:scale(1.05);transition:all .2s ease}
.mini.done:hover{transform:scale(1.12);box-shadow:0 0 10px rgba(0,0,0,.3)}
.mini:disabled{opacity:.35}
.pager{display:flex;align-items:center;gap:10px;margin-top:10px;flex-wrap:wrap}
.pager span{font-size:13px;color:var(--dim)}
.pager input{width:54px;padding:4px 6px;background:var(--panel2);border:1px solid var(--line);border-radius:5px;color:var(--txt);text-align:center}
.pager .pg{display:inline-flex;align-items:center;gap:4px}
.pager .pg input{width:46px}
tbody .ck,#ckAll{accent-color:var(--acc);cursor:pointer}
td.ck{width:26px;text-align:center}
footer{margin-top:14px;color:var(--dim);font-size:12px;text-align:center}
#msg{color:var(--warn);font-size:13px;min-height:18px;margin:8px 0}
#toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%) translateY(16px);background:rgba(18,26,38,.94);color:#fff;padding:10px 20px;border-radius:8px;font-size:13px;opacity:0;pointer-events:none;transition:opacity .25s ease,transform .25s ease;z-index:999}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
#toast.ok{background:linear-gradient(135deg,#0b3d2e,#14532d);border:1px solid #22c55e}
#toast.err{background:linear-gradient(135deg,#5c1515,#7f1d1d);border:1px solid #ef4444}
.prog{display:flex;align-items:center;gap:12px;margin-top:12px}
.prog .bar{flex:1;height:16px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.prog .fill{height:100%;width:0;background:linear-gradient(90deg,var(--acc),var(--acc2));transition:width .8s}
.prog .plabel{font-size:13px;color:var(--dim);white-space:nowrap}
.logbox{background:#0a0e14;border:1px solid var(--line);border-radius:8px;height:190px;overflow-y:auto;
font-family:ui-monospace,Consolas,monospace;font-size:12.5px;padding:10px;margin-top:8px;line-height:1.65}
.logline{white-space:pre-wrap;word-break:break-all}
.logline .t{color:#4a5560;margin-right:8px}
.logline.err .m{color:var(--err)}
.logline.ok .m{color:var(--acc2)}

</style>
</head>
<body>
<div class="head">
  <h1>CF 优选IP 扫描管理台</h1>
  <span id="pill" class="pill idle">待命</span>
  <span id="dbpath" class="sub" style="margin:0"></span>
</div>
<div class="sub">多端口 + TLS确认 + 优质C段加权 + 地区补全 + 带宽实测 + 线路分类 &nbsp;|&nbsp; 数据实时落库 SQLite</div>

<div class="route-hint">⚠️ <b>路由检测仅识别去程方向，无法探测回程；晚高峰卡顿多由回程链路导致，实际体验请以延迟、抖动、丢包、下载速度为准。</b></div>

<div class="card">
  <div class="row">
    <div class="f"><label>地址源<span class="tip">?<span class="pop">官方全网=扫CF全部公布网段; CF官方/电信/联通/移动=只扫各运营商官方优选网段</span></span></label>
      <select id="operator">
      <option value="">官方全网</option><option value="cf">CF官方优选</option>
      <option value="ct">电信优选</option><option value="cu">联通优选</option>
      <option value="cmcc">移动优选</option></select></div>
    <div class="f"><label>端口<span class="tip">?<span class="pop">逗号分隔多个端口, 每个IP按顺序尝试. 常用: 443,2053,2083,8443</span></span></label><input id="ports" value="443,2053,2083,8443"></div>
    <div class="f"><label>抽样数/轮<span class="tip">?<span class="pop">每轮随机抽样探测的IP数量. 越大覆盖越广但每轮耗时越长</span></span></label><input id="count" type="number" value="5000"></div>
    <div class="f"><label>并发<span class="tip">?<span class="pop">同时探测的连接数. 越大扫得越快, 越吃CPU和带宽. NAS建议100-200</span></span></label><input id="concurrency" type="number" value="400"></div>
    <div class="f"><label>验证预算/轮<span class="tip">?<span class="pop">每轮对达标IP做地区识别(访问/cdn-cgi/trace)的数量上限</span></span></label><input id="verify" type="number" value="400"></div>
    <div class="f"><label>测带宽/轮<span class="tip">?<span class="pop">每轮实测带宽的IP数量. 很耗带宽和CPU, 想省资源调小或设0</span></span></label><input id="bench" type="number" value="20"></div>
    <div class="f"><label>测速并连数<span class="tip">?<span class="pop">测速时同时开的下载连接数. 6条基本能测满本机线路</span></span></label><input id="bench_parallel" type="number" value="6"></div>
    <div class="f"><label>测速域名<span class="tip">?<span class="pop">带宽实测用的测速服务域名. 默认 speed.cloudflare.com(会被限流); 可填自己的CF Worker域名如 myspeedtest.workers.dev, 不受公共限流</span></span></label><input id="bench_host" value="speed.cloudflare.com" style="min-width:220px"></div>
    <div class="f"><label>地区补全/轮<span class="tip">?<span class="pop">对还没有地区信息的旧IP补做识别. 修复历史遗留数据</span></span></label><input id="backfill" type="number" value="300"></div>
    <div class="f"><label>复核/轮<span class="tip">?<span class="pop">对冷却期已过的最旧IP重新探测, 防止IP失效后仍留在列表</span></span></label><input id="recheck" type="number" value="200"></div>
    <div class="f"><label>线路检测/轮<span class="tip">?<span class="pop">每轮做线路分类的IP上限. 新发现的IP优先测, 已有带宽的IP会在超时后重测, 已测且新鲜的自动跳过不占额度. 精品线路占比极低, 想提高命中率请调大(默认100). 每个IP约1-2秒(并行发包)</span></span></label><input id="route_budget" type="number" value="100"></div>
    <div class="f"><label>线路重测周期(时)<span class="tip">?<span class="pop">已测过线路的IP, 若超过该小时数且本轮IP有带宽数据才重测; 新发现的IP始终测. 避免每轮重复探测消耗资源</span></span></label><input id="route_stale_hours" type="number" value="6"></div>
    <div class="f"><label>优质C段比例<span class="tip">?<span class="pop">抽样时0-1比例的IP从历史优质C段(邻居表现好)里选. 0.6=6成优质邻域+4成随机</span></span></label><input id="exploit" type="number" step="0.1" value="0.6"></div>
    <div class="f"><label>最大延迟ms<span class="tip">?<span class="pop">延迟超过该值的IP不算"达标", 不会被送去验证和测速</span></span></label><input id="max_latency" type="number" value="2000"></div>
    <div class="chk"><input type="checkbox" id="tls_check" checked><label for="tls_check">TLS二次确认<span class="tip">?<span class="pop">TCP能连后还要TLS握手(SNI=cloudflare.com)成功才算存活, 过滤假IP. 吃CPU但结果更干净</span></span></label></div>
    <div class="chk"><input type="checkbox" id="route_check" checked><label for="route_check">线路分类检测<span class="tip">?<span class="pop">对达标IP做路由线路分类: 只识别去程方向(CN2-GIA/9929/CMIN2为精品, 163/169/9808为普通), 需系统有ping命令</span></span></label></div>
    <div class="chk"><input type="checkbox" id="ipv6"><label for="ipv6">同时扫描IPv6<span class="tip">?<span class="pop">IPv6 池 = 公开优选 v6 列表(优先测, 命中率高) + CF官方大段(随机发现新地址). 本机需有IPv6网络. 注意: v6 线路分类暂不支持 ASN 判定, 一律显示"未识别", 不参与精品识别</span></span></label></div>
    <button id="startBtn" onclick="control('start')">开始扫描</button>
    <button id="stopBtn" class="stop" onclick="control('stop')" disabled>停止</button>
    <button class="ghost" onclick="saveSet()">保存设置</button>
  </div>
  <div id="msg"></div>
  <div class="prog">
    <div class="bar"><div class="fill" id="progFill"></div></div>
    <div class="plabel" id="progLabel">—</div>
  </div>
  <div class="logbox" id="logbox"><div class="logline"><span class="t">HH:MM:SS</span><span class="m">等待事件...</span></div></div>
</div>

<div class="card">
  <div class="stats">
    <div class="stat"><div class="v" id="st_total">0</div><div class="l">已测试IP</div></div>
    <div class="stat"><div class="v g" id="st_alive">0</div><div class="l">存活IP</div></div>
    <div class="stat"><div class="v p" id="st_verified">0</div><div class="l">已验证地区</div></div>
    <div class="stat"><div class="v" id="st_bw">0</div><div class="l">有带宽数据</div></div>
    <div class="stat"><div class="v w" id="st_avglat">-</div><div class="l">平均延迟ms</div></div>
    <div class="stat"><div class="v" id="st_maxbw">-</div><div class="l">最高带宽Mbps</div></div>
    <div class="stat"><div class="v" id="st_minlat">-</div><div class="l">最低延迟ms</div></div>
    <div class="stat"><div class="v" id="st_cov">0%</div><div class="l">覆盖率</div></div>
    <div class="stat"><div class="v" id="st_route">-</div><div class="l">精品线路IP</div></div>
  </div>
</div>

<div class="card">
  <div class="charts">
    <div class="chart"><h3>机房分布 (colo 前12)</h3><canvas id="ch_colo"></canvas></div>
    <div class="chart"><h3>国家/地区分布 (colo 前12)</h3><canvas id="ch_country"></canvas></div>
    <div class="chart"><h3>延迟分布 (ms)</h3><canvas id="ch_lat"></canvas></div>
    <div class="chart"><h3>带宽分布 (Mbps)</h3><canvas id="ch_bw"></canvas></div>
    <div class="chart"><h3>线路分布 (前12)</h3><canvas id="ch_route"></canvas></div>
  </div>
</div>

<div class="card">
  <div class="h">🎯 手动优选 <span class="sub">从本地库已优选 IP 中抽候选现场重测(连通+识别+测速), 取最优 N 条展示, 不写入本地库</span></div>
  <div class="toolbar">
    <div class="f"><label>数量</label><input id="opt_count" type="number" min="1" max="200" value="10"></div>
    <div class="f"><label>优先</label><select id="opt_prio">
      <option value="bw">优先带宽</option><option value="lat">优先延迟</option></select></div>
    <div class="f"><label>地区过滤</label><input id="opt_region" placeholder="如 HKG,NRT"></div>
    <div class="chk"><input type="checkbox" id="opt_premium"><label for="opt_premium">仅精品</label></div>
    <div class="chk"><input type="checkbox" id="opt_hasbw" checked><label for="opt_hasbw">仅有带宽</label></div>
    <div class="chk"><input type="checkbox" id="opt_v6"><label for="opt_v6">仅IPv6</label></div>
    <button class="ghost" id="optBtn" onclick="runOpt()">优选</button>
    <button class="ghost mini" onclick="copyOptSel()">复制选中(<span id="optSelCount">0</span>)</button>
    <button class="ghost mini" onclick="copyOpt()">复制全部</button>
    <span class="pin" id="optPin"></span>
  </div>
  <div id="optWrap">
    <table>
      <thead><tr>
        <th style="width:26px"><input type="checkbox" id="optCkAll" title="全选" onclick="toggleOptAll(this)"></th>
        <th>#</th><th>带宽Mbps</th><th>延迟ms</th><th>IP</th><th>端口</th>
        <th>机房</th><th>国家/地区</th><th>线路</th><th>测速时间</th>
      </tr></thead>
      <tbody id="optBody"></tbody>
    </table>
    <div class="dead" id="optEmpty">点击「优选」: 从本地库已优选 IP 中抽候选, 现场重测后取最优 N 条, 展示在此处, 不写入本地库</div>
  </div>
</div>

<div class="card">
  <div class="toolbar">
    <div class="f"><label>机房过滤</label><input id="f_region" placeholder="如 HKG,NRT"></div>
    <div class="f"><label>最小带宽Mbps</label><input id="f_minbw" type="number" value="0"></div>
    <div class="f"><label>最大延迟ms</label><input id="f_maxlat" type="number" value="2000"></div>
    <div class="f"><label>IP包含</label><input id="f_q" placeholder="IP关键字"></div>
    <div class="f"><label>端口</label><input id="f_port" placeholder="全部"></div>
    <div class="chk"><input type="checkbox" id="f_premium"><label for="f_premium">只显示精品互联线路</label></div>
    <div class="chk"><input type="checkbox" id="f_hasbw"><label for="f_hasbw">仅有带宽</label></div>
    <div class="chk"><input type="checkbox" id="f_v6"><label for="f_v6">仅IPv6</label></div>
    <button class="ghost" onclick="exportF('txt')">导出 ADD.txt</button>
    <button class="ghost" onclick="exportF('csv')">导出 CSV</button>
  </div>
  <div id="tabWrap">
    <table>
      <thead><tr>
        <th style="width:26px"><input type="checkbox" id="ckAll" title="全选本页" onclick="togglePageSel(this)"></th>
        <th>#</th><th onclick="sortBy('bw')">带宽Mbps</th><th onclick="sortBy('lat')">延迟ms</th>
        <th onclick="sortBy('ip')">IP</th><th onclick="sortBy('port')">端口</th>
        <th onclick="sortBy('colo')">机房</th><th>国家/地区</th>
        <th title="仅作筛选标签, 不参与排序">线路</th>
        <th onclick="sortBy('time')">最近测试</th><th>存活/失败</th><th>操作</th></thead>
      <tbody id="tbody"></tbody>
    </table>
    <div class="dead" id="emptyTip">暂无数据 — 点击"开始扫描"</div>
  </div>
  <div class="pager">
    <button class="ghost mini" onclick="copySel()">复制选中IP(<span id="selCount">0</span>)</button>
    <button class="ghost mini" onclick="exportSel()">导出选中</button>
    <button class="ghost mini" onclick="clearSel()">清空选中</button>
    <span style="flex:1"></span>
    <button class="ghost mini" onclick="page(-1)">上一页</button>
    <span id="pageInfo">共 0 条</span>
    <span class="pg">第 <input id="pageJump" type="number" min="1" value="1"> / <span id="pageTotal">1</span> 页</span>
    <button class="ghost mini" onclick="jumpPage()">跳转</button>
    <button class="ghost mini" onclick="page(1)">下一页</button>
  </div>
</div>

<footer>数据来源: <span id="srcHost">speed.cloudflare.com</span> 实测带宽 &amp; /cdn-cgi/trace 地区识别 &nbsp;|&nbsp; 服务端 v<span id="ver">?</span> &nbsp;|&nbsp; <span class="link" onclick="openAbout()">关于</span></footer>

<div id="chartTip"><div class="t-title"></div><div class="t-body"></div></div>

<div class="modal-mask" id="aboutMask" onclick="if(event.target===this)closeAbout()">
  <div class="modal">
    <div class="row" style="justify-content:space-between;align-items:center">
      <h2>🚀 CF 优选IP 扫描管理台</h2>
      <span class="mclose" onclick="closeAbout()">✕ 关闭</span>
    </div>
    <p>基于 Cloudflare 官方地址池的<b>持续优选扫描器</b>, 带 Web 图形管理台。纯 Python 标准库实现, 零第三方依赖, 数据存 SQLite 断点续扫。</p>
    <h3>功能一览</h3>
    <ul>
      <li>多端口并发探测 + TLS 二次确认, 自动发现可用 CF 边缘 IP</li>
      <li>邻域加权采样(优质 C 段优先), 达标命中率远高于纯随机</li>
      <li>带宽实测(可配自建 Worker 测速域名规避公共限流) + 机房/国家地区识别</li>
      <li>去程线路分类: 精品(CN2-GIA/9929/CMIN2) / 普通(163/169/9808) / 混合 / 未识别, 悬停线路列看逐跳 Traceroute</li>
      <li>手动优选: 从本地库抽候选现场重测, 取最优 N 条, 可优先带宽/延迟, 勾选复制</li>
      <li>本地IP列表: 列排序 / 多条件筛选 / 勾选批量操作 / 翻页跳转, 导出 ADD.txt/CSV</li>
    </ul>
    <h3>版本</h3>
    <p>服务端 v<span id="ver2">?</span> &nbsp;|&nbsp; 后端地址: 官方 / 电信 / 联通 / 移动优选段</p>
    <h3>开源</h3>
    <p>GitHub: <a href="https://github.com/zqy857/cf-optimizer" target="_blank" rel="noopener">zqy857/cf-optimizer</a> (MIT 许可)</p>
  </div>
</div>

<script>
const $=id=>document.getElementById(id);
let SORT="bw";
let OFFSET=0;
const LIMIT=100;
let PAGE_TOTAL=0;
const SEL=new Set();
function openAbout(){const v=$("ver2");if(v)v.textContent=$("ver").textContent||"?";$("aboutMask").classList.add("open");}
function closeAbout(){$("aboutMask").classList.remove("open");}
function updateSelUI(){const el=$("selCount");if(el)el.textContent=SEL.size;}
function togglePageSel(ck){
  document.querySelectorAll("#tbody .ck").forEach(c=>{c.checked=ck.checked;
    if(ck.checked)SEL.add(c.dataset.ip);else SEL.delete(c.dataset.ip);});
  updateSelUI();
}
function rowSelChange(c){
  if(c.checked)SEL.add(c.dataset.ip);else SEL.delete(c.dataset.ip);
  updateSelUI();
}
function copyText(txt){
  if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(txt).then(()=>true);
  return new Promise(res=>{
    const ta=document.createElement("textarea");ta.value=txt;
    ta.style.cssText="position:fixed;opacity:0";document.body.appendChild(ta);
    ta.select();
    let ok=false;try{ok=document.execCommand("copy")}catch(e){}
    ta.remove();res(ok);
  });
}
function toast(text,cls){
  const t=$("toast");if(!t)return;
  t.textContent=text;t.className=cls||"";t.classList.add("show");
  clearTimeout(toast._t);
  toast._t=setTimeout(()=>{t.classList.remove("show")},2400);
}
function copySel(){
  const ips=[...SEL].sort();
  if(!ips.length){toast("未选中任何IP","err");return}
  fetch("/api/copy?ips="+encodeURIComponent(ips.join(","))).then(r=>r.json()).then(d=>{
    if(!d.rows||!d.rows.length){toast("所选IP在数据库中无记录","err");return}
    const lines=d.rows.map(r=>r.ip+":"+r.port+"#"+r.country+(r.route_class==="premium"?"精品":""));
    copyText(lines.join("\n")).then(ok=>{
      if(ok)toast("复制成功: "+lines.length+" 条","ok");
      else toast("复制失败, 请手动复制","err");
    });
  }).catch(()=>toast("复制请求失败","err"));
}
function exportSel(){
  const ips=[...SEL].sort();
  if(!ips.length){toast("未选中任何IP","err");return}
  fetch("/api/copy?ips="+encodeURIComponent(ips.join(","))).then(r=>r.json()).then(d=>{
    if(!d.rows||!d.rows.length){toast("所选IP在数据库中无记录","err");return}
    const lines=d.rows.map(r=>r.ip+":"+r.port+"#"+r.country+(r.route_class==="premium"?"精品":""));
    const a=document.createElement("a");
    a.href=URL.createObjectURL(new Blob([lines.join("\n")+"\n"],{type:"text/plain;charset=utf-8"}));
    a.download="selected.txt";
    document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a);a.remove()},400);
    toast("已导出 "+lines.length+" 条","ok");
  }).catch(()=>toast("导出请求失败","err"));
}
function clearSel(){SEL.clear();
  document.querySelectorAll("#tbody .ck").forEach(c=>c.checked=false);
  const ca=$("ckAll");if(ca)ca.checked=false;updateSelUI();}
function jumpPage(){
  const totalPages=Math.max(1,Math.ceil(PAGE_TOTAL/LIMIT));
  let pg=Math.floor(+$("pageJump").value||1);
  pg=Math.max(1,Math.min(pg,totalPages));
  $("pageJump").value=pg;
  OFFSET=(pg-1)*LIMIT;
  loadTable();
}
let OPT_ROWS=[], OSEL=new Set(), OPT_TS=0;
function optParams(){
  const p=new URLSearchParams();
  p.set("count",$("opt_count").value||10);
  p.set("prio",$("opt_prio").value||"bw");
  if($("opt_region").value.trim())p.set("region",$("opt_region").value.trim());
  if($("opt_premium").checked)p.set("route","premium");
  if($("opt_hasbw").checked)p.set("hasbw","1");
  if($("opt_v6").checked)p.set("v6","1");
  return p;
}
function optLine(r){return r.ip+":"+r.port+"#"+r.country+(r.route_class==="premium"?"精品":"");}
function optSelUI(){
  const c=$("optSelCount");if(c)c.textContent=OSEL.size;
  const all=$("optCkAll");
  if(all){const cs=[...document.querySelectorAll("#optBody .optck")];all.checked=cs.length>0&&cs.every(c=>c.checked);}
}
function toggleOptSel(el){
  const k=el.dataset.key;
  if(el.checked)OSEL.add(k);else OSEL.delete(k);
  optSelUI();
}
function toggleOptAll(el){
  document.querySelectorAll("#optBody .optck").forEach(c=>{c.checked=el.checked;const k=c.dataset.key;if(el.checked)OSEL.add(k);else OSEL.delete(k);});
  optSelUI();
}
function renderOpt(d){
  const rows=d.rows||[];
  const tb=$("optBody"), empty=$("optEmpty");
  tb.innerHTML="";
  OPT_ROWS=rows;
  OSEL=new Set([...OSEL].filter(k=>rows.some(r=>r.ip+":"+r.port===k)));
  if(!rows.length){empty.style.display="block";$("optPin").textContent="";optSelUI();return}
  empty.style.display="none";
  const now=OPT_TS?new Date(OPT_TS*1000).toLocaleString("zh-CN",{hour12:false}):"";
  tb.innerHTML=rows.map((r,i)=>{
    const key=r.ip+":"+r.port;
    const rcl=r.route_class;
    const rtxt=RCL[rcl]?("<span title=\"仅作筛选标签, 不参与排序\">"+RCL[rcl]+"</span>"):"<span class=\"muted\">待测</span>";
    return "<tr>"+
      '<td><input type="checkbox" class="optck" data-key="'+key+'" '+(OSEL.has(key)?"checked":"")+' onchange="toggleOptSel(this)"></td>'+
      "<td>"+(i+1)+"</td>"+
      "<td>"+(r.bandwidth!=null?r.bandwidth:"<span class=\"muted\">—</span>")+"</td>"+
      "<td>"+(r.latency!=null?r.latency:"—")+"</td>"+
      "<td>"+r.ip+"</td>"+"<td>"+r.port+"</td>"+
      "<td>"+(r.colo||"UNK")+"</td>"+"<td>"+r.country+"</td>"+
      "<td>"+rtxt+"</td>"+"<td>"+now+"</td>"+
      "</tr>";
  }).join("");
  $("optPin").textContent="🔝 最优 "+rows.length+" 条, 勾选后「复制选中」";
  optSelUI();
}
function runOpt(){
  const btn=document.querySelector("#optBtn");
  if(btn){btn.disabled=true;btn.textContent="优选中...";}
  $("optEmpty").textContent="正在从本地库抽候选并现场重测(探测+识别+测速), 请稍候...";
  $("optEmpty").style.display="block";
  $("optBody").innerHTML="";
  fetch("/api/optimize?"+optParams()).then(r=>r.json()).then(d=>{
    OPT_TS=Math.floor(Date.now()/1000);
    if(!d.rows||!d.rows.length){OPT_ROWS=[];OSEL.clear();$("optEmpty").textContent="无符合条件的结果, 请调整筛选条件";$("optEmpty").style.display="block";$("optPin").textContent="";optSelUI();toast("无符合条件的结果","err");return}
    renderOpt(d);
    toast("优选完成: 候选"+d.cands+"条/存活"+d.live+"条","ok");
  }).catch(e=>{
    $("optEmpty").textContent="优选请求失败: "+e;
    toast("优选请求失败: "+e,"err");
  }).finally(()=>{
    if(btn){btn.disabled=false;btn.textContent="优选";}
  });
}
function copyOpt(){
  if(!OPT_ROWS.length){toast("请先点「优选」","err");return}
  const txt=OPT_ROWS.map(optLine).join("\n");
  copyText(txt).then(ok=>{
    if(ok)toast("已复制全部 "+OPT_ROWS.length+" 条","ok");
    else toast("复制失败, 请手动复制","err");
  });
}
function copyOptSel(){
  if(!OSEL.size){toast("未选中任何优选结果","err");return}
  const map=Object.fromEntries(OPT_ROWS.map(r=>[r.ip+":"+r.port,optLine(r)]));
  const txt=[...OSEL].map(k=>map[k]).filter(Boolean).join("\n");
  copyText(txt).then(ok=>{
    if(ok)toast("已复制选中 "+OSEL.size+" 条","ok");
    else toast("复制失败, 请手动复制","err");
  });
}
const MANUAL={};
const HOPS={};
const RCL={premium:"🏆 精品互联线路",common:"⚡ 普通国际线路",mixed:"🔀 混合互联线路",undetected:"🧪 无法判定路由"};
function esc(s){return String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}

function fmt(v){return v==null?"-":v}

function hexA(hex,a){const n=parseInt(hex.slice(1),16);
  return `rgba(${(n>>16)&255},${(n>>8)&255},${n&255},${a})`}
function chartHover(cv){
  if(cv._hb)return; cv._hb=1;
  const redraw=()=>{const d=cv._data;if(!d)return;
    d.type==="bar"?barChart(cv.id,d.items,d.color):histChart(cv.id,d.labels,d.data,d.color)};
  const TIP=$("chartTip");
  function moveTip(title,lines,color){
    TIP.style.borderColor=hexA(color,.6);
    TIP.querySelector(".t-title").style.borderLeftColor=color;
    TIP.querySelector(".t-title").textContent=title;
    TIP.querySelector(".t-body").innerHTML=lines.map(l=>
      `<div class="t-row"><span class="k">${esc(l[0])}</span><span class="v" style="color:${l[2]||'#fff'}">${esc(l[1])}</span></div>`
    ).join("");
  }
  cv.addEventListener("mousemove",e=>{
    const rect=cv.getBoundingClientRect();
    const x=(e.clientX-rect.left)*(cv.width/rect.width);
    const y=(e.clientY-rect.top)*(cv.height/rect.height);
    cv._mx=x; cv._my=y;
    const d=cv._data; if(!d)return;
    let h=-1;
    if(d.type==="bar"){const rh=(cv.height-16)/Math.max(1,d.items.length);h=Math.floor((y-4)/rh);if(h<0||h>=d.items.length)h=-1}
    else{const n=d.labels.length,sl=(cv.width-16)/n;h=Math.floor((x-8)/sl);if(h<0||h>=n)h=-1}
    if(h>=0){
      TIP.classList.add("show");
      TIP.style.left=e.clientX+"px"; TIP.style.top=e.clientY+"px";
      const nw=TIP.offsetWidth, nh=TIP.offsetHeight;
      let lx=e.clientX+16, ty=e.clientY+14;
      if(lx+nw>innerWidth-8)lx=e.clientX-nw-16;
      if(ty+nh>innerHeight-8)ty=e.clientY-nh-14;
      TIP.style.transform=`translate(${lx-e.clientX}px,${ty-e.clientY}px)`;
      if(d.type==="bar"&&d.items[h]){
        const it=d.items[h],total=d.items.reduce((a,b)=>a+b.count,0);
        moveTip(it.name,[["数量",it.count,"#fff"],["占比",total?Math.round(it.count/total*100)+"%":"-",d.color],["排名","#"+(h+1),"#8ad"]],d.color);
      }else if(d.type==="hist"&&d.data[h]!=null){
        const v=d.data[h],total=d.data.reduce((a,b)=>a+b,0);
        moveTip(d.labels[h],[[v+" IP",v,"#fff"],[d.labels[h],total?Math.round(v/total*100)+"%":"-",d.color]],d.color);
      }
    }else{TIP.classList.remove("show")}
    if(cv._hover!==h){cv._hover=h;redraw()}
    else if(h>=0){redraw()}
  });
  cv.addEventListener("mouseleave",()=>{cv._mx=null;cv._my=null;TIP.classList.remove("show");if(cv._hover!==-1){cv._hover=-1;redraw()}});
  cv.addEventListener("click",()=>{cv._needredraw=true});
}
function barChart(cid, items, color){
  const cv=$(cid); if(!cv)return;
  cv._data={type:"bar",items,color}; chartHover(cv);
  const ctx=cv.getContext("2d");
  const W=cv.width=cv.clientWidth*2, H=cv.height=250*2, pad=90;
  const n=items.length, rowH=(H-16)/Math.max(1,n), max=Math.max(1,...items.map(i=>i.count));
  const maxW=(W-pad-20)*0.7;
  const hover=cv._hover!=null?cv._hover:-1;
  const prog=(cv.dataset.bar||1)-0; const p=Math.min(1,prog+0.14);
  cv.dataset.bar=p;
  ctx.clearRect(0,0,W,H); ctx.textBaseline="middle";
  const grad=ctx.createLinearGradient(pad,0,W,0);
  grad.addColorStop(0,hexA(color,.3)); grad.addColorStop(1,color);
  items.forEach((it,i)=>{
    const y=i*rowH+4, w=Math.max(3,maxW*(it.count/max)*easeOut(p));
    const isHover=hover===i;
    ctx.font="19px sans-serif";
    ctx.fillStyle=isHover?color:"#aeb6bf";
    ctx.fillText(it.name,2,y+rowH/2,pad-8);
    if(w>2){
      if(isHover){ctx.fillStyle=color;ctx.shadowColor=hexA(color,.55);ctx.shadowBlur=16}
      else ctx.fillStyle=grad;
      ctx.beginPath();ctx.roundRect(pad,y,w,rowH-8,[5,5,5,5]);ctx.fill();ctx.shadowBlur=0;
      if(isHover){ctx.strokeStyle="#fff";ctx.lineWidth=2;ctx.beginPath();ctx.roundRect(pad,y,w,rowH-8,[5,5,5,5]);ctx.stroke()}
    }
    ctx.font=(isHover?"22px":"19px")+" sans-serif";
    ctx.fillStyle=isHover?"#fff":"#d8dee6";
    ctx.fillText(it.count,pad+w+6,y+rowH/2);
  });
  if(hover>=0&&cv._mx!=null&&items[hover]){
    const it=items[hover], y=hover*rowH+4, w=Math.max(3,maxW*(it.count/max)*easeOut(p));
    const bx=pad+w, by=y+rowH/2, mx=cv._mx, my=cv._my;
    ctx.save();
    ctx.strokeStyle=hexA(color,.6);ctx.lineWidth=3;ctx.setLineDash([8,6]);
    ctx.beginPath();ctx.moveTo(bx,by);ctx.lineTo(mx,my);ctx.stroke();ctx.setLineDash([]);
    ctx.strokeStyle="rgba(0,0,0,.35)";ctx.lineWidth=7;
    ctx.beginPath();ctx.arc(mx,my,9,0,7);ctx.stroke();
    ctx.fillStyle=color;ctx.beginPath();ctx.arc(mx,my,9,0,7);ctx.fill();
    ctx.strokeStyle="#fff";ctx.lineWidth=2.5;ctx.beginPath();ctx.arc(mx,my,9,0,7);ctx.stroke();
    ctx.restore();
  }
  if(p<1)requestAnimationFrame(()=>barChart(cid,items,color))
}
function histChart(cid, labels, data, color){
  const cv=$(cid); if(!cv)return;
  cv._data={type:"hist",labels,data,color}; chartHover(cv);
  const ctx=cv.getContext("2d");
  const W=cv.width=cv.clientWidth*2, H=cv.height=250*2, padB=34, padT=30;
  const n=labels.length;
  const max=Math.max(1,...data), slot=(W-16)/n;
  const maxH=(H-padB-padT)*0.85;
  const hover=cv._hover!=null?cv._hover:-1;
  const prog=(cv.dataset.hist||1)-0; const p=Math.min(1,prog+0.12);
  cv.dataset.hist=p;
  ctx.clearRect(0,0,W,H);
  const grad=ctx.createLinearGradient(0,H-padB,0,padT);
  grad.addColorStop(0,hexA(color,.22)); grad.addColorStop(1,color);
  ctx.textAlign="center"; ctx.textBaseline="middle";
  data.forEach((v,i)=>{
    const x=i*slot+8, w=slot-14, h=Math.max(1,Math.round(maxH*(v/max)*easeOut(p)));
    const isHover=hover===i;
    if(h>1){
      if(isHover){ctx.fillStyle=color;ctx.shadowColor=hexA(color,.55);ctx.shadowBlur=16}
      else ctx.fillStyle=grad;
      ctx.beginPath();ctx.roundRect(x,H-padB-h,w,h,[5,5,0,0]);ctx.fill();ctx.shadowBlur=0;
      if(isHover){ctx.strokeStyle="#fff";ctx.lineWidth=2;ctx.beginPath();ctx.roundRect(x,H-padB-h,w,h,[5,5,0,0]);ctx.stroke()}
    }
    ctx.font="18px sans-serif";
    ctx.fillStyle="#aeb6bf"; ctx.fillText(labels[i],x+w/2,H-padB+14);
    ctx.font=(isHover?"21px":"18px")+" sans-serif";
    ctx.fillStyle=isHover?"#fff":"#d8dee6";
    ctx.fillText(v,x+w/2,H-padB-h-14);
  });
  if(hover>=0&&cv._mx!=null&&data[hover]!=null){
    const v=data[hover], x=hover*slot+8, w=slot-14, h=Math.max(1,Math.round(maxH*(v/max)*easeOut(p)));
    const bx=x+w/2, by=H-padB-h, mx=cv._mx, my=cv._my;
    ctx.save();
    ctx.strokeStyle=hexA(color,.6);ctx.lineWidth=3;ctx.setLineDash([8,6]);
    ctx.beginPath();ctx.moveTo(bx,by);ctx.lineTo(mx,my);ctx.stroke();ctx.setLineDash([]);
    ctx.strokeStyle="rgba(0,0,0,.35)";ctx.lineWidth=7;
    ctx.beginPath();ctx.arc(mx,my,9,0,7);ctx.stroke();
    ctx.fillStyle=color;ctx.beginPath();ctx.arc(mx,my,9,0,7);ctx.fill();
    ctx.strokeStyle="#fff";ctx.lineWidth=2.5;ctx.beginPath();ctx.arc(mx,my,9,0,7);ctx.stroke();
    ctx.restore();
  }
  ctx.textAlign="left";
  if(p<1)requestAnimationFrame(()=>histChart(cid,labels,data,color))
}
function easeOut(t){return 1-Math.pow(1-t,3)}

function control(act){
  if(act==="start"){ $("startBtn").disabled=true; $("startBtn").textContent="启动中...";
    $("msg").textContent="正在发送启动指令..."; }
  fetch("/api/control",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({action:act,operator:$("operator").value,ports:$("ports").value,
      count:$("count").value,concurrency:$("concurrency").value,verify:$("verify").value,
      bench:$("bench").value,backfill:$("backfill").value,recheck:$("recheck").value,
      exploit:$("exploit").value,max_latency:$("max_latency").value,
      bench_parallel:$("bench_parallel").value,
      bench_host:$("bench_host").value,
      route_budget:$("route_budget").value,
      route_stale_hours:$("route_stale_hours").value,
      route_check:$("route_check").checked?"1":"0",
      tls_check:$("tls_check").checked?"1":"0",
      ipv6:$("ipv6").checked?"1":"0"})}).then(r=>r.json()).then(r=>{
    $("startBtn").textContent="开始扫描";
    if(!r.ok&&r.error){$("msg").textContent="启动失败: "+r.error}
    else if(act==="start"){$("msg").textContent="启动指令已送达, 扫描开始, 请留意下方状态与日志";}
    else{$("msg").textContent="停止指令已送达, 正在结束本轮探测...";}
  }).catch(e=>{ $("startBtn").textContent="开始扫描";
    $("msg").textContent="请求失败, 请重开网页或重启程序: "+e;
    $("startBtn").disabled=false; });
}

function tableParams(){
  const region=($("f_region").value||"").split(",").map(s=>s.trim()).filter(Boolean);
  const p=new URLSearchParams();
  if(region.length)p.set("region",region.join(","));
  if($("f_premium").checked)p.set("route","premium");
  if(+$("f_minbw")>0)p.set("minbw",$("f_minbw"));
  if(+$("f_maxlat")<99999)p.set("maxlat",$("f_maxlat"));
  if($("f_q").value)p.set("q",$("f_q"));
  if($("f_port").value)p.set("port",$("f_port"));
  if($("f_hasbw").checked)p.set("hasbw","1");
  if($("f_v6").checked)p.set("v6","1");
  p.set("sort",SORT);
  p.set("offset",OFFSET);
  return p;
}

function bwCellHtml(r){
  if(r.bandwidth==null)return '<span class="bw muted">待测</span>';
  const data=JSON.stringify({
    bw:r.bandwidth,
    best:r.bw_best!=null?r.bw_best.toFixed(1):"—",
    lastAt:r.bw_last_at?new Date(r.bw_last_at*1000).toLocaleString("zh-CN",{hour12:false}):"未知",
    lat:r.latency!=null?r.latency+" ms":"—",
    ok:r.ok, fail:r.fail
  }).replace(/"/g,"&quot;");
  return '<span class="bw" data-bw="'+data+'">'+r.bandwidth+'</span>';
}
function renderTable(data){
  const rows=data.rows, tb=$("tbody"); tb.innerHTML="";
  PAGE_TOTAL=data.total;
  $("pageInfo").textContent="共 "+data.total+" 条 · 显示 "+(data.offset+1)+"~"+(data.offset+rows.length)+" · 每页 "+data.limit;
  $("pageTotal").textContent=Math.max(1,Math.ceil(data.total/LIMIT));
  $("pageJump").value=Math.floor(data.offset/LIMIT)+1;
  if(!rows.length){$("emptyTip").style.display="block";return}
  $("emptyTip").style.display="none";
  for(const k in HOPS)delete HOPS[k];
  rows.forEach((r,i)=>{
    const bwCell=bwCellHtml(r);
    const lat=r.latency==null?"-":'<span class="lat">'+r.latency+"</span>";
    const tt=r.tested?new Date(r.tested*1000).toLocaleString("zh-CN",{hour12:false}):"-";
    const rcl=r.route_class;
    const hk=r.ip+":"+r.port;
    let hopsData=null;
    if(r.route_hops){try{hopsData=JSON.parse(r.route_hops)}catch(e){}}
    if(hopsData&&hopsData.length)HOPS[hk]=hopsData;else delete HOPS[hk];
    const routeAttrs=rcl?(' data-cls="'+esc(rcl)+'"'+(hopsData&&hopsData.length?(' data-hk="'+hk+'"'):'')):'';
    const routeCell=rcl
      ?'<span class="route '+esc(rcl)+'"'+routeAttrs+'>'+esc(RCL[rcl]||rcl)+'</span>'
      :'<span class="route">未检测</span>';
    const mla=MANUAL[r.ip+":"+r.port+":lat"], mbw=MANUAL[r.ip+":"+r.port+":bw"], mrt=MANUAL[r.ip+":"+r.port+":route"];
    const latBtn=mla?`<button class="mini lat done" title="${esc(mla.title)}" onclick="testIp('lat','${r.ip}',${r.port},this)">${mla.text}</button>`
                   :`<button class="mini lat" onclick="testIp('lat','${r.ip}',${r.port},this)">测延迟</button>`;
    const bwBtn=mbw?`<button class="mini bw done" title="${esc(mbw.title)}" onclick="testIp('bw','${r.ip}',${r.port},this)">${mbw.text}</button>`
                   :`<button class="mini bw" onclick="testIp('bw','${r.ip}',${r.port},this)">测带宽</button>`;
    const rtBtn=mrt?`<button class="mini route done" title="${esc(mrt.title)}" onclick="testIp('route','${r.ip}',${r.port},this)">${mrt.text}</button>`
                   :`<button class="mini route" onclick="testIp('route','${r.ip}',${r.port},this)">测线路</button>`;
    const tr=document.createElement("tr");
    if(rcl==="premium")tr.className="route-premium-row";
    tr.setAttribute("data-aslist", r.route_as_list||"");
    const ck=SEL.has(r.ip);
    tr.innerHTML=`<td class="ck"><input type="checkbox" class="ck" data-ip="${esc(r.ip)}" ${ck?"checked":""} onchange="rowSelChange(this)"></td>`+
      `<td>${data.offset+i+1}</td><td>${bwCell}</td><td>${lat}</td><td>${esc(r.ip)}</td><td>${r.port}</td>`+
      `<td class="colo">${esc(r.colo)}</td><td>${esc(r.country)}</td><td>${routeCell}</td><td>${tt}</td>`+
      `<td>${fmt(r.ok)}/<span style="color:var(--err)">${r.fail}</span></td>`+
      `<td>${latBtn}${bwBtn}${rtBtn}</td>`;
    tb.appendChild(tr);
  });
  const ca=$("ckAll");
  if(ca)ca.checked=rows.length>0&&rows.every(r=>SEL.has(r.ip));
  updateSelUI();
}
function sortBy(k){SORT=k;OFFSET=0;loadTable()}
function page(d){OFFSET=Math.max(0,OFFSET+d*LIMIT);loadTable()}
function loadTable(){
  fetch("/api/table?"+tableParams()).then(r=>r.json()).then(data=>renderTable(data));
}
function testIp(act,ip,port,btn){
  btn.disabled=true;const old=btn.textContent;btn.textContent="测试中...";
  fetch("/api/test",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({action:act,ip:ip,port:port,bench_host:$("bench_host").value})}).then(r=>r.json()).then(r=>{
    if(r.ok){
      if(act==="route"){
        MANUAL[ip+":"+port+":route"]={text:r.label,title:r.label+(r.route_class==="premium"?" (精品)":"")+" [AS: "+(r.as_list||[]).join(",")+"] · 悬停线路列看逐跳详情",ok:true};
        btn.textContent=r.label;btn.title=MANUAL[ip+":"+port+":route"].title;
        btn.classList.add("done");btn.disabled=false;loadTable();
      }else{
        MANUAL[ip+":"+port+":"+act]={text:act==="lat"?(r.latency+"ms"):(r.bandwidth+"M"),
          title:act==="lat"?("实测延迟 "+r.latency+"ms"):("实测带宽 "+r.bandwidth+" Mbps"),ok:true};
        btn.textContent=act==="lat"?(r.latency+"ms"):(r.bandwidth+"M");
        btn.classList.add("done");btn.title=MANUAL[ip+":"+port+":"+act].title;
        btn.disabled=false;loadTable();
      }
    }
    else{btn.textContent="失败";btn.title={lat:"延迟测试失败",bw:"带宽测试失败",route:"线路检测失败"}[act];
      setTimeout(()=>{btn.textContent=old;btn.disabled=false},8000);
    }
  }).catch(e=>{btn.textContent=old;btn.disabled=false;alert("请求失败: "+e)});
}
function saveSet(){
  const body={operator:$("operator").value,ports:$("ports").value,count:$("count").value,
    concurrency:$("concurrency").value,verify:$("verify").value,bench:$("bench").value,
    backfill:$("backfill").value,recheck:$("recheck").value,exploit:$("exploit").value,
    max_latency:$("max_latency").value,bench_parallel:$("bench_parallel").value,
    bench_host:$("bench_host").value,route_budget:$("route_budget").value,
    route_stale_hours:$("route_stale_hours").value,
    route_check:$("route_check").checked?"1":"0",
    tls_check:$("tls_check").checked?"1":"0",
    ipv6:$("ipv6").checked?"1":"0"};
  fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify(body)}).then(r=>r.json()).then(r=>{
    $("msg").textContent=r.ok?"设置已保存到服务器, 下次刷新也会保留":"保存失败: "+r.error;
  }).catch(e=>{$("msg").textContent="保存失败: "+e});
}
function loadSet(){
  fetch("/api/settings").then(r=>r.json()).then(d=>{
    if(!d||!Object.keys(d).length)return;
    if(d.operator!==undefined)$("operator").value=d.operator||"";
    ["ports","count","concurrency","verify","bench","bench_parallel","bench_host",
     "backfill","recheck","exploit","max_latency","route_budget","route_stale_hours"].forEach(k=>{
       const v=d[k];
       if(v!==undefined&&v!==null&&v!=="")$(k).value=v;
    });
    if(d.tls_check!==undefined)$("tls_check").checked=d.tls_check!=="0";
    if(d.route_check!==undefined)$("route_check").checked=d.route_check!=="0";
    if(d.ipv6!==undefined)$("ipv6").checked=d.ipv6!=="0"&&d.ipv6!==false;
    $("srcHost").textContent=$("bench_host").value||"speed.cloudflare.com";
  }).catch(e=>{});
}
function exportF(fmt){
  const u="/api/export?fmt="+fmt+"&"+tableParams();
  fetch(u).then(r=>r.blob()).then(b=>{
    const a=document.createElement("a");a.href=URL.createObjectURL(b);
    a.download=fmt==="csv"?"cf_optimizer.csv":"ADD.txt";
    document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a);a.remove()},400);
  });
}

function renderLog(entries){
  const box=$("logbox"); if(!box)return;
  const tsStr=ts=>{const dt=new Date(ts*1000);
    return ("0"+dt.getHours()).slice(-2)+":"+("0"+dt.getMinutes()).slice(-2)+":"+("0"+dt.getSeconds()).slice(-2)};
  let changed=false;
  if(!(entries&&entries.length)){ if(box.childElementCount!==1){box.innerHTML=
    '<div class="logline"><span class="t">--:--:--</span><span class="m">等待事件...</span></div>'} return; }
  const n=box.childElementCount;
  if(n!==entries.length)changed=true;
  else for(let i=0;i<n;i++){
    const lt=box.children[i].querySelector(".t");
    if(!lt||lt.textContent!==tsStr(entries[i][0])){changed=true;break;}
  }
  if(!changed&&box.dataset.ver===$("ver").textContent&&n===entries.length)return;
  box.dataset.ver=$("ver").textContent;
  const nearBottom=box.scrollTop+box.clientHeight>=box.scrollHeight-4;
  box.innerHTML="";
  entries.forEach(e=>{
    const msg=String(e[1]||""), dt=new Date(e[0]*1000);
    const pad=("0"+dt.getHours()).slice(-2)+":"+("0"+dt.getMinutes()).slice(-2)+":"+("0"+dt.getSeconds()).slice(-2);
    const cls=msg.startsWith("开始")?"ok":(msg.includes("错误")||msg.includes("异常")?"err":"");
    const d=document.createElement("div"); d.className="logline "+(cls||"m");
    d.innerHTML='<span class="t">'+pad+'</span><span class="m">'+esc(msg)+'</span>';
    box.appendChild(d);
  });
  if(nearBottom)box.scrollTop=box.scrollHeight;
}

async function poll(){
  try{
    const st=await (await fetch("/api/status")).json();
    $("dbpath").textContent=st.db||""; $("ver").textContent=st.version||"?";
    const pill=$("pill");
    if(st.running){pill.className="pill run";pill.textContent="扫描中 · 第"+st.round+"轮 · 本轮达标 "+st.last_ok;
      $("startBtn").disabled=true;$("stopBtn").disabled=false;}
    else{pill.className=st.msg.startsWith("错误")?"pill stop":"pill idle";
      pill.textContent=st.msg;$("startBtn").disabled=false;$("stopBtn").disabled=true;}
    const pf=$("progFill"), pl=$("progLabel");
    if(st.running&&st.total>0){
      const pct=Math.min(100,Math.round(st.probed/st.total*100));
      pf.style.width=(pct||0.6)+"%";
      pl.textContent=(pct||0)+"% · 第"+(st.round+1)+"轮 已探测 "+st.probed+" / "+st.total+
        " · 本轮达标 "+st.ok_now;
    }else if(st.running){pf.style.width="3%";pl.textContent="第"+(st.round+1)+"轮 准备中(发现IP/构造地址池)...";}
    else{pf.style.width="0";pl.textContent="当前未在扫描";}
    renderLog(st.log||[]);
    const s=await (await fetch("/api/stats")).json();
    STATS=s;
    countTo("st_total",s.total,true);
    countTo("st_alive",s.alive,true);
    countTo("st_verified",s.verified,true);
    countTo("st_bw",s.withbw,true);
    countTo("st_avglat",s.avglat,false);
    $("st_maxbw").textContent=fmt(s.maxbw);
    countTo("st_minlat",s.minlat,false);
    countTo("st_cov",s.coverage,false,"%");
    $("st_route").textContent=s.premium!=null?fmt(s.premium):"-";
    barChart("ch_colo",s.colos.slice(0,12),"#a78bfa");
    barChart("ch_country",s.countries.slice(0,12),"#3b82f6");
    histChart("ch_lat",s.lat.labels,s.lat.data,"#f59e0b");
    histChart("ch_bw",s.bw.labels,s.bw.data,"#22c55e");
    barChart("ch_route",s.routes||[],"#22c55e");
  }catch(e){}
  setTimeout(poll,2000);
}
const CNT={};
function countTo(id,val,fmtK,sfx){
  const el=$(id); if(!el||val==null)return;
  const from=CNT[id]!=null?CNT[id]:val;
  CNT[id]=val;
  if(from===val){el.textContent=(fmtK?Math.round(val).toLocaleString():String(val))+(sfx||"");return}
  const t0=performance.now(),dur=600;
  function tick(t){
    const k=Math.min(1,(t-t0)/dur),e=1-Math.pow(1-k,3);
    const cur=from+(val-from)*e;
    el.textContent=(fmtK?Math.round(cur).toLocaleString():cur.toFixed(1))+(sfx||"");
    if(k<1)requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}
let STATS=null;
function statTipSetup(){
  const map={
    st_total:{t:"已测试IP",c:"var(--acc)",rows:s=>[["总发现",s.total,"#fff"],["覆盖率",s.coverage+"%","#22c55e"]]},
    st_alive:{t:"存活IP",c:"var(--acc2)",rows:s=>{const dead=s.total-s.alive;return [["当前存活",s.alive,"#22c55e"],["不可用",dead,"#ef4444"],["存活率",s.total?Math.round(s.alive/s.total*100)+"%":"-","#fff"]]}},
    st_verified:{t:"已验证地区",c:"var(--purp)",rows:s=>[["已验证",s.verified,"#8b5cf6"],["已测试",s.total,"#fff"]]},
    st_bw:{t:"有带宽数据",c:"var(--acc)",rows:s=>[["有带宽",s.withbw,"#22c55e"],["已测试",s.total,"#fff"],["占比",s.total?Math.round(s.withbw/s.total*100)+"%":"-","#fff"]]},
    st_avglat:{t:"平均延迟",c:"var(--warn)",rows:s=>[["平均值",s.avglat??"-","#f59e0b"],["最低",s.minlat??"-","#fff"]]},
    st_maxbw:{t:"最高带宽",c:"var(--acc)",rows:s=>[["最近最高",s.maxbw??"-","#fff"],["历史最高",s.bwbest??"-","#22c55e"]]},
    st_minlat:{t:"最低延迟",c:"var(--warn)",rows:s=>[["最低",s.minlat??"-","#fff"],["平均",s.avglat??"-","#f59e0b"]]},
    st_cov:{t:"覆盖率",rows:s=>[["覆盖",s.coverage+"%","#fff"],["已发现",s.total,"#22c55e"]]},
    st_route:{t:"精品线路",c:"var(--acc2)",rows:s=>{const rts=(s.routes||[]).slice(0,5);
      const base=[["已测线路",s.route_done??0,"#fff"],["其中精品",s.premium??0,"#22c55e"]];
      if(!rts.length)return base;
      return base.concat([["分布"]], rts.map(r=>[r.name, r.count, r.premium?"#22c55e":"#8b98a5"]));}
    }
  };
  Object.entries(map).forEach(([id,cfg])=>{
    const el=$(id); if(!el)return;
    el.addEventListener("mouseenter",()=>{
      if(!STATS)return;
      const TIP=$("chartTip");
      TIP.querySelector(".t-title").textContent=cfg.t;
      TIP.querySelector(".t-title").style.borderLeftColor=cfg.c;
      TIP.querySelector(".t-body").innerHTML=cfg.rows(STATS).map(r=>
        `<div class="t-row">${r.length>1&&r[1]!==undefined?`<span class="k">${esc(r[0])}</span><span class="v" style="color:${r[2]||"#fff"}">${esc(r[1])}</span>`:`<span class="k sec">${esc(r[0])}</span>`}</div>`
      ).join("");
      TIP.classList.add("show");
      const r=el.getBoundingClientRect(),nw=TIP.offsetWidth,nh=TIP.offsetHeight;
      let lx=r.left+r.width/2,ty=r.top-nh-10;
      if(lx+nw>innerWidth-8)lx=innerWidth-nw-8;
      if(lx<8)lx=8;
      if(ty<8)ty=r.bottom+10;
      TIP.style.left=lx+"px";TIP.style.top=ty+"px";
      TIP.style.transform="translate(0,0)";
    });
    el.addEventListener("mouseleave",()=>{$("chartTip").classList.remove("show")});
  });
}
function bwTipSetup(){
  const TIP=$("chartTip");
  document.addEventListener("mouseover",e=>{
    const bw=e.target.closest&&e.target.closest(".bw");
    if(!bw||!bw.dataset.bw){
      if(e.target.closest&&e.target.closest(".stat"))return;
      if(e.target.closest&&e.target.closest(".route[data-cls]"))return;
      if(TIP._hideTmr)clearTimeout(TIP._hideTmr);
      TIP._hideTmr=setTimeout(()=>TIP.classList.remove("show"),60);
      return;
    }
    if(bw.dataset.bw==="none")return;
    if(TIP._hideTmr){clearTimeout(TIP._hideTmr);TIP._hideTmr=null;}
    const d=JSON.parse(bw.dataset.bw);
    const diff=(d.best!=="—"&&d.best!==d.bw)?Math.round(d.bw-d.best):null;
    TIP.querySelector(".t-title").textContent="带宽详情";
    TIP.querySelector(".t-title").style.borderLeftColor="var(--acc2)";
    TIP.querySelector(".t-body").innerHTML=
      '<div class="t-row"><span class="k">当前带宽</span><span class="v">'+esc(d.bw)+' Mbps</span></div>'+
      '<div class="t-row"><span class="k">历史最高</span><span class="v">'+esc(d.best)+' Mbps</span></div>'+
      (diff?'<div class="t-row"><span class="k">较最高</span><span class="v" style="color:'+(diff<0?'var(--err)':'var(--ok)')+'">'+(diff>0?'+':'')+diff+' Mbps</span></div>':'')+
      '<div class="t-row"><span class="k">最近测于</span><span class="v">'+esc(d.lastAt)+'</span></div>'+
      '<div class="t-row"><span class="k">延迟</span><span class="v">'+esc(d.lat)+'</span></div>'+
      '<div class="t-row"><span class="k">存活/失败</span><span class="v">'+esc(d.ok)+' / '+esc(d.fail)+'</span></div>';
    TIP.classList.add("show");
    const nw=TIP.offsetWidth,nh=TIP.offsetHeight;
    let lx=e.clientX+14,ty=e.clientY+12;
    if(lx+nw>innerWidth-8)lx=e.clientX-nw-14;
    if(ty+nh>innerHeight-8)ty=e.clientY-nh-12;
    TIP.style.left=lx+"px";TIP.style.top=ty+"px";
    TIP.style.transform="translate(0,0)";
  });
}
function routeTipSetup(){
  const TIP=$("chartTip");
  document.addEventListener("mouseover",e=>{
    const rt=e.target.closest&&e.target.closest(".route[data-cls]");
    if(!rt){
      if(e.target.closest&&(e.target.closest(".stat")||e.target.closest(".bw[data-bw]")))return;
      if(TIP._hideTmr)clearTimeout(TIP._hideTmr);
      TIP._hideTmr=setTimeout(()=>TIP.classList.remove("show"),60);
      return;
    }
    if(TIP._hideTmr){clearTimeout(TIP._hideTmr);TIP._hideTmr=null;}
    const rcl=rt.dataset.cls, label=RCL[rcl]||rcl||"线路";
    const hops=rt.dataset.hk?HOPS[rt.dataset.hk]:null;
    const rc=rcl==="premium"?"#22c55e":rcl==="mixed"?"#f59e0b":"#fff";
    TIP.querySelector(".t-title").textContent="线路详情";
    TIP.querySelector(".t-title").style.borderLeftColor=rcl==="premium"?"#22c55e":"var(--acc2)";
    let body='<div class="t-row"><span class="k">线路分类</span><span class="v" style="color:'+rc+'">'+esc(label)+'</span></div>';
    if(hops&&hops.length){
      body+='<div class="t-row"><span class="k sec">Traceroute 逐跳</span></div>';
      hops.forEach(h=>{
        const ip=h.ip||"*";
        const tag=h.asn?("AS"+h.asn+" "+esc(h.name||"")):esc(h.name||"");
        const tm=h.time!=null?(h.time+"ms"):"-";
        const tgt=h.target?" ✓目标":"";
        body+='<div class="t-row"><span class="k">'+esc(h.n+". "+ip)+'</span>'+
          '<span class="v" style="color:'+(h.target?"#22c55e":h.time!=null?"#fff":"#5b6570")+'">'+tag+' '+tm+tgt+'</span></div>';
      });
    }else{
      body+='<div class="t-row"><span class="k sec">逐跳数据缺失(重新测线路后可见)</span></div>';
    }
    body+='<div class="t-row"><span class="k sec">跨境AS</span></div><div class="t-row"><span class="k">识别结果</span>'+
      '<span class="v" style="color:#9aa6b0">'+esc((rt.closest("tr")&&rt.closest("tr").dataset.aslist)||"—")+'</span></div>';
    TIP.querySelector(".t-body").innerHTML=body;
    TIP.classList.add("show");
    const nw=TIP.offsetWidth,nh=TIP.offsetHeight;
    let lx=e.clientX+14,ty=e.clientY+12;
    if(lx+nw>innerWidth-8)lx=e.clientX-nw-14;
    if(ty+nh>innerHeight-8)ty=e.clientY-nh-12;
    TIP.style.left=lx+"px";TIP.style.top=ty+"px";
    TIP.style.transform="translate(0,0)";
  });
}
function scrollGuardSetup(){
  const tw=$("tabWrap");
  let t=null;
  tw.addEventListener("scroll",()=>{
    tw.classList.add("scrolling");
    clearTimeout(t);
    t=setTimeout(()=>tw.classList.remove("scrolling"),150);
  },{passive:true});
}
["f_region","f_minbw","f_maxlat","f_q","f_port"].forEach(id=>{
  $(id).addEventListener("input",()=>{OFFSET=0;loadTable()});
});
["f_hasbw","f_premium","f_v6"].forEach(id=>{
  $(id).addEventListener("change",()=>{OFFSET=0;loadTable()});
});
loadSet();
$("bench_host").addEventListener("input",()=>{$("srcHost").textContent=$("bench_host").value||"speed.cloudflare.com"});
loadTable();statTipSetup();bwTipSetup();routeTipSetup();scrollGuardSetup();poll();
</script>
<div id="toast"></div>
</body>
</html>
"""


def lan_ips():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ips.append(info[4][0])
    except Exception:
        pass
    seen = set()
    out = []
    for ip in ips:
        if ip not in seen and not ip.startswith("127."):
            seen.add(ip)
            out.append(ip)
    return out


BASE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PIDFILE = os.path.join(BASE, "cf_web.pid")
DEFAULT_LOGFILE = os.path.join(BASE, "cf_web.log")


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def get_pid(pidfile):
    try:
        with open(pidfile) as fh:
            pid = int(fh.read().strip())
        return pid if pid_alive(pid) else None
    except Exception:
        return None


def daemon_main(args):
    """启动为后台服务: 脱离终端, 关闭会话不退出, 可 --stop 停止"""
    import subprocess

    existing = get_pid(args.pidfile)
    if existing:
        print(f"已在运行 (PID {existing}), 无需重复启动")
        return
    log = open(args.log, "a", encoding="utf-8", buffering=1)
    cmd = [sys.executable, os.path.abspath(__file__),
           "--db", args.db, "--host", args.host, "--port", str(args.port),
           "--log", args.log, "--pidfile", args.pidfile, "--no-browser", "--child"]
    proc = subprocess.Popen(cmd, start_new_session=True, stdout=log, stderr=log, stdin=subprocess.DEVNULL)
    time.sleep(1.5)
    if proc.poll() is not None:
        print("后台启动失败, 最近日志:")
        try:
            print(open(args.log).read()[-800:])
        except Exception:
            pass
        sys.exit(1)
    with open(args.pidfile, "w") as fh:
        fh.write(str(proc.pid))
    port = args.port
    print(f"已后台启动 (PID {proc.pid}), 日志: {args.log}")
    print(f"  本机打开: http://127.0.0.1:{port}/")
    for ip in lan_ips():
        print(f"  局域网打开: http://{ip}:{port}/")
    print("后台服务与会话无关, 关终端也不会退出")
    print("停止: python3 cf_web.py --stop | 状态: python3 cf_web.py --status")


def daemon_stop(pidfile):
    pid = get_pid(pidfile)
    if not pid:
        print("没有正在运行的服务")
        return
    try:
        os.kill(pid, 2 if sys.platform != "win32" else 0)  # SIGINT 优雅退出
    except ProcessLookupError:
        pass
    for _ in range(50):  # 最多等 ~5s
        if not pid_alive(pid):
            break
        time.sleep(0.1)
    for p in (pidfile,):
        try:
            os.remove(p)
        except OSError:
            pass
    if pid_alive(pid):
        print(f"进程 {pid} 未能在5秒内退出, 已强制结束")
        try:
            os.kill(pid, 9)
        except OSError:
            pass
    else:
        print(f"已停止服务 (原PID {pid})")


def daemon_status(pidfile):
    pid = get_pid(pidfile)
    if pid:
        print(f"运行中 (PID {pid})")
    else:
        print("未在运行")


def serve_forever(args, host, port):
    if not os.path.exists(args.db):
        conn = cf_db.open_db(args.db)
        conn.close()
    try:
        srv = ThreadingHTTPServer((host, port), Handler)
    except OSError as e:
        print(f"启动失败: {e}", file=sys.stderr)
        print(f"端口 {port} 可能已被占用, 换端口: python3 cf_web.py --port 9000", file=sys.stderr)
        return False
    port = srv.server_address[1]
    local = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    print(f"CF 优选IP 扫描管理台已启动  数据库: {os.path.abspath(args.db)}", flush=True)
    print(f"  本机打开: http://{local}:{port}/", flush=True)
    for ip in lan_ips():
        print(f"  局域网打开: http://{ip}:{port}/", flush=True)
    if not args.no_browser:
        webbrowser.open(f"http://{local}:{port}/")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        STATE["stop"].set()
        srv.server_close()
    return True


def child_main(args):
    """后台服务的子进程: 崩溃自动重启, 收到 SIGTERM/SIGINT 才退出"""
    import signal

    def _sig(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    try:
        while True:
            ok = serve_forever(args, args.host, args.port)
            if not ok:
                sys.exit(1)
            try:
                time.sleep(3)
            except BaseException:
                pass
    finally:
        try:
            os.remove(args.pidfile)
        except OSError:
            pass


def main():
    global DB
    ap = argparse.ArgumentParser(description="CF 优选IP 扫描管理台 (Web图形界面, 数据库驱动)")
    ap.add_argument("--db", default="cf_ips.db", help="SQLite 数据库路径(默认 cf_ips.db)")
    ap.add_argument("--host", default="0.0.0.0",
                    help="监听地址(默认 0.0.0.0, 本机和其他设备都能开); 仅本机可用 127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--daemon", action="store_true", help="后台服务模式(脱离终端运行, 关闭会话不退出)")
    ap.add_argument("--stop", action="store_true", help="停止后台服务")
    ap.add_argument("--status", action="store_true", help="查看后台服务状态")
    ap.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--pidfile", default=DEFAULT_PIDFILE)
    ap.add_argument("--log", default=DEFAULT_LOGFILE)
    args = ap.parse_args()
    DB = args.db
    if args.stop:
        daemon_stop(args.pidfile)
        return
    if args.status:
        daemon_status(args.pidfile)
        return
    if args.child:
        child_main(args)
        return
    if args.daemon:
        daemon_main(args)
        return
    if not serve_forever(args, args.host, args.port):
        sys.exit(1)


DB = None


if __name__ == "__main__":
    main()