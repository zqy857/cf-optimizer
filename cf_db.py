#!/usr/bin/env python3
"""
CF 优选IP 扫描数据库 (常驻稳定扫描器) - 增强版

持续扫描, 所有 IP 及其延迟/带宽/机房/国家累积进 SQLite 数据库, 可断点续扫, 按需导出。
完全自包含, 无第三方依赖, Python 3.8+ 标准库即可。

增强能力:
  * 多端口探测   --ports 443,2053,2083,8443  自动找到该IP可用端口(部分IP并非全端口开放)
  * TLS握手二次确认  TCP能连≠真CF边缘; 握手探测(SNI=cloudflare.com)通过后才算"存活"
  * 优秀/24邻域加权采样  --exploit 命中过好IP的C段优先抽, 达标命中率远高于纯随机
  * 冷却期自动复测  --cooldown 失败的IP/旧IP冷却后自动重新探测, 不再永久拉黑
  * 每轮自动复核  --recheck 复核库内旧IP(存活刷新+失败重试), 名单永新

核心流程(按周期循环):
  1. 发现: 邻域加权+全池随机抽 --count 个候选, 多端口并发拨号+TLS确认测延迟
  2. 验证: 对新达标的候选做地区识别(colo/loc), 预算内再实测带宽
  3. 沉淀: 结果实时写入数据库(可随时 Ctrl+C 安全退出, 下次接着扫)
  4. 复核: 每轮对库中旧IP重新探测, 剔除失效项, 保证名单时效

用法示例:
  python3 cf_db.py                      # 默认连续扫描, 每轮抽 5000
  python3 cf_db.py --operator ct        # 电信优选段
  python3 cf_db.py --once               # 只跑一轮就退出(便于测试/限量)
  python3 cf_db.py --cycles 50 --gap 20 # 跑50轮, 轮间歇20秒
  python3 cf_db.py --ports 443,8443     # 只测 443 和 8443
  python3 cf_db.py --no-tls-check       # 关闭TLS二次确认(更快但质量略低)
  python3 cf_db.py --exploit 0.8        # 更多向优质C段倾斜
  python3 cf_db.py --reverify           # 只复核库内现有优质IP, 不发现新IP
  python3 cf_db.py --stats              # 查看库统计/覆盖率/达标率
  python3 cf_db.py --export top.txt     # 导出当前最优 N 条 (--top N, 可加 --region)
  python3 cf_db.py --seed myadd.txt     # 把现有优选名单导入数据库作为种子

数据库: cf_ips.db (可 --db 指定)
"""
import argparse
import asyncio
import ipaddress
import os
import queue
import random
import socket
import sqlite3
import ssl
import sys
import threading
import time
import types
import urllib.parse

OFFICIAL_V4_URL = "https://www.cloudflare.com/ips-v4"
FALLBACK_RANGES = [
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15",
    "188.114.96.0/20", "173.245.48.0/20", "198.41.128.0/17", "141.101.64.0/18",
    "190.93.240.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "131.0.72.0/22", "108.162.192.0/18", "103.28.248.0/22", "192.0.77.0/24",
]
OPERATOR_URLS = {
    "cf": "https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt",
    "ct": "https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/ct.txt",
    "cu": "https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/cu.txt",
    "cmcc": "https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/cmcc.txt",
}
OPERATOR_NAMES = {"cf": "CF官方优选", "ct": "电信优选", "cu": "联通优选", "cmcc": "移动优选"}
TRACE_HOST = "cloudflare.com"
SPEED_HOST = "speed.cloudflare.com"
PORTS_DEFAULT = [443, 2053, 2083, 8443]

SCHEMA = """
CREATE TABLE IF NOT EXISTS ips(
  ip TEXT PRIMARY KEY,
  port INTEGER DEFAULT 443,
  colo TEXT,
  loc TEXT,
  latency_ms REAL,
  bandwidth_mbps REAL,
  bw_last_mbps REAL,
  bw_last_at REAL,
  tested_at REAL,
  verified_at REAL,
  first_seen REAL,
  ok_count INTEGER DEFAULT 0,
  fail_count INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ips_score ON ips(latency_ms, verified_at, bandwidth_mbps);
CREATE INDEX IF NOT EXISTS idx_ips_tested ON ips(tested_at);
"""

MIGRATIONS = [
    "ALTER TABLE ips ADD COLUMN bw_last_mbps REAL",
    "ALTER TABLE ips ADD COLUMN bw_last_at REAL",
]

N24_SQL = ("substr(ip,1,"
           "instr(ip,'.')+instr(substr(ip,instr(ip,'.')+1),'.')"
           "+instr(substr(ip,instr(ip,'.')+instr(substr(ip,instr(ip,'.')+1),'.')+1),'.')-1)")


def ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def open_db(path):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    have = {r[1] for r in conn.execute("PRAGMA table_info(ips)").fetchall()}
    for m in MIGRATIONS:
        col = m.split(" ADD COLUMN ")[1].split(" ")[0]
        if col not in have:
            conn.execute(m)
    conn.commit()
    return conn


def load_known(conn):
    rows = conn.execute("SELECT ip, tested_at FROM ips").fetchall()
    return {r[0]: r[1] or 0 for r in rows}


async def fetch(url, timeout=10):
    loop = asyncio.get_running_loop()
    _, writer = await asyncio.wait_for(asyncio.open_connection(
        url.host, url.port or 443, ssl=True, server_hostname=url.host), timeout)
    try:
        writer.write("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: cf-optimizer\r\nConnection: close\r\n\r\n".format(
            path=url.path or "/", host=url.host).encode())
        await writer.drain()
        data = b""
        while True:
            chunk = await asyncio.wait_for(writer.wait_for_read, 1)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        writer.close()
        await writer.wait_closed()


def upsert(conn, rec):
    if rec.get("ip") is None:
        return
    ok = 1 if rec.get("ok") else 0
    fail = 0 if ok else 1
    conn.execute(
        """
        INSERT INTO ips(ip,port,colo,loc,latency_ms,bandwidth_mbps,
                        bw_last_mbps,bw_last_at,
                        tested_at,verified_at,first_seen,ok_count,fail_count)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
          port=CASE WHEN excluded.latency_ms IS NOT NULL THEN excluded.port ELSE port END,
          latency_ms=CASE WHEN excluded.latency_ms IS NOT NULL THEN excluded.latency_ms ELSE latency_ms END,
          tested_at=excluded.tested_at,
          colo=COALESCE(excluded.colo,colo),
          loc=COALESCE(excluded.loc,loc),
          verified_at=COALESCE(excluded.verified_at,verified_at),
          bandwidth_mbps=CASE WHEN excluded.bandwidth_mbps IS NOT NULL AND (bandwidth_mbps IS NULL OR excluded.bandwidth_mbps > bandwidth_mbps)
                              THEN excluded.bandwidth_mbps ELSE bandwidth_mbps END,
          bw_last_mbps=CASE WHEN excluded.bw_last_mbps IS NOT NULL THEN excluded.bw_last_mbps ELSE bw_last_mbps END,
          bw_last_at=CASE WHEN excluded.bw_last_at IS NOT NULL THEN excluded.bw_last_at ELSE bw_last_at END,
          ok_count=ok_count+excluded.ok_count,
          fail_count=fail_count+excluded.fail_count
        """,
        (
            rec.get("ip"), rec.get("port") or 443,
            rec.get("colo"), rec.get("loc"),
            rec.get("latency"), rec.get("bandwidth"),
            rec.get("bandwidth"), rec.get("tested_at") if rec.get("bandwidth") is not None else None,
            rec.get("tested_at") or time.time(),
            rec.get("verified_at"), rec.get("first_seen") or time.time(),
            ok, fail,
        ),
    )


def fetch_networks(operator, port):
    nets = []
    label = "官方地址池"
    if operator:
        label = OPERATOR_NAMES.get(operator, operator)
        url = urllib.parse.urlparse(OPERATOR_URLS[operator])
        try:
            raw = asyncio.run(fetch(url))
            for line in raw.decode("utf-8", "replace").splitlines():
                line = line.strip().split("#")[0].strip()
                if "/" in line:
                    try:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        continue
        except Exception:
            nets = []
    if not nets:
        try:
            raw = asyncio.run(fetch(urllib.parse.urlparse(OFFICIAL_V4_URL)))
            for l in raw.decode().splitlines():
                l = l.strip()
                if "/" in l:
                    nets.append(ipaddress.ip_network(l, strict=False))
        except Exception:
            for r in FALLBACK_RANGES:
                nets.append(ipaddress.ip_network(r))
    return nets, label


def net_total(nets):
    return sum(1 << (32 - n.prefixlen) for n in nets)


def random_ip_in_net(net):
    base = int(net.network_address)
    size = 1 << (32 - net.prefixlen)
    return ipaddress.ip_address(base + random.randrange(size))


def net24(ip):
    return ".".join(ip.split(".")[:3])


def fetch_hot24(path, limit=200, raw=False):
    try:
        conn = sqlite3.connect(path)
        q = (f"SELECT {N24_SQL} AS n, SUM(ok_count) g, SUM(fail_count) f, COUNT(*) c "
             f"FROM ips GROUP BY n ORDER BY (SUM(ok_count)-SUM(fail_count)) DESC, g DESC LIMIT ?")
        rows = conn.execute(q, (limit,)).fetchall()
        conn.close()
    except Exception:
        return []
    hot = [(n, (g or 0), (f or 0), c) for n, g, f, c in rows]
    if raw:
        return hot
    return [(n, max(1, g)) for n, g, f, c in hot if g and g >= 1]


def fetch_recheck(path, limit, cooldown):
    try:
        conn = sqlite3.connect(path)
        cutoff = time.time() - cooldown
        rows = conn.execute("SELECT ip, port FROM ips WHERE tested_at < ? AND ok_count>0 "
                            "ORDER BY tested_at ASC LIMIT ?", (cutoff, limit)).fetchall()
        out = list(rows)
        if len(out) < limit:
            rows2 = conn.execute("SELECT ip, port FROM ips WHERE tested_at < ? AND ok_count=0 "
                                 "ORDER BY tested_at ASC LIMIT ?", (cutoff, limit - len(out))).fetchall()
            out.extend(rows2)
        conn.close()
        return out
    except Exception:
        return []


def fetch_backfill(path, limit, cooldown):
    try:
        conn = sqlite3.connect(path)
        cutoff = time.time() - cooldown
        rows = conn.execute(
            "SELECT ip, port, latency_ms, ok_count FROM ips "
            "WHERE tested_at < ? AND ok_count>0 AND (colo IS NULL OR loc IS NULL) "
            "ORDER BY tested_at ASC LIMIT ?", (cutoff, limit)).fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def discover(nets, hot24, count, ports, known, cooldown, exploit_frac):
    now = time.time()

    def eligible(ip):
        t = known.get(ip)
        return t is None or (now - t) >= cooldown

    def take_ip(net_or_pre, tries_cap, skip_known):
        if isinstance(net_or_pre, str):
            base = int(ipaddress.ip_address(net_or_pre + ".0"))
            max_tries = min(tries_cap, 256)
            for _ in range(max_tries):
                ip = str(ipaddress.ip_address(base + random.randrange(256)))
                if ip in known and skip_known:
                    continue
                if not eligible(ip):
                    continue
                return ip
            return None
        max_tries = min(tries_cap, 1 << (32 - net_or_pre.prefixlen))
        for _ in range(max_tries):
            ip = str(random_ip_in_net(net_or_pre))
            if ip in known and skip_known:
                continue
            if not eligible(ip):
                continue
            return ip
        return None

    cands = []
    n_exploit = min(count, int(count * exploit_frac)) if hot24 else 0
    exhausted = set()

    for _ in range(n_exploit):
        if not hot24:
            break
        weights = [w for _, w in hot24]
        total = sum(weights)
        if total <= 0:
            break
        pre = random.choices([p for p, _ in hot24], weights=weights)[0]
        if pre in exhausted:
            continue
        ip = take_ip(pre, count, skip_known=False)
        if ip is None:
            exhausted.add(pre)
            continue
        known[ip] = now
        cands.append((ip, tuple(ports)))

    for _ in range(count - n_exploit):
        if not nets:
            break
        net = random.choice(nets)
        if net in exhausted:
            continue
        ip = take_ip(net, count * 8, skip_known=True)
        if ip is None:
            exhausted.add(net)
            continue
        known[ip] = now
        cands.append((ip, tuple(ports)))

    return cands


async def tcp_latency(ip, port, timeout):
    begin = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except Exception:
        return None
    elapsed = (time.perf_counter() - begin) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return elapsed


async def tls_probe(ip, port, timeout):
    begin = time.perf_counter()
    ctx = ssl_ctx()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=TRACE_HOST), timeout)
    except Exception:
        return None
    elapsed = (time.perf_counter() - begin) * 1000
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return elapsed


async def probe_ip(ip, ports, args):
    for p in ports:
        tcp = await tcp_latency(ip, p, args.ping_timeout)
        if tcp is None:
            continue
        if args.tls_check:
            tls = await tls_probe(ip, p, min(args.ping_timeout * 2, 4.0))
            if tls is None:
                return ip, None, None, False
        return ip, p, tcp, True
    return ip, None, None, False


async def tls_request(host, path, ip, port, timeout=6):
    ctx = ssl_ctx()
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host), timeout)
        writer.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: cf-optimizer\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        data = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def identify(ip, port, args, latency=None):
    timeout = min(10, max(4, (latency or 0) / 1000 * 3))
    data = b""
    for _ in range(2):
        try:
            data = await tls_request(TRACE_HOST, "/cdn-cgi/trace", ip, port, timeout=timeout)
        except Exception:
            data = b""
        if data:
            break
        await asyncio.sleep(0.3)
    text = data.decode("utf-8", "replace")
    colo = None
    loc = None
    for line in text.splitlines():
        if line.startswith("colo="):
            colo = line.split("=", 1)[1].strip().upper()
        elif line.startswith("loc="):
            loc = line.split("=", 1)[1].strip().upper()
    if not colo:
        return None
    return {"ip": ip, "port": port, "latency": latency or 0,
            "bandwidth": None, "colo": colo or "UNK", "loc": loc or "UNK"}


async def bench_bandwidth(ip, port, args, parallel=4):
    parallel = max(1, getattr(args, "bench_parallel", parallel) or parallel)
    size = max(1_000_000, min(args.bench_size, 80_000_000))
    host = getattr(args, "bench_host", SPEED_HOST) or SPEED_HOST
    timeout = args.bench_timeout
    begin = time.perf_counter()
    deadline = begin + timeout
    ctx = ssl_ctx()

    async def one():
        if time.perf_counter() >= deadline:
            return 0
        n = 0
        reader = writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host),
                min(timeout, 5))
            try:
                sock = writer.get_extra_info("socket")
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 << 20)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            writer.write(f"GET /__down?bytes={size} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: cf-optimizer\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
            while True:
                rem = deadline - time.perf_counter()
                if rem <= 0:
                    break
                chunk = await asyncio.wait_for(reader.read(65536), rem)
                if not chunk:
                    break
                n += len(chunk)
                if n >= size:
                    break
        except asyncio.TimeoutError:
            pass
        except Exception:
            return 0
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        return n

    bodies = await asyncio.gather(*(one() for _ in range(parallel)), return_exceptions=True)
    total = 0
    for b in bodies:
        if isinstance(b, int):
            total += b
    if total < 100_000:
        return None
    elapsed = time.perf_counter() - begin
    if elapsed <= 0:
        return None
    mbps = (total * 8) / (elapsed * 1_000_000)
    return round(mbps, 2)


async def run_session(nets, known, q, args, stop):
    sem = asyncio.Semaphore(args.concurrency)
    max_lat = args.max_latency
    ports = list(args.ports)
    now = time.time()

    async def probe(ip, ports_seq):
        async with sem:
            return await probe_ip(ip, ports_seq, args)

    async def run_tasks(coros):
        """并发运行协程集合; 保持结果顺序; 每0.3s检查stop, 停止则取消剩余快速退出"""
        tasks = [asyncio.create_task(c) for c in coros]
        out = [None] * len(tasks)
        idx_of = {id(t): i for i, t in enumerate(tasks)}
        pending = set(tasks)
        while pending:
            if stop.is_set():
                for t in pending:
                    t.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                break
            done, pending = await asyncio.wait(
                list(pending), timeout=0.3, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                idx = idx_of[id(t)]
                if not t.cancelled():
                    try:
                        out[idx] = t.result()
                    except Exception:
                        out[idx] = None
        return out

    async def verify_one(ip, p, lat, do_bench):
        args_ns = types.SimpleNamespace(bench_size=args.bench_size,
                                        bench_timeout=args.bench_timeout,
                                        bench_parallel=args.bench_parallel,
                                        bench_host=getattr(args, "bench_host", SPEED_HOST))
        try:
            info = await identify(ip, p, args_ns, latency=lat)
        except Exception:
            info = None
        colo = loc = bw = None
        verified_at = None
        if info:
            colo, loc = info["colo"], info["loc"]
            verified_at = time.time()
            if do_bench:
                try:
                    bw = await bench_bandwidth(ip, p, args_ns)
                except Exception:
                    bw = None
        rec = {"type": "result", "ip": ip, "port": p, "ok": True,
               "latency": lat, "colo": colo, "loc": loc, "bandwidth": bw,
               "tested_at": time.time()}
        if verified_at:
            rec["verified_at"] = verified_at
        q.put(rec)

    async def verify_batch(pend):
        vsem = asyncio.Semaphore(min(8, len(pend)))

        async def v(ip, p, lat, idx):
            async with vsem:
                await verify_one(ip, p, lat, idx < args.bench)

        await run_tasks([v(ip, p, lat, i) for i, (ip, p, lat) in enumerate(pend)])

    async def discovery_cycle():
        hot24 = fetch_hot24(args.db) if args.exploit > 0 else []
        cands = discover(nets, hot24, args.count, ports, known, args.cooldown, args.exploit)
        backfill_ips = set()
        if args.recheck and not args.once:
            for ip, p in fetch_recheck(args.db, args.recheck, args.cooldown):
                if ip in known:
                    known[ip] = time.time()
                seq = [p] + [x for x in ports if x != p]
                cands.append((ip, tuple(seq)))
        if getattr(args, "backfill", 0) and not args.once:
            for ip, p, _, _ in fetch_backfill(args.db, args.backfill, args.cooldown):
                if ip in known:
                    known[ip] = time.time()
                backfill_ips.add(ip)
                seq = [p] + [x for x in ports if x != p]
                cands.append((ip, tuple(seq)))
        if not cands:
            return 0, []
        q.put({"type": "cycle_start", "total": len(cands)})
        results = [r for r in await run_tasks([probe(ip, ps) for ip, ps in cands]) if r]
        ok = 0
        alive_list = []
        n = time.time()
        for ip, p, lat, alive in results:
            if not ip:
                continue
            if alive and lat is not None and lat <= max_lat:
                ok += 1
                q.put({"type": "result", "ip": ip, "port": p, "ok": True,
                       "latency": lat, "tested_at": n})
                alive_list.append((ip, p, lat, ip in backfill_ips))
            else:
                q.put({"type": "result", "ip": ip, "port": p, "ok": False,
                       "latency": lat, "tested_at": n})
        alive_list.sort(key=lambda r: (0 if r[3] else 1, r[2]))
        pend = [(ip, p, lat) for ip, p, lat, _ in alive_list[: args.verify]]
        if args.bench > 0:
            try:
                conn_hb = sqlite3.connect(args.db)
                have_bw = {r[0] for r in conn_hb.execute("SELECT ip FROM ips WHERE bandwidth_mbps IS NOT NULL")}
                conn_hb.close()
            except Exception:
                have_bw = set()
            pend = ([x for x in pend if x[0] not in have_bw] + [x for x in pend if x[0] in have_bw])
        return ok, pend

    async def gap_sleep():
        waited = 0.0
        while waited < args.gap:
            if stop.is_set():
                return
            await asyncio.sleep(0.5)
            waited += 0.5

    if args.reverify:
        conn_rev = open_db(args.db)
        targets = conn_rev.execute(
            "SELECT ip, port FROM ips WHERE latency_ms IS NOT NULL AND colo IS NOT NULL AND loc IS NOT NULL "
            "ORDER BY latency_ms ASC LIMIT ?", (args.reverify,)).fetchall()
        conn_rev.close()
        for ip, p in targets:
            if stop.is_set():
                break
            lat = await tcp_latency(ip, p, args.ping_timeout)
            q.put({"type": "result", "ip": ip, "port": p, "ok": lat is not None,
                   "latency": lat, "tested_at": time.time()})
            await gap_sleep()
        return

    if args.once:
        ok, pend = await discovery_cycle()
        if pend:
            await verify_batch(pend)
        q.put({"type": "cycle_end", "ok": ok})
        return

    cycles = 0
    while not stop.is_set():
        if args.cycles and cycles >= args.cycles:
            break
        ok, pend = await discovery_cycle()
        if pend:
            await verify_batch(pend)
        q.put({"type": "cycle_end", "ok": ok})
        cycles += 1
        await gap_sleep()


def export_report(args):
    conn = open_db(args.db)
    region = getattr(args, "region", None)
    where = "latency_ms IS NOT NULL AND ok_count > 0"
    params = []
    if getattr(args, "verified_only", False):
        where += " AND colo IS NOT NULL AND loc IS NOT NULL"
    if region:
        keep = [r.strip().upper() for r in region.split(",")]
        ph = ",".join("?" for _ in keep)
        where += f" AND (colo IN ({ph}) OR loc IN ({ph}))"
        params.extend(keep)
        params.extend(keep)
    rows = conn.execute(
        f"SELECT ip, port, colo, loc, latency_ms, bandwidth_mbps FROM ips "
        f"WHERE {where} "
        f"ORDER BY (CASE WHEN bandwidth_mbps IS NULL THEN 0 ELSE bandwidth_mbps END) DESC, "
        f"latency_ms ASC LIMIT ?", params + [args.top if args.top else 100]).fetchall()
    conn.close()
    lines = []
    csv_lines = ["rank,ip,port,latency_ms,bandwidth_mbps,colo,loc"]
    for i, (ip, p, colo, loc, lat, bw) in enumerate(rows, 1):
        remark = f"{colo or 'UNK'}-{loc or 'UNK'}-{i}"
        lines.append(f"{ip}:{p}#{remark}")
        csv_lines.append(f"{i},{ip},{p},{lat or ''},{bw if bw is not None else ''},{colo or ''},{loc or ''}")
    mode = args.mode
    if mode == "txt":
        body = "\n".join(lines) + ("\n" if lines else "")
    else:
        body = "\n".join(csv_lines) + "\n"
    return body


def stats_report(args):
    conn = open_db(args.db)
    total = conn.execute("SELECT COUNT(*) FROM ips").fetchone()[0]
    ok = conn.execute("SELECT COUNT(*) FROM ips WHERE ok_count>0").fetchone()[0]
    verified = conn.execute("SELECT COUNT(*) FROM ips WHERE verified_at IS NOT NULL").fetchone()[0]
    unverified = conn.execute("SELECT COUNT(*) FROM ips WHERE ok_count>0 AND verified_at IS NULL").fetchone()[0]
    with_bw = conn.execute("SELECT COUNT(*) FROM ips WHERE bandwidth_mbps IS NOT NULL AND bandwidth_mbps>0").fetchone()[0]
    avg_lat = conn.execute("SELECT ROUND(AVG(latency_ms),1) FROM ips WHERE ok_count>0").fetchone()[0]
    rows = conn.execute(
        "SELECT colo, COUNT(*) FROM ips WHERE ok_count>0 GROUP BY colo ORDER BY COUNT(*) DESC LIMIT 10").fetchall()
    port_rows = conn.execute(
        "SELECT port, COUNT(*) FROM ips WHERE ok_count>0 GROUP BY port ORDER BY COUNT(*) DESC LIMIT 6").fetchall()
    conn.close()
    nets, label = fetch_networks(args.operator, args.port)
    cov = net_total(nets)
    out = [
        f"数据库: {os.path.abspath(args.db)}",
        f"覆盖源: {label}  地址总量约: {cov:,}",
        f"已测试IP: {total:,}  (覆盖率 {total / cov * 100 if cov else 0:.2f}%)",
        f"存活IP:  {ok:,}  已验证地区: {verified:,}  未识别地区: {unverified:,}  有带宽数据: {with_bw:,}",
        f"平均延迟(存活): {avg_lat}ms",
        f"常用端口: " + ", ".join(f"{p}:{c}" for p, c in port_rows),
        "机房分布(前10):",
    ]
    for colo, c in rows:
        out.append(f"  {colo}: {c}")
    return "\n".join(out)


def seed_db(args):
    conn = open_db(args.db)
    n = 0
    for path in [args.seed]:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                host = line.split("#")[0].strip()
                remark = line.split("#")[1] if "#" in line else ""
                port = args.port
                if ":" in host:
                    h, p = host.rsplit(":", 1)
                    if h and p.isdigit():
                        host, port = h, int(p)
                colo = loc = None
                up = remark.upper()
                for part in up.split("-"):
                    if len(part) == 3 and part.isalnum():
                        colo = part
                    elif len(part) == 2 and part.isalnum():
                        loc = part
                rec = {"ip": host, "port": port, "ok": True, "latency": 0,
                       "colo": colo, "loc": loc, "tested_at": time.time(),
                       "verified_at": time.time()}
                known = load_known(conn)
                if host in known:
                    continue
                upsert(conn, rec)
                conn.commit()
                n += 1
    conn.close()
    return f"已导入 {n} 个种子IP"


def main():
    ap = argparse.ArgumentParser(
        description="CF 优选IP 扫描数据库(增强版): 多端口+TLS确认+邻域加权+冷却复测, 所有IP累积进SQLite, 可导出 ADD.txt")
    ap.add_argument("--db", default="cf_ips.db", help="SQLite 数据库路径(默认 cf_ips.db)")
    ap.add_argument("--operator", choices=["cf", "ct", "cu", "cmcc"], default=None,
                    help="地址源: 官方/电信(ct)/联通(cu)/移动(cmcc)")
    ap.add_argument("--count", type=int, default=5000, help="每轮发现抽样数(默认 5000)")
    ap.add_argument("--verify", type=int, default=30, help="每轮验证地区预算(默认30)")
    ap.add_argument("--bench", type=int, default=40, help="每轮带宽测试预算(默认40)")
    ap.add_argument("--concurrency", type=int, default=400, help="并发拨号数")
    ap.add_argument("--ping-timeout", type=float, default=1.2)
    ap.add_argument("--max-latency", type=float, default=2000, help="延迟达标上限ms")
    ap.add_argument("--port", type=int, default=443, help="首选端口(优先级最高)")
    ap.add_argument("--ports", default=None,
                    help="探测端口列表, 逗号分隔, 默认 443,2053,2083,8443; 按顺序尝试直到一个可用")
    ap.add_argument("--tls-check", dest="tls_check", action="store_true", default=True,
                    help="TCP连通后用TLS握手(SNI cloudflare.com)二次确认, 过滤非CF/中间盒(默认开)")
    ap.add_argument("--no-tls-check", dest="tls_check", action="store_false",
                    help="关闭TLS二次确认(更快但可能收录伪CF IP)")
    ap.add_argument("--exploit", type=float, default=0.6,
                    help="每轮抽样中偏向优质/24邻域的比例 0~1 (默认0.6, 0=纯随机)")
    ap.add_argument("--cooldown", type=float, default=3600,
                    help="同一IP复测冷却秒数, 冷却期内不再测(默认3600)")
    ap.add_argument("--recheck", type=int, default=30,
                    help="每轮复核库内旧IP数量(存活刷新+失败重试, 默认30; 0=关闭)")
    ap.add_argument("--backfill", type=int, default=0,
                    help="每轮为'存活但缺地区(colo/loc)'的旧IP补全地区识别数量(默认0; GUI默认开启)")
    ap.add_argument("--bench-size", type=int, default=50_000_000)
    ap.add_argument("--bench-timeout", type=float, default=12)
    ap.add_argument("--bench-parallel", type=int, default=4)
    ap.add_argument("--cycles", type=int, default=0, help="扫描轮数限制, 0=无限")
    ap.add_argument("--gap", type=float, default=5, help="轮间间隔秒(默认5)")
    ap.add_argument("--once", action="store_true", help="只扫描一轮(发现+验证预算)后退出")
    ap.add_argument("--reverify", type=int, metavar="N", default=0,
                    help="复核模式: 重新探测库内现有最优的 N 个IP")
    ap.add_argument("--stats", action="store_true", help="打印库统计信息")
    ap.add_argument("--export", metavar="FILE", default=None, help="导出到文件(add.txt 格式, 用 --top 控制数量)")
    ap.add_argument("--top", type=int, default=100, help="导出数量(默认100)")
    ap.add_argument("--verified-only", action="store_true",
                    help="导出仅包含已识别出地区(colo/loc)的IP; 默认导出所有存活IP, 地区未知标为 UNK")
    ap.add_argument("--region", help="导出地区过滤, 逗号分隔 如 HKG,NRT")
    ap.add_argument("--seed", metavar="FILE", default=None, help="从现有 ADD.txt 导入种子IP到数据库")
    ap.add_argument("--mode", choices=["txt", "csv"], default="txt", help="导出格式(default txt=ADD.txt)")
    args = ap.parse_args()

    base_ports = [int(x.strip()) for x in (args.ports or "").split(",") if x.strip()]
    if not base_ports:
        base_ports = list(PORTS_DEFAULT)
    if args.port and args.port not in base_ports:
        base_ports.insert(0, args.port)
    args.ports = tuple(base_ports)

    if args.stats:
        print(stats_report(args))
        return
    if args.export:
        body = export_report(args)
        with open(args.export, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"已导出 {len(body.strip().splitlines())} 行 -> {args.export}", flush=True)
        print("提示: 默认包含所有存活IP; 只看有地区的用 --verified-only", flush=True)
        return
    if args.seed:
        print(seed_db(args))
        return

    conn = open_db(args.db)
    known = load_known(conn)
    nets, label = fetch_networks(args.operator, args.port)
    q = queue.Queue()
    stop = threading.Event()

    def len_from_db():
        return conn.execute("SELECT COUNT(*) FROM ips").fetchone()[0]

    def cov_percent():
        c = len_from_db()
        return c / net_total(nets) * 100 if net_total(nets) else 0

    def banner():
        return (f"[{time.strftime('%H:%M:%S')}] 库内 {len_from_db():,} IP, "
                f"覆盖率 {cov_percent():.2f}%, 扫描源: {label}")

    def worker():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_session(nets, known, q, args, stop))
        except Exception as e:
            q.put({"type": "error", "msg": str(e)})
        finally:
            try:
                loop.close()
            except Exception:
                pass
        q.put({"type": "done"})

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    print(banner(), flush=True)
    if args.reverify:
        print(f"复核模式: 重新探测库内最优 {args.reverify} 个IP", flush=True)
    else:
        print(f"地址源: {label} | 每轮抽样 {args.count} | 验证 {args.verify} | 测带宽 {args.bench} | "
              f"端口 {','.join(map(str, args.ports))} | TLS确认 {'开' if args.tls_check else '关'} | "
              f"优质邻域 {int(args.exploit*100)}% | 复测冷却 {args.cooldown:.0f}s", flush=True)
    print("Ctrl+C 安全退出(数据已实时落库), 重跑命令即可续扫", flush=True)
    try:
        pend = 0
        while not stop.is_set():
            try:
                rec = q.get(timeout=0.5)
            except queue.Empty:
                continue
            if rec["type"] == "result":
                upsert(conn, rec)
                pend += 1
                if pend >= 200:
                    conn.commit()
                    pend = 0
            elif rec["type"] == "cycle_end":
                conn.commit()
                pend = 0
                print(banner(), f"| 本轮达标 {rec['ok']}", flush=True)
            elif rec["type"] == "done":
                conn.commit()
                print(banner(), flush=True)
                print("扫描会话已结束", flush=True)
                stop.set()
                break
            elif rec["type"] == "error":
                conn.commit()
                print("错误:", rec["msg"], flush=True)
                break
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        conn.commit()
        conn.close()
        print("\n已安全退出, 数据已保存到", args.db, flush=True)
        print("可用 --stats 查看, --export 导出 ADD.txt", flush=True)


if __name__ == "__main__":
    main()