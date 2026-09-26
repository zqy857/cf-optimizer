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
import threading
import time
import types
import urllib.parse

import cf_health
import cf_lifecycle
import cf_policy

OFFICIAL_V4_URL = "https://www.cloudflare.com/ips-v4"
FALLBACK_RANGES = [
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15",
    "188.114.96.0/20", "173.245.48.0/20", "198.41.128.0/17", "141.101.64.0/18",
    "190.93.240.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "131.0.72.0/22", "108.162.192.0/18", "103.28.248.0/22", "192.0.77.0/24",
]
OFFICIAL_V6_URL = "https://www.cloudflare.com/ips-v6"
FALLBACK_RANGES_V6 = [
    "2606:4700::/32", "2606:4700:3000::/48", "2606:4700:3100::/48",
    "2400:cb00::/32", "2803:f800::/32",
]
# IPv6 地址池: 公开「优选 v6 IP 列表」(命中率高, 体积小) 命中率高, 还需叠加 CF 官方 v6 大段
# 以随机发现新地址(命中率低但覆盖广)。
# 注: addressesapi 的 ct-ipv6 / cu-ipv6 已失效(404), 故只保留 cmcc; 公共列表始终纳入。
V6_CURATED_URLS = {
    "cmcc": "https://addressesapi.090227.xyz/cmcc-ipv6",
}
# 公共优选 v6 列表: 主源 + CDN 镜像(raw.githubusercontent 在部分网络会超时/被墙)
V6_CURATED_GENERAL_URLS = [
    "https://raw.githubusercontent.com/joname1/BestCFip/refs/heads/main/ipv6.txt",
    "https://cdn.jsdelivr.net/gh/joname1/BestCFip@main/ipv6.txt",
]
V6_CURATED_GENERAL = V6_CURATED_GENERAL_URLS[0]
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
  fail_count INTEGER DEFAULT 0,
  last_ok_at REAL,
  last_fail_at REAL,
  fail_streak INTEGER DEFAULT 0,
  lat_ewma_ms REAL,
  bw_ewma_mbps REAL,
  score REAL DEFAULT 0,
  next_check_at REAL DEFAULT 0,
  state TEXT,
  interval REAL,
  tag TEXT,
  pin INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ips_score ON ips(latency_ms, verified_at, bandwidth_mbps);
CREATE INDEX IF NOT EXISTS idx_ips_tested ON ips(tested_at);
CREATE INDEX IF NOT EXISTS idx_ips_dead ON ips(tested_at) WHERE ok_count = 0;
CREATE INDEX IF NOT EXISTS idx_ips_colo ON ips(colo);
CREATE INDEX IF NOT EXISTS idx_ips_alive ON ips(ok_count) WHERE ok_count > 0;
CREATE INDEX IF NOT EXISTS idx_ips_bw ON ips(bandwidth_mbps) WHERE bandwidth_mbps > 0;
CREATE TABLE IF NOT EXISTS graveyard(
  ip TEXT PRIMARY KEY,
  buried_at REAL
);
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL DEFAULT 0
);
"""


MIGRATIONS = [
    "ALTER TABLE ips ADD COLUMN bw_last_mbps REAL",
    "ALTER TABLE ips ADD COLUMN bw_last_at REAL",
    # 健康度模型(见 cf_health.py)
    "ALTER TABLE ips ADD COLUMN last_ok_at REAL",
    "ALTER TABLE ips ADD COLUMN last_fail_at REAL",
    "ALTER TABLE ips ADD COLUMN fail_streak INTEGER DEFAULT 0",
    "ALTER TABLE ips ADD COLUMN lat_ewma_ms REAL",
    "ALTER TABLE ips ADD COLUMN bw_ewma_mbps REAL",
    "ALTER TABLE ips ADD COLUMN score REAL DEFAULT 0",
    "ALTER TABLE ips ADD COLUMN next_check_at REAL DEFAULT 0",
    # 生命周期: 状态标签 / 监控周期 / 用户标签 / 置顶保护
    "ALTER TABLE ips ADD COLUMN state TEXT",
    "ALTER TABLE ips ADD COLUMN interval REAL",
    "ALTER TABLE ips ADD COLUMN tag TEXT",
    "ALTER TABLE ips ADD COLUMN pin INTEGER DEFAULT 0",
    "CREATE INDEX IF NOT EXISTS idx_ips_next ON ips(next_check_at)",
    "CREATE INDEX IF NOT EXISTS idx_ips_quality ON ips(score)",
    "CREATE INDEX IF NOT EXISTS idx_ips_state ON ips(state)",
]

N24_SQL = ("substr(ip,1,"
           "instr(ip,'.')+instr(substr(ip,instr(ip,'.')+1),'.')"
           "+instr(substr(ip,instr(ip,'.')+instr(substr(ip,instr(ip,'.')+1),'.')+1),'.')-1)")


_SSL_CTX = None


def ssl_ctx():
    """共享客户端 SSLContext: 重复创建会反复加载 CA 库, 探测高频路径下开销显著."""
    global _SSL_CTX
    if _SSL_CTX is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        _SSL_CTX = ctx
    return _SSL_CTX


def open_db(path):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(ips)").fetchall()}
    for m in MIGRATIONS:
        if m.startswith("ALTER TABLE ips ADD COLUMN "):
            col = m.split(" ADD COLUMN ")[1].split(" ")[0]
            if col in cols:
                continue
        elif m.startswith("ALTER TABLE ips DROP COLUMN "):
            col = m.split(" DROP COLUMN ")[1].split(" ")[0]
            if col not in cols:
                continue
        try:
            conn.execute(m)
        except Exception:
            pass
    # 累计测试计数器: 首次使用时以 库内+墓碑 为基数播种, 之后由 upsert 对新IP累加, 剪枝不扣减
    try:
        conn.execute(
            "INSERT INTO meta(key,value) "
            "SELECT 'tested_total',(SELECT COUNT(*) FROM ips)+(SELECT COUNT(*) FROM graveyard) "
            "WHERE NOT EXISTS(SELECT 1 FROM meta WHERE key='tested_total')")
        conn.commit()
    except Exception:
        pass
    _health_migrate(conn)
    return conn


def _health_migrate(conn):
    """把存量库接入/升级到当前健康度模型: 回填 last_ok_at/last_fail_at/fail_streak,
    重算 score 与 next_check_at. 以 meta.health_ver 记录已应用的评分版本,
    评分公式变更(HEALTH_VERSION 提升)时自动重算一次, 无需手动干预."""
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='health_ver'").fetchone()
        ver = row[0] if row else 0
    except Exception:
        return
    if ver == cf_health.HEALTH_VERSION:
        return
    now = time.time()
    try:
        conn.execute("UPDATE ips SET last_ok_at=tested_at "
                     "WHERE ok_count>0 AND last_ok_at IS NULL")
        conn.execute("UPDATE ips SET last_fail_at=tested_at "
                     "WHERE ok_count=0 AND last_fail_at IS NULL")
        conn.execute("UPDATE ips SET fail_streak=MIN(fail_count, 10) "
                     "WHERE ok_count=0 AND COALESCE(fail_streak,0)=0")
        cf_health.health_refresh(conn, now)
        conn.execute("INSERT INTO meta(key,value) VALUES('health_ver',?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                     (cf_health.HEALTH_VERSION,))
        conn.commit()
    except Exception:
        pass


def load_known(conn):
    rows = conn.execute("SELECT ip, tested_at FROM ips").fetchall()
    known = {r[0]: r[1] or 0 for r in rows}
    try:
        known.update(conn.execute("SELECT ip, buried_at FROM graveyard"))
    except Exception:
        pass
    return known


async def fetch(url, timeout=10):
    loop = asyncio.get_running_loop()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(
        url.hostname, url.port or 443, ssl=True, server_hostname=url.hostname), timeout)
    try:
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        writer.write("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: cf-optimizer\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".format(
            path=path, host=url.hostname).encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), timeout)
        idx = data.find(b"\r\n\r\n")
        if idx < 0:
            return data
        header = data[:idx].decode("latin-1")
        body = data[idx + 4:]
        clen = None
        for line in header.split("\r\n")[1:]:
            k, _, v = line.partition(":")
            if k.strip().lower() == "content-length":
                try:
                    clen = int(v.strip())
                except ValueError:
                    clen = None
                break
        while clen is not None and len(body) < clen:
            chunk = await asyncio.wait_for(reader.read(65536), timeout)
            if not chunk:
                break
            body += chunk
        if clen is None:
            # 无 Content-Length(chunked/keep-alive): 读到连接关闭为止
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout)
                    if not chunk:
                        break
                    body += chunk
                except asyncio.TimeoutError:
                    break
        return body
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# 国家聚合配额缓存: 扫描高频写路径, 每次 upsert 都做全表聚合太贵,
# 但扫描周期是秒级, 1.5s 内的旧结果几乎不影响均衡判断.
_QUOTA_AGG = {"at": 0.0, "alive": 0, "agg": {}}


def _quota_agg(conn):
    now = time.time()
    if now - _QUOTA_AGG["at"] < 1.5:
        return _QUOTA_AGG["alive"], _QUOTA_AGG["agg"]
    alive = conn.execute("SELECT COUNT(*) FROM ips WHERE ok_count > 0").fetchone()[0]
    rows = conn.execute("SELECT colo, COUNT(*) FROM ips "
                        "WHERE colo IS NOT NULL AND ok_count > 0 "
                        "GROUP BY colo").fetchall()
    agg = {}
    for colo, cnt in rows:
        c = _country(colo)
        if c:
            agg[c] = agg.get(c, 0) + cnt
    _QUOTA_AGG["at"] = now
    _QUOTA_AGG["alive"] = alive
    _QUOTA_AGG["agg"] = agg
    return alive, agg


def _quota_ok(conn, country, pct):
    """单国家占比配额: 该国家(colos 映射聚合)活跃数占比 >= pct% 则拒绝新增该国家新IP。
    冷启动(<2个活跃国家)时不设限, 保证首批能收集到多种地区."""
    if not country:
        return True
    try:
        alive, agg = _quota_agg(conn)
        if len(agg) < 2 or alive < 2:
            return True
        cnt = agg.get(country, 0)
        return cnt * 100 < alive * pct
    except Exception:
        return True


_EXISTING_COLS = ("ok_count,fail_count,fail_streak,last_ok_at,last_fail_at,"
                  "latency_ms,lat_ewma_ms,bandwidth_mbps,bw_last_mbps,bw_last_at,"
                  "bw_ewma_mbps,colo,loc,verified_at,first_seen,port")


def upsert(conn, rec, country_pct=0):
    """写入一条 IP 探测结果, 并据健康度模型刷新 score / next_check_at.

    country_pct>0 时按单国家占比上限吸收新IP(均衡地区); 配额拒绝返回 'refused'。
    采用显式"读-改-写", 用 Python 计算连续成功/失败、EWMA 与质量分, 取代原先
    复杂的 ON CONFLICT CASE(仅单线程写库, 竞争极小)。
    """
    ip = rec.get("ip")
    if ip is None:
        return None
    now = rec.get("tested_at") or time.time()
    ok = 1 if rec.get("ok") else 0
    fail = 0 if ok else 1
    row = conn.execute(f"SELECT {_EXISTING_COLS} FROM ips WHERE ip=? LIMIT 1",
                       (ip,)).fetchone()
    is_new = row is None
    if is_new:
        if ok and rec.get("colo") and country_pct and country_pct > 0:
            if not _quota_ok(conn, _country(rec["colo"]), country_pct):
                return "refused"
        (p_ok, p_fail, p_fs, p_lok, p_lfail, p_lat, p_latw, p_bw, p_bwlast,
         p_bwlastat, p_bww, p_colo, p_loc, p_ver, p_first, p_port) = (
            0, 0, 0, None, None, None, None, None, None, None, None, None, None,
            None, now, 443)
    else:
        (p_ok, p_fail, p_fs, p_lok, p_lfail, p_lat, p_latw, p_bw, p_bwlast,
         p_bwlastat, p_bww, p_colo, p_loc, p_ver, p_first, p_port) = row

    ok_count = (p_ok or 0) + ok
    fail_count = (p_fail or 0) + fail
    fail_streak = 0 if ok else (p_fs or 0) + 1
    last_ok_at = now if ok else p_lok
    last_fail_at = p_lfail if ok else now

    latency = rec.get("latency")
    if ok and latency is not None:
        latency_ms = latency
        lat_ewma = latency if p_latw is None else round(0.7 * p_latw + 0.3 * latency, 3)
    else:
        latency_ms = p_lat
        lat_ewma = p_latw

    bw = rec.get("bandwidth")
    if bw is not None:
        best_bw = bw if p_bw is None else max(p_bw, bw)
        bw_ewma = bw if p_bww is None else round(0.7 * p_bww + 0.3 * bw, 3)
        bw_last = bw
        bw_last_at = now
    else:
        best_bw, bw_ewma, bw_last, bw_last_at = p_bw, p_bww, p_bwlast, p_bwlastat

    colo = rec.get("colo") or p_colo
    loc = rec.get("loc") or p_loc
    verified_at = rec.get("verified_at") or p_ver
    if rec.get("colo") and not verified_at:
        verified_at = now
    port = (rec.get("port") or p_port or 443) if ok else (p_port or 443)
    first_seen = p_first or now

    lat_v = lat_ewma if lat_ewma is not None else latency_ms
    bw_v = bw_ewma if bw_ewma is not None else best_bw
    verified = bool(colo)
    sc = cf_health.score(ok_count, fail_count, lat_v, bw_v, verified, last_ok_at, now)
    st = cf_health.classify(ok_count, fail_streak, sc, last_ok_at, now, verified)
    iv = cf_health.state_interval(st, sc, fail_streak, verified)
    nxt = cf_health.next_check_for(ip, st, sc, fail_streak, last_ok_at, last_fail_at,
                                   now, verified, now)

    values = (port, colo, loc, latency_ms, best_bw, bw_last, bw_last_at, now,
              verified_at, ok_count, fail_count, last_ok_at, last_fail_at,
              fail_streak, lat_ewma, bw_ewma, sc, nxt, iv, st)
    if is_new:
        conn.execute(
            "INSERT INTO ips(ip,port,colo,loc,latency_ms,bandwidth_mbps,bw_last_mbps,"
            "bw_last_at,tested_at,verified_at,ok_count,fail_count,last_ok_at,last_fail_at,"
            "fail_streak,lat_ewma_ms,bw_ewma_mbps,score,next_check_at,interval,state,first_seen) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ip,) + values + (first_seen,))
        try:
            conn.execute(
                "INSERT INTO meta(key,value) VALUES('tested_total',1) "
                "ON CONFLICT(key) DO UPDATE SET value=value+1")
        except Exception:
            pass
    else:
        conn.execute(
            "UPDATE ips SET port=?,colo=?,loc=?,latency_ms=?,bandwidth_mbps=?,"
            "bw_last_mbps=?,bw_last_at=?,tested_at=?,verified_at=?,ok_count=?,fail_count=?,"
            "last_ok_at=?,last_fail_at=?,fail_streak=?,lat_ewma_ms=?,bw_ewma_mbps=?,"
            "score=?,next_check_at=?,interval=?,state=? WHERE ip=?",
            values + (ip,))
    return "ok"


GRAVE_DAYS = 7           # 死IP墓碑静默期(天): 期间抽样自动跳过
GRAVE_EXPIRE_DAYS = 30   # 墓碑过期天数
GRAVE_MAX_ROWS = 200000  # 墓碑行数硬上限

# CF 机房三字码 → 国家/地区 (与 Web 端共用一份)
COLO_COUNTRY = {
    "LAX": "美国", "SJC": "美国", "SEA": "美国", "PDX": "美国",
    "DEN": "美国", "ORD": "美国", "DFW": "美国", "IAD": "美国",
    "ATL": "美国", "MIA": "美国", "JFK": "美国", "EWR": "美国",
    "PHX": "美国", "SFO": "美国", "BOS": "美国", "PHL": "美国",
    "MCI": "美国", "MSP": "美国", "STL": "美国", "MSY": "美国",
    "SLC": "美国", "SAN": "美国", "LAS": "美国", "AUS": "美国",
    "SAT": "美国", "OKC": "美国", "TUS": "美国", "RDU": "美国",
    "CLT": "美国", "BNA": "美国", "MCO": "美国", "MKE": "美国",
    "IND": "美国", "CMH": "美国", "CLE": "美国", "PIT": "美国",
    "ABQ": "美国", "ELP": "美国", "OMA": "美国",
    "YYZ": "加拿大", "YVR": "加拿大", "YUL": "加拿大", "YOW": "加拿大",
    "YEG": "加拿大", "YWG": "加拿大", "YYC": "加拿大", "YHZ": "加拿大",
    "HKG": "中国香港", "TPE": "中国台湾", "NRT": "日本", "KIX": "日本",
    "FUK": "日本", "NGO": "日本", "CTS": "日本",
    "SEL": "韩国", "ICN": "韩国", "SIN": "新加坡", "BKK": "泰国", "KUL": "马来西亚",
    "SGN": "越南", "HAN": "越南", "MNL": "菲律宾", "CGK": "印尼",
    "DPS": "印尼", "PNH": "柬埔寨", "RGN": "缅甸", "DAC": "孟加拉",
    "CMB": "斯里兰卡", "KTM": "尼泊尔",
    "LHR": "英国", "MAN": "英国", "FRA": "德国", "MUC": "德国", "DUS": "德国",
    "HAM": "德国", "TXL": "德国", "BER": "德国",
    "AMS": "荷兰", "PAR": "法国", "CDG": "法国", "MRS": "法国",
    "MAD": "西班牙", "BCN": "西班牙", "MXP": "意大利", "MIL": "意大利",
    "FCO": "意大利", "VCE": "意大利", "NAP": "意大利", "PMO": "意大利",
    "WAW": "波兰", "KRK": "波兰", "ARN": "瑞典", "STO": "瑞典",
    "HEL": "芬兰", "OSL": "挪威", "CPH": "丹麦", "ZRH": "瑞士",
    "GVA": "瑞士", "VIE": "奥地利", "PRG": "捷克", "BUD": "匈牙利",
    "SOF": "保加利亚", "ATH": "希腊", "HER": "希腊", "SKG": "希腊",
    "LIS": "葡萄牙", "BRU": "比利时", "DUB": "爱尔兰", "ZAG": "克罗地亚",
    "OTP": "罗马尼亚", "BUH": "罗马尼亚", "LJU": "斯洛文尼亚",
    "IST": "土耳其", "GZT": "土耳其",
    "DXB": "阿联酋", "MCT": "阿曼", "TLV": "以色列", "BEY": "黎巴嫩",
    "AMM": "约旦", "KWI": "科威特", "RUH": "沙特", "JED": "沙特",
    "DOH": "卡塔尔", "BHR": "巴林",
    "JNB": "南非", "CPT": "南非", "LOS": "尼日利亚", "GBE": "博茨瓦纳",
    "KGL": "卢旺达", "NBO": "肯尼亚", "MBA": "肯尼亚", "MUB": "博茨瓦纳",
    "ADD": "埃塞俄比亚", "DAR": "坦桑尼亚", "TUN": "突尼斯", "CMN": "摩洛哥",
    "ACC": "加纳", "EBB": "乌干达",
    "GIG": "巴西", "GRU": "巴西", "BSB": "巴西", "MAO": "巴西",
    "FOR": "巴西", "REC": "巴西", "CNF": "巴西", "BEL": "巴西",
    "EZE": "阿根廷", "LIM": "秘鲁", "BOG": "哥伦比亚", "MEX": "墨西哥",
    "GDL": "墨西哥", "MTY": "墨西哥", "SCL": "智利", "PTY": "巴拿马",
    "CCS": "委内瑞拉", "MVD": "乌拉圭", "ASU": "巴拉圭", "UIO": "厄瓜多尔",
    "GYE": "厄瓜多尔", "SJO": "哥斯达黎加",
    "SYD": "澳大利亚", "MEL": "澳大利亚", "PER": "澳大利亚",
    "BNE": "澳大利亚", "ADL": "澳大利亚",
    "AKL": "新西兰",
    "BOM": "印度", "BLR": "印度", "DEL": "印度", "MAA": "印度", "HYD": "印度",
    "CCU": "印度", "KBP": "乌克兰",
}


def _country(colo):
    """colo 三字码 → 国家/地区, 未知返回 None"""
    return COLO_COUNTRY.get((colo or "").upper())


def _grave_ts(now):
    """使墓碑在 known 冷却判断下恰好静默 GRAVE_DAYS 天"""
    return now + GRAVE_DAYS * 86400 - 3600


def prune_ips(conn, max_v4, max_v6, country_pct=0, target_active=0):
    """兼容入口: 转交 cf_lifecycle.lifecycle_pass(剔除闭环). 返回剔除总数."""
    stats, _def = cf_lifecycle.lifecycle_pass(
        conn, max_v4, max_v6, country_pct, target_active)
    return sum(stats.values())


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


def resolve_sources(args):
    """按 v4/ipv6 开关与各自地址源解析地址池. 返回 (nets, label, nets6).

    label 为 "v4源 + v6源" 的组合描述, 供 Web/CLI 展示与日志使用。
    """
    nets, nets6 = [], []
    parts = []
    if getattr(args, "v4", True):
        nets, v4label = fetch_networks(getattr(args, "operator", None), args.port)
        parts.append(v4label)
    if getattr(args, "ipv6", False):
        nets6 = fetch_networks_v6(getattr(args, "operator_v6", "") or "",
                                  include_official=getattr(args, "v6_official", True))
        op6 = {"cmcc": "移动"}.get(getattr(args, "operator_v6", None), "公共")
        off6 = "" if getattr(args, "v6_official", True) else "(不含官方大段)"
        parts.append(f"IPv6({op6}{off6})")
    return nets, " + ".join(parts) or "无地址源", nets6


def fetch_networks_v6(operator="", include_official=True):
    """IPv6 地址池。

    公开「优选 v6 IP 列表」(运营商匹配 + 通用源合并, 均为已优选好的具体IP,
    命中率高) + (可选) CF 官方 v6 大段(随机发现新地址, 命中率低但覆盖广) 合并返回。
    返回 ip_network 列表: 优选条目是 /128 主机, 官方是大段。
    """
    def _parse(raw):
        out = []
        for line in raw.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("["):
                ip = line.split("]", 1)[0].lstrip("[")
            else:
                ip = line.split("#", 1)[0].split()[0]
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if a.version == 6:
                out.append(str(a))
        return out

    seeds = []
    urls = []
    if operator in V6_CURATED_URLS:
        urls.append((operator, [V6_CURATED_URLS[operator]]))
    urls.append(("公共", list(V6_CURATED_GENERAL_URLS)))
    for name, ulist in urls:
        got = []
        for u in ulist:   # 多个镜像依次尝试, 任一成功即用
            try:
                raw = asyncio.run(fetch(urllib.parse.urlparse(u), timeout=7))
                got = _parse(raw)
                if got:
                    break
            except Exception as e:
                print(f"[源] IPv6 优选源 {name} 不可用({type(e).__name__}): {u}", flush=True)
                continue
        if not got:
            print(f"[源] IPv6 优选源 {name} 全部镜像无有效数据", flush=True)
        seeds.extend(got)
    seeds = list(dict.fromkeys(seeds))
    nets = [ipaddress.ip_network(s, strict=False) for s in seeds] if seeds else []
    # 可选: 叠加 CF 官方 v6 大段, 用于随机发现新地址(命中率低但覆盖广)
    if include_official:
        try:
            raw = asyncio.run(fetch(urllib.parse.urlparse(OFFICIAL_V6_URL), timeout=7))
            for l in raw.decode().splitlines():
                l = l.strip()
                if "/" in l:
                    try:
                        nets.append(ipaddress.ip_network(l, strict=False))
                    except ValueError:
                        continue
        except Exception:
            for r in FALLBACK_RANGES_V6:
                try:
                    nets.append(ipaddress.ip_network(r))
                except ValueError:
                    continue
    return nets


def net_total(nets):
    return sum(1 << (n.max_prefixlen - n.prefixlen) for n in nets)


def random_ip_in_net(net):
    base = int(net.network_address)
    size = 1 << (net.max_prefixlen - net.prefixlen)
    return ipaddress.ip_address(base + random.randrange(size))


def net24(ip):
    return ".".join(ip.split(".")[:3])


def fetch_hot24(path, limit=200, raw=False, cap=cf_lifecycle.PER24_MAX):
    """优质 v4 /24 邻域(按历史净成功加权). cap: 已达该前缀配额的 /24 不再返回,
    避免"发现->超额->剔除"的空转(与生命周期去重联动)。"""
    try:
        conn = sqlite3.connect(path)
        q = (f"SELECT {N24_SQL} AS n, SUM(ok_count) g, SUM(fail_count) f, COUNT(*) c "
             f"FROM ips WHERE instr(ip, ':')=0 GROUP BY n "
             f"ORDER BY (SUM(ok_count)-SUM(fail_count)) DESC, g DESC")
        rows = conn.execute(q).fetchall()
        conn.close()
    except Exception:
        return []
    hot = [(n, (g or 0), (f or 0), c) for n, g, f, c in rows]
    if raw:
        return hot
    hot = [(n, max(1, g)) for n, g, f, c in hot if g and g >= 1 and c < cap]
    return hot[:limit]


def fetch_due(path, limit, now=None):
    """分层调度: 取已到复测时间(next_check_at<=now)的 IP, 最久到期者优先。

    next_check_at 由 cf_health 按分数/失败退避生成——优质 IP 到期更快、复测更勤,
    失败 IP 指数退避; 按到期时间排序保证任何 IP 都不会被无限饿死。
    """
    now = now or time.time()
    try:
        conn = sqlite3.connect(path)
        rows = conn.execute(
            "SELECT ip, port FROM ips WHERE next_check_at <= ? "
            "ORDER BY next_check_at ASC, score DESC LIMIT ?", (now, limit)).fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def _maybe_refresh_health(conn, target_active=0, ttl=120):
    """限频地把全库 score/state/interval/next_check_at 重算.

    新版会按分数排名: 每协议前 target_active 名 -> active(高频), 其余 -> reserve(低频)。
    """
    now = time.time()
    row = conn.execute("SELECT value FROM meta WHERE key='score_refreshed_at'").fetchone()
    if row and now - row[0] < ttl:
        return
    try:
        cf_health.health_refresh(conn, now, target_active)
        conn.execute("INSERT INTO meta(key,value) VALUES('score_refreshed_at',?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (int(now),))
        conn.commit()
    except Exception:
        pass


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
    hot_pre = [p for p, _ in hot24]
    hot_w = [w for _, w in hot24]
    hot_total = sum(hot_w)

    for _ in range(n_exploit):
        if hot_total <= 0:
            break
        pre = random.choices(hot_pre, weights=hot_w)[0]
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


def v6_prefix(ip, hextets=3):
    """IPv6 邻域前缀。CF 的 v6 anycast 是按 /48 公告的: 同一 /48 内任意地址几乎都可达,
    而未公告的 /48 则全灭。故用 /48(前 3 段)作为 v6 的"学习/利用单元"."""
    try:
        parts = ipaddress.ip_address(ip).exploded.split(":")
    except ValueError:
        return ip
    return ":".join(parts[:hextets])


def fetch_hot_v6(path, limit=400, cap=cf_lifecycle.PER48_MAX):
    """从库内已存活 v6 聚合出优质 /48 邻域(按成功次数加权), 供发现时优先利用.
    cap: 已达该 /48 配额的邻域不再返回(与去重联动, 防止同 /48 反复超容/回填 churn)."""
    try:
        conn = sqlite3.connect(path)
        rows = conn.execute("SELECT ip, ok_count FROM ips WHERE instr(ip,':')>0 "
                            "AND ok_count>0").fetchall()
        conn.close()
    except Exception:
        return []
    agg = {}
    cnt = {}
    for ip, ok in rows:
        p = v6_prefix(ip)
        agg[p] = agg.get(p, 0) + (ok or 0)
        cnt[p] = cnt.get(p, 0) + 1
    hot = [(p, w) for p, w in agg.items() if cnt.get(p, 0) < cap]
    hot.sort(key=lambda x: -x[1])
    return [(p, max(1, w)) for p, w in hot[:limit]]


def discover_v6(nets6, count, ports, known, cooldown, hot48=None, exploit_frac=0.7):
    """IPv6 候选抽样。

    1) 先用尽优选 /128 列表(命中率高)
    2) 邻域利用: 在已知优质 /48 内随机取址(实测 /48 内命中率接近 100%)
    3) 余量对官方大段随机抽样, 探索新的 /48 邻域
    总数不超过 count。
    """
    now = time.time()

    def eligible(ip):
        t = known.get(ip)
        return t is None or (now - t) >= cooldown

    def add(ip):
        if ip in seen or ip in known or not eligible(ip):
            return False
        known[ip] = now
        seen.add(ip)
        cands.append((ip, tuple(ports)))
        return True

    cands = []
    seen = set()

    curated = [n for n in nets6 if n.prefixlen >= 64]
    random.shuffle(curated)
    for net in curated:
        if len(cands) >= count:
            break
        add(str(random_ip_in_net(net)))

    # 邻域利用: 在已知优质 /48 内随机生成本轮新地址
    hot48 = hot48 or []
    n_exploit = min(count - len(cands), int(count * exploit_frac))
    if hot48 and n_exploit > 0:
        pre = [p for p, _ in hot48]
        w = [x for _, x in hot48]
        added = tries = 0
        while added < n_exploit and len(cands) < count and tries < n_exploit * 4:
            tries += 1
            p = random.choices(pre, weights=w)[0]
            try:
                net = ipaddress.ip_network(p + "::/48")
            except ValueError:
                continue
            if add(str(random_ip_in_net(net))):
                added += 1

    big = [n for n in nets6 if n.prefixlen < 64]
    remaining = max(0, count - len(cands))
    for _ in range(remaining):
        if not big:
            break
        net = random.choice(big)
        max_tries = min(32, 1 << max(0, min(32, net.max_prefixlen - net.prefixlen)))
        for _ in range(max_tries):
            if add(str(random_ip_in_net(net))):
                break
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


async def probe_ip(ip, ports, args, do_tls=None):
    """探测一个IP: TCP可达则(可选)TLS确认. do_tls=None 时按 args.tls_check 决定."""
    if do_tls is None:
        do_tls = args.tls_check
    for p in ports:
        tcp = await tcp_latency(ip, p, args.ping_timeout)
        if tcp is None:
            continue
        if do_tls:
            tls = await tls_probe(ip, p, min(args.ping_timeout * 2, 4.0))
            if tls is None:
                continue
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
            return (0, None, None)
        n = 0
        start = None
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
                if start is None:
                    start = time.perf_counter()
                n += len(chunk)
                if n >= size:
                    break
        except asyncio.TimeoutError:
            pass
        except Exception:
            return (0, None, None)
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        if start is None:
            return (0, None, None)
        return (n, start, time.perf_counter())

    bodies = await asyncio.gather(*(one() for _ in range(parallel)), return_exceptions=True)
    items = [b for b in bodies if isinstance(b, tuple) and b[0] and b[1] is not None]
    total = sum(b[0] for b in items)
    if total < 100_000:
        # 大档位+高并发可能被测速端限流(实测 6×30MB 常失败, 8MB 稳定);
        # 失败时自动降档重试一次(更小体积 + 更少并发), 显著提升带宽测量命中率。
        if size > 3_000_000:
            ns2 = types.SimpleNamespace(
                bench_size=max(2_000_000, size // 4),
                bench_timeout=timeout,
                bench_parallel=max(2, parallel // 2),
                bench_host=host)
            return await bench_bandwidth(ip, port, ns2)
        return None
    w0 = min(b[1] for b in items)
    w1 = max(b[2] for b in items)
    elapsed = max(0.05, w1 - w0)
    mbps = (total * 8) / (elapsed * 1_000_000)
    return round(mbps, 2)


async def run_session(nets, known, q, args, stop, nets6=None):
    sem = asyncio.Semaphore(args.concurrency)
    max_lat = args.max_latency
    ports = list(args.ports)
    now = time.time()
    verified = set()

    async def probe(ip, ports_seq):
        async with sem:
            do_tls = bool(args.tls_check) and ip not in verified
            return await probe_ip(ip, ports_seq, args, do_tls=do_tls)

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

    async def verify_one(ip, p, lat, do_bench, do_id=True):
        args_ns = types.SimpleNamespace(bench_size=args.bench_size,
                                        bench_timeout=args.bench_timeout,
                                        bench_parallel=args.bench_parallel,
                                        bench_host=getattr(args, "bench_host", SPEED_HOST))
        colo = loc = bw = None
        verified_at = None
        if do_id:
            try:
                info = await identify(ip, p, args_ns, latency=lat)
            except Exception:
                info = None
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

    async def verify_batch(pend, bench=None):
        if not pend:
            return
        if bench is None:
            bench = args.bench
        vsem = asyncio.Semaphore(min(8, len(pend)))

        async def v(ip, p, lat, do_id, idx):
            async with vsem:
                await verify_one(ip, p, lat, idx < bench, do_id)

        await run_tasks([v(ip, p, lat, do_id, i)
                         for i, (ip, p, lat, do_id) in enumerate(pend)])

    last_explore = {"t": 0.0}

    async def discovery_cycle():
        nonlocal verified
        verified = set()
        have_bw = None
        have_colo = set()
        deficits = {}
        next_due = None
        due_count = 0
        active_mode = True
        explore = True
        v6_count = getattr(args, "count_v6", args.count)
        bud = {"count": 0, "count_v6": 0, "verify": args.verify,
               "bench": args.bench, "recheck": args.recheck}
        try:
            conn_v = sqlite3.connect(args.db)
            _maybe_refresh_health(conn_v, getattr(args, "target_active", 0))
            target_active = getattr(args, "target_active", cf_policy.TARGET_ACTIVE)
            target_prefixes = getattr(args, "target_prefixes", cf_policy.TARGET_PREFIXES)
            force = getattr(args, "scan_mode", "auto") or "auto"
            modes = cf_policy.evaluate_all(conn_v, target_active=target_active,
                                           target_prefixes=target_prefixes, force=force)
            mi4, mi6 = modes["v4"], modes["v6"]
            active_mode = any(m["mode"] != "maintenance" for m in (mi4, mi6))
            deficits = cf_lifecycle.replenish_need(conn_v, target_active,
                                                   args.max_ips_v4, args.max_ips_v6)
            now = time.time()
            reserve_tick = (now - last_explore["t"]) >= cf_policy.EXPLORE_INTERVAL
            reserve_need = any(d["deficit_reserve"] > 0 for d in deficits.values())
            active_need = any(d["deficit"] > 0 for d in deficits.values())
            # 发现条件: 发现/恢复期, 或热缺口, 或(维护期且到点)补库容(备胎)
            explore = active_mode or active_need or (reserve_need and reserve_tick)
            # 纯值守: 无需发现 -> 不再有"轮"的概念
            pure_monitor = (not active_mode) and (not explore)
            sb4 = cf_policy.shared_budget(mi4["mode"], args.verify, args.bench,
                                          args.recheck, mi4["active"])
            sb6 = cf_policy.shared_budget(mi6["mode"], args.verify, args.bench,
                                          args.recheck, mi6["active"])

            def proto_count(key, mi, base, enabled):
                if not enabled:
                    return 0
                if mi["mode"] != "maintenance":
                    return cf_policy.scan_count(mi["mode"], base)     # 发现/恢复: 正常量
                d = deficits.get(key, {})
                if reserve_tick and d.get("deficit_reserve", 0) > 0:
                    return max(30, int(base * 0.1))                    # 维护: 低频补备胎
                return 0                                               # 维护且库容已满: 不发现
            bud = {
                "count": proto_count("v4", mi4, args.count, bool(nets)),
                "count_v6": proto_count("v6", mi6, v6_count, bool(nets6)),
                "verify": max(sb4["verify"], sb6["verify"]),
                "bench": max(sb4["bench"], sb6["bench"]) if (nets or nets6) else 0,
                "recheck": max(sb4["recheck"], sb6["recheck"]),
            }
            next_due = conn_v.execute("SELECT MIN(next_check_at) FROM ips").fetchone()[0]
            due_count = conn_v.execute(
                "SELECT COUNT(*) FROM ips WHERE next_check_at<=?", (now,)).fetchone()[0]
            q.put({"type": "mode", "modes": modes, "budgets": bud, "explore": explore,
                   "deficits": deficits,
                   "active": mi4["active"] + mi6["active"],
                   "fresh": mi4["fresh"] + mi6["fresh"],
                   "prefixes": mi4["prefixes"] + mi6["prefixes"],
                   "yield": max(mi4["yield"], mi6["yield"]),
                   "mode": mi4["mode"] if mi4["mode"] != "maintenance" else mi6["mode"],
                   "reason": f"v4 {mi4['mode']} / v6 {mi6['mode']}" + (" +探索" if explore else "")})
            have_bw = set() if bud["bench"] > 0 else None
            for ip, okc, bw, colo, loc in conn_v.execute(
                    "SELECT ip, ok_count, bandwidth_mbps, colo, loc FROM ips"):
                if okc and okc > 0:
                    verified.add(ip)
                if have_bw is not None and bw is not None:
                    have_bw.add(ip)
                if colo and loc:
                    have_colo.add(ip)
            conn_v.close()
        except Exception:
            verified = set()
            explore = True

        cands = []
        seen = set()

        def add_cand(ip, ports_seq):
            if not ip or ip in seen:
                return
            seen.add(ip)
            cands.append((ip, tuple(ports_seq)))

        def seq_for(p):
            return [p] + [x for x in ports if x != p]

        # 1) 监控: 到期复测(每轮始终执行, 限速)
        due_limit = min(cf_policy.MONITOR_BATCH,
                        bud["recheck"] or cf_policy.MONITOR_BATCH)
        if not args.once:
            for ip, p in fetch_due(args.db, due_limit):
                if ip in known:
                    known[ip] = time.time()
                add_cand(ip, seq_for(p))

        # 2) 补充: 有缺口时优先提升 reserve(快速确认)
        for key, is_v6 in (("v4", False), ("v6", True)):
            d = (deficits.get(key) or {}).get("deficit", 0)
            if d > 0:
                for ip, p in cf_lifecycle.fetch_promote(args.db, is_v6, d, args.cooldown):
                    if ip in known:
                        known[ip] = time.time()
                    add_cand(ip, seq_for(p))

        # 3) 发现: 仅在探索期进行(避免库满后空扫); 邻域名单已排除超额前缀
        if nets and bud["count"] > 0:
            hot24 = fetch_hot24(args.db) if args.exploit > 0 else []
            for ip, ps in discover(nets, hot24, bud["count"], ports, known,
                                   args.cooldown, args.exploit):
                add_cand(ip, ps)
        if nets6 and bud["count_v6"] > 0:
            hot48 = fetch_hot_v6(args.db) if args.exploit > 0 else []
            for ip, ps in discover_v6(nets6, bud["count_v6"], ports, known,
                                      args.cooldown, hot48, args.exploit):
                add_cand(ip, ps)

        # 4) 地区补全
        backfill_ips = set()
        if getattr(args, "backfill", 0) and not args.once:
            for ip, p, _, _ in fetch_backfill(args.db, args.backfill, args.cooldown):
                if ip in known:
                    known[ip] = time.time()
                backfill_ips.add(ip)
                add_cand(ip, seq_for(p))

        status = {"active_mode": active_mode, "explored": explore,
                  "pure_monitor": pure_monitor, "next_due": next_due,
                  "due": due_count, "deficits": deficits}
        if not cands:
            return 0, [], bud, status
        if pure_monitor:
            q.put({"type": "monitor", "checking": len(cands), "due": due_count,
                   "next_due": next_due})
        else:
            q.put({"type": "cycle_start", "total": len(cands)})
        results = []

        async def probe_emit(ip, ps):
            r = await probe(ip, ps)
            if r and r[0]:
                _, p, lat, alive = r
                good = bool(alive) and lat is not None and lat <= max_lat
                q.put({"type": "result", "ip": ip, "port": p, "ok": good,
                       "latency": lat, "tested_at": time.time()})
                results.append(r)
            return r

        await run_tasks([probe_emit(ip, ps) for ip, ps in cands])
        ok = 0
        alive_list = []
        for ip, p, lat, alive in results:
            if alive and lat is not None and lat <= max_lat:
                ok += 1
                alive_list.append((ip, p, lat, ip in backfill_ips, ip not in have_colo))
        alive_list.sort(key=lambda r: (0 if r[3] else 1, r[2]))
        pend = [(ip, p, lat, need_id)
                for ip, p, lat, _bf, need_id in alive_list[: bud["verify"]]]
        if bud["bench"] > 0 and have_bw is not None:
            pend = ([x for x in pend if x[0] not in have_bw]
                    + [x for x in pend if x[0] in have_bw])
        return ok, pend, bud, status

    async def sleep_interruptible(seconds):
        slept = 0.0
        while slept < seconds and not stop.is_set():
            step = min(0.5, seconds - slept)
            await asyncio.sleep(step)
            slept += step

    async def gap_sleep():
        await sleep_interruptible(args.gap)

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
        ok, pend, bud, _st = await discovery_cycle()
        if pend:
            await verify_batch(pend, bud["bench"])
        q.put({"type": "cycle_end", "ok": ok})
        return

    cycles = 0
    last_life = 0.0
    while not stop.is_set():
        if args.cycles and cycles >= args.cycles:
            break
        ok, pend, bud, st = await discovery_cycle()
        if pend:
            await verify_batch(pend, bud["bench"])
        if st["pure_monitor"]:
            # 值守监控: 不计"轮", 不发 cycle_end; 定期做一次生命周期维护(剔除/补充判定)
            if time.time() - last_life >= cf_policy.LIFE_INTERVAL:
                q.put({"type": "lifecycle"})
                last_life = time.time()
            q.put({"type": "monitor_end", "checked": ok})
        else:
            q.put({"type": "cycle_end", "ok": ok})
            cycles += 1
        if st["explored"]:
            last_explore["t"] = time.time()
        # 节奏: 发现/恢复/探索期短歇; 纯监控期按 tick / 睡到下一个到期, 不空转
        if st["active_mode"] or st["explored"]:
            await sleep_interruptible(args.gap)
        else:
            nx = st["next_due"]
            if st.get("due", 0) > 0:
                wait = cf_policy.MONITOR_TICK
            elif not nx:
                wait = cf_policy.IDLE_CAP
            else:
                wait = max(cf_policy.MONITOR_TICK, min(nx - time.time(), cf_policy.IDLE_CAP))
            wait = min(wait, max(2.0, cf_policy.EXPLORE_INTERVAL
                                 - (time.time() - last_explore["t"])))
            await sleep_interruptible(wait)


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
        f"ORDER BY score DESC, latency_ms ASC LIMIT ?",
        params + [args.top if args.top else 100]).fetchall()
    conn.close()
    lines = []
    csv_lines = ["rank,ip,port,latency_ms,bandwidth_mbps,colo,loc"]
    for i, (ip, p, colo, loc, lat, bw) in enumerate(rows, 1):
        remark = f"{colo or 'UNK'}-{loc or 'UNK'}-{i}"
        lines.append(f"{ip}:{p}#{remark}")
        csv_lines.append(f"{i},{ip},{p},{lat if lat is not None else ''},"
                         f"{bw if bw is not None else ''},{colo or ''},{loc or ''}")
    mode = args.mode
    if mode == "txt":
        body = "\n".join(lines) + ("\n" if lines else "")
    else:
        body = "\n".join(csv_lines) + "\n"
    return body


def stats_report(args):
    conn = open_db(args.db)
    total = conn.execute("SELECT COUNT(*) FROM ips").fetchone()[0]
    row = conn.execute("SELECT value FROM meta WHERE key='tested_total'").fetchone()
    if row and row[0]:
        tested_all = row[0]
    else:
        grave = conn.execute("SELECT COUNT(*) FROM graveyard").fetchone()[0]
        tested_all = total + grave
    ok = conn.execute("SELECT COUNT(*) FROM ips WHERE ok_count>0").fetchone()[0]
    fresh = conn.execute(
        "SELECT COUNT(*) FROM ips WHERE ok_count>0 AND COALESCE(last_ok_at,tested_at) > ?",
        (time.time() - cf_health.FRESH_WINDOW,)).fetchone()[0]
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
        f"已测试IP: {tested_all:,} (历史累计)  库内保留: {total:,}  "
        f"(覆盖率 {total / cov * 100 if cov else 0:.2f}%)",
        f"存活IP:  {ok:,}  (1h内新鲜: {fresh:,})  已验证地区: {verified:,}  "
        f"未识别地区: {unverified:,}  有带宽数据: {with_bw:,}",
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
    known = load_known(conn)
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
                if host in known:
                    continue
                known[host] = time.time()
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
    ap.add_argument("--no-v4", dest="v4", action="store_false", default=True,
                    help="关闭 IPv4 扫描(默认开)")
    ap.add_argument("--ipv6", action="store_true", default=False,
                    help="同时采样 IPv6 地址池(公开优选列表 + CF官方大段, 需本机有IPv6网络)")
    ap.add_argument("--v6-operator", dest="operator_v6", choices=["cmcc"], default=None,
                    help="IPv6 优选列表来源: 移动(cmcc); 默认仅公共优选列表(注: 电信/联通优选源已失效)")
    ap.add_argument("--no-v6-official", dest="v6_official", action="store_false", default=True,
                    help="IPv6 不叠加 CF 官方 v6 大段(默认叠加, 用于随机发现新地址)")
    ap.add_argument("--count", type=int, default=5000, help="IPv4 每轮发现抽样数(默认 5000)")
    ap.add_argument("--count-v6", dest="count_v6", type=int, default=None,
                    help="IPv6 每轮发现抽样数(默认与 --count 相同)")
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
                    help="每轮到期复测数量(按健康度分层调度: 优质IP勤测, 失败退避; 默认30; 0=关闭)")
    ap.add_argument("--backfill", type=int, default=0,
                    help="每轮为'存活但缺地区(colo/loc)'的旧IP补全地区识别数量(默认0; GUI默认开启)")
    ap.add_argument("--bench-size", type=int, default=12_000_000)
    ap.add_argument("--bench-timeout", type=float, default=12)
    ap.add_argument("--bench-parallel", type=int, default=4)
    ap.add_argument("--cycles", type=int, default=0, help="扫描轮数限制, 0=无限")
    ap.add_argument("--max-ips-v4", type=int, default=0, dest="max_ips_v4",
                    help="IPv4 库上限(0=不限)")
    ap.add_argument("--max-ips-v6", type=int, default=0, dest="max_ips_v6",
                    help="IPv6 库上限(0=不限)")
    ap.add_argument("--country-pct", type=int, default=30, dest="country_pct",
                    help="单国家活跃占比上限%% (0=关闭均衡). 超过上限的新IP不吸收, 超限时该国低分IP先裁剪")
    ap.add_argument("--gap", type=float, default=5, help="轮间间隔秒(默认5)")
    ap.add_argument("--scan-mode", dest="scan_mode", choices=["auto", "discovery", "maintenance", "recovery"],
                    default="auto", help="扫描策略: auto=达动态平衡后自动转健康维护(默认)")
    ap.add_argument("--target-active", type=int, default=60, dest="target_active",
                    help="动态平衡目标: 期望保有的可用IP数(默认60)")
    ap.add_argument("--target-prefixes", type=int, default=8, dest="target_prefixes",
                    help="动态平衡目标: 期望覆盖的独立前缀数(默认8)")
    ap.add_argument("--per24-max", type=int, default=50, dest="per24_max",
                    help="每个 v4 /24 最多保留(越小越多样; 默认50; 0=不限)")
    ap.add_argument("--per48-max", type=int, default=100, dest="per48_max",
                    help="每个 v6 /48 最多保留(默认100; 0=不限)")
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
    if args.count_v6 is None:
        args.count_v6 = args.count

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
    nets, label, nets6 = resolve_sources(args)
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
            loop.run_until_complete(run_session(nets, known, q, args, stop, nets6=nets6))
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
        print(f"地址源: {label} | 抽样 v4 {args.count}/v6 {args.count_v6} | 验证 {args.verify} | 测带宽 {args.bench} | "
              f"端口 {','.join(map(str, args.ports))} | TLS确认 {'开' if args.tls_check else '关'} | "
              f"IPv6 {'开(' + (args.operator_v6 or '公共') + ')' if args.ipv6 else '关'} | "
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
                upsert(conn, rec, getattr(args, "country_pct", 0))
                pend += 1
                if pend >= 200:
                    conn.commit()
                    pend = 0
            elif rec["type"] == "mode":
                bud = rec.get("budgets", {})
                modes = rec.get("modes") or {}
                parts = []
                for _p in ("v4", "v6"):
                    _mi = modes.get(_p) or {}
                    parts.append(f"{_p} {cf_policy.MODE_NAMES.get(_mi.get('mode'), '?')}"
                                 f"(用{_mi.get('active', 0)}/前{_mi.get('prefixes', 0)})")
                print(f"【模式】{'，'.join(parts)}｜本轮抽样 v4 {bud.get('count')} "
                      f"v6 {bud.get('count_v6')}｜复测 {bud.get('recheck')}", flush=True)
            elif rec["type"] == "monitor":
                print(f"【值守】本批检查 {rec.get('checking', 0)} 个"
                      f"（还有 {rec.get('due', 0)} 个到期）", flush=True)
            elif rec["type"] == "monitor_end":
                pass
            elif rec["type"] in ("cycle_end", "lifecycle"):
                conn.commit()
                pend = 0
                if rec["type"] == "cycle_end":
                    print(banner(), f"｜本轮可用 {rec['ok']}", flush=True)
                try:
                    stats, deficits = cf_lifecycle.lifecycle_pass(
                        conn, args.max_ips_v4, args.max_ips_v6,
                        getattr(args, "country_pct", 0),
                        getattr(args, "target_active", 0),
                        getattr(args, "per24_max", None),
                        getattr(args, "per48_max", None))
                    conn.commit()
                    ev = sum(stats.values())
                    if ev:
                        print(f"【清理】失效 {stats['dead']}｜重复 {stats['dedup']}｜"
                              f"地区均衡 {stats['balanced']}｜超容量 {stats['capped']}", flush=True)
                    d4 = deficits.get("v4", {})
                    d6 = deficits.get("v6", {})
                    print(f"【库存】v4 可用 {d4.get('active',0)}｜备用 {d4.get('reserve',0)}｜"
                          f"待补 {d4.get('deficit_reserve',0)} ∥ v6 可用 {d6.get('active',0)}｜"
                          f"备用 {d6.get('reserve',0)}｜待补 {d6.get('deficit_reserve',0)}", flush=True)
                except Exception as e:
                    print(f"库清理失败: {e}", flush=True)
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