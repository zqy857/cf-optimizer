#!/usr/bin/env python3
"""
路由线路分类探测模块 (route_probe)

独立模块, 不破坏 cf_db.py / cf_web.py 原有逻辑, 通过函数调用接入。

功能:
  * TTL 递增的轻量 ICMP traceroute (无需 root, 兼容 Linux / Windows)
  * 离线 IP->ASN 查询 (pyasn 离线数据库), 首次运行自动下载并构建本地 dat 文件
  * 按固定 AS 基准表分类: premium / common / mixed / undetected

=====================================================================
AS 基准表 (严格遵守, 禁止自行修改):
  精品跨境AS (仅命中国际段才算精品, 共3个):
    AS4809  -> 电信 CN2-GIA 国际精品
    AS9929  -> 联通 CUII-9929 国际精品
    AS58807 -> 移动 CMIN2 国际精品
  普通骨干AS:
    AS4134  -> 电信163普通骨干
    AS4837  -> 联通169普通骨干
    AS9808  -> 移动普通CMI出口
  绝对禁止判定为精品的 AS (必须归入普通/忽略):
    AS23764 -> CTGNet 电信海外中转 (不是 CN2-GIA 核心, 不算精品)
    AS58453 -> 移动国内城域网 (只是国内内网, 不是 CMIN2 国际精品)

分类枚举 (数据库存英文, 前端展示中文):
  premium    -> 🏆 精品互联线路
  common     -> ⚡ 普通国际线路
  mixed      -> 🔀 混合互联线路
  undetected -> 🧪 无法判定路由

判定逻辑:
  1. 只以「跨境出海段」的 AS 号为准, 国内城域网跳不参与精品判定
  2. 路由中出现任意一个精品 AS  -> premium
  3. 只出现普通骨干 AS, 无精品  -> common
  4. 同时出现精品 AS + 普通骨干 -> mixed
  5. 有效路由跳少于3跳 / 大量*号丢包 / Cloudflare 拦截ICMP 无法识别
     -> 统一标记 undetected, 禁止强行猜测线路

约束:
  * 线路分类属于「本次测速记录」的属性, 不是 IP 固有属性;
    同一 IP 换运营商网络测速结果可以不同。禁止给 IP 主表加永久 is_premium 字段。
  * 禁止把精品标签作为 IP 排序权重依据。
  * 禁止调用在线 HTTP 接口做逐跳 AS 查询 (仅首次构建离线库时下载一次)。
=====================================================================
"""

import gzip
import ipaddress
import os
import re
import subprocess
import sys
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DAT_FILE = os.path.join(BASE_DIR, "ipasn-v4.dat")
TSV_GZ = os.path.join(BASE_DIR, "ip2asn-v4.tsv.gz")
IPASN_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"

# ------------------------- AS 基准表 (禁止修改) -------------------------
PREMIUM_ASN = {4809, 9929, 58807}          # 精品跨境AS (仅3个)
COMMON_ASN = {4134, 4837, 9808}            # 普通骨干AS
FORBIDDEN_PREMIUM_ASN = {23764, 58453}     # 绝对禁止判定为精品, 归入普通/忽略
ALL_INTEREST_ASN = PREMIUM_ASN | COMMON_ASN | FORBIDDEN_PREMIUM_ASN

ROUTE_CLASS_LABEL = {
    "premium": "🏆 精品互联线路",
    "common": "⚡ 普通国际线路",
    "mixed": "🔀 混合互联线路",
    "undetected": "🧪 无法判定路由",
}

# 去程检测提示 (Web 端必须展示)
ROUTE_HINT = ("路由检测仅识别去程方向，无法探测回程；晚高峰卡顿多由回程链路导致，"
              "实际体验请以延迟、抖动、丢包、下载速度为准。")

# 常见 AS 名称表 (展示用, 不影响判定)
AS_NAMES = {
    4134: "电信163", 4837: "联通169", 9808: "移动CMNET",
    4809: "电信CN2-GIA", 9929: "联通CUII", 58807: "移动CMIN2",
    23764: "电信CTGNet", 58453: "移动CMI", 10099: "联通CUG",
    13335: "Cloudflare", 15169: "Google", 20940: "Akamai",
    9009: "M247", 20473: "Vultr", 63949: "Linode",
    45102: "阿里云", 37963: "阿里云", 16509: "Amazon",
}


def _as_name(asn):
    if asn is None:
        return "未知"
    return AS_NAMES.get(asn, "AS%d" % asn)


def _is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


# 并行发包线程池: 全局共享, 限制同时ping进程数, 避免大量IP同时探测时进程爆炸
_PROBE_POOL = ThreadPoolExecutor(max_workers=10, thread_name_prefix="probe")


# ------------------------------- ICMP 探测 ------------------------------
_SRC_RE = re.compile(r"(?:From|来自|Reply from)\s+(\d{1,3}(?:\.\d{1,3}){3})")
_SRC_RE6 = re.compile(r"(?:From|来自|Reply from)\s+([0-9a-fA-F:]+)")
_TIME_RE = re.compile(r"(?:time|時間|时间)[=:]\s*(\d+(?:\.\d+)?)\s*(?:ms|毫秒)")
_EXPIRED_RE = re.compile(r"超过生存时间|time to live exceeded|TTL expired|已过期|过期")
_ERR_RE = re.compile(
    r"(?:无效|未知|无法识别|不能识别|错误)的?选项|invalid option|unknown option|"
    r"usage:|not found|未找到|找不到|No such file|"
    r"Operation not permitted|权限不够|不允许的操作|需要 root|requires root|"
    r"no permission|permission denied|权限不足")


class PingProbeError(RuntimeError):
    """ping 命令本身不可用/参数不支持/权限不足等导致探测失败 (区别于单纯超时)"""


def _ping_cmd(ip, ttl, timeout):
    """TTL=ttl 的单包 ping; Linux 用 -t, Windows 用 -i, 均无需 root; 按地址族选 -4/-6"""
    family = "-6" if ":" in ip else "-4"
    if sys.platform.startswith("win"):
        return ["ping", family, "-n", "1", "-i", str(ttl), "-w", str(int(timeout * 1000)), ip]
    return ["ping", family, "-n", "-c", "1", "-t", str(ttl), "-W", str(int(timeout)), ip]


def probe_hops(ip, max_hops=18, timeout=1.5):
    """TTL 递增轻量 traceroute (各TTL并行发包, 资源有上限)。

    返回 (log, timeouts, reached):
      log      逐跳日志列表, 每跳 {"n":ttl,"ip":str|None,"time":ms|None,"target":bool}
               时间解析失败/无响应时 ip 为 None (相当于 *); target=True 表示收到目标回包
      timeouts 无响应(相当于 *) 的跳数
      reached  是否收到目标回包
    """
    def _run(ttl):
        try:
            r = subprocess.run(
                _ping_cmd(ip, ttl, timeout),
                capture_output=True, text=True, timeout=timeout + 1)
            return r.stdout + r.stderr
        except FileNotFoundError:
            raise PingProbeError("系统缺少 ping 命令")
        except Exception:
            return None

    srcre = _SRC_RE6 if ":" in ip else _SRC_RE
    outs = list(_PROBE_POOL.map(_run, range(1, max_hops + 1)))
    log = []
    timeouts = 0
    reached = False
    for ttl, out in enumerate(outs, 1):
        if reached:
            break
        if out is None:
            log.append({"n": ttl, "ip": None, "time": None, "target": False})
            timeouts += 1
            continue
        if _ERR_RE.search(out):
            msg = re.sub(r"\s+", " ", out.strip())[:200]
            raise PingProbeError(msg)
        mt = _TIME_RE.search(out)
        tm = float(mt.group(1)) if mt else None
        if tm is not None and not _EXPIRED_RE.search(out):
            reached = True
            log.append({"n": ttl, "ip": ip, "time": round(tm, 1), "target": True})
            break
        m = srcre.search(out)
        if m:
            src = m.group(1)
            if src == ip:
                timeouts += 1
                log.append({"n": ttl, "ip": None, "time": None, "target": False})
                continue
            log.append({"n": ttl, "ip": src,
                        "time": round(tm, 1) if tm is not None else None,
                        "target": False})
        else:
            log.append({"n": ttl, "ip": None, "time": None, "target": False})
            timeouts += 1
    return log, timeouts, reached


# --------------------------- 离线 IP->ASN 查询 --------------------------
_ASN_DB = None
_ASN_LOCK = threading.Lock()


def _range_to_cidr(start, end):
    """ip2asn 起止地址段 -> 最小 CIDR"""
    s = int(ipaddress.IPv4Address(start))
    e = int(ipaddress.IPv4Address(end))
    bits = (s ^ e).bit_length()
    mask = ((1 << bits) - 1) if bits else 0
    net = ipaddress.IPv4Address(s & ~mask)
    return "{}/{}".format(net, 32 - bits)


def _download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "cf-optimizer/route-probe"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        with open(dest, "wb") as fh:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                fh.write(chunk)


def _build_dat(tsv_gz, dat_file):
    """把 ip2asn-v4.tsv.gz (start end asn country holder) 转成 pyasn 文本 dat"""
    tmp = dat_file + ".tmp"
    n = 0
    with gzip.open(tsv_gz, "rt", encoding="utf-8") as fin, open(tmp, "w", encoding="ascii") as fout:
        fout.write("; IP-ASN32-DAT file\n; Source: %s\n" % IPASN_URL)
        for line in fin:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            start, end, asn = parts[0], parts[1], parts[2]
            if not asn.isdigit() or int(asn) == 0:
                continue
            try:
                cidr = _range_to_cidr(start, end)
            except Exception:
                continue
            fout.write("%s\t%s\n" % (cidr, asn))
            n += 1
    os.replace(tmp, dat_file)
    return n


def ensure_db(force=False):
    """确保本地 pyasn 离线数据库就绪 (缺失则下载并构建), 返回 pyasn 实例"""
    global _ASN_DB
    if _ASN_DB is not None and not force:
        return _ASN_DB
    with _ASN_LOCK:
        if _ASN_DB is not None and not force:
            return _ASN_DB
        if not os.path.exists(DAT_FILE) or force:
            if not os.path.exists(TSV_GZ) or force:
                _download(IPASN_URL, TSV_GZ)
            _build_dat(TSV_GZ, DAT_FILE)
        import pyasn
        _ASN_DB = pyasn.pyasn(DAT_FILE)
        return _ASN_DB


def lookup_asn(ip, db=None):
    """IP -> ASN (离线), 查不到返回 None"""
    try:
        if db is None:
            db = ensure_db()
        res = db.lookup(ip)
        if res:
            return res[0]
    except Exception:
        pass
    return None


# ------------------------------- 线路判定 -------------------------------
def _dedup_asn(asns):
    """按出现顺序去重, 返回排序后的 AS 编号字符串列表"""
    seen = set()
    order = []
    for a in asns:
        if a and a not in seen:
            seen.add(a)
            order.append(a)
    return [str(a) for a in sorted(order)]


def classify_route(ip, max_hops=18, timeout=1.5):
    """探测 IP 并分类线路。

    返回 dict:
      route_class  premium / common / mixed / undetected
      as_list     探测到的跨境相关 AS 编号列表 (JSON 可序列化)
      hops        逐跳日志 [{n,ip,time,asn,name,target}], 可直接 JSON 序列化存储
    """
    if ":" in ip:
        # IPv6 暂不做 ASN 判定(离线库只有 v4 数据), 只记录逐跳; 分类统一 undetected
        try:
            log, _timeouts, _reached = probe_hops(ip, max_hops=max_hops, timeout=timeout)
        except PingProbeError as e:
            return {"route_class": "undetected", "as_list": [], "hops": [], "error": str(e)}
        for h in log:
            if h["ip"] is None:
                h["asn"] = None
                h["name"] = "超时(*)"
            elif _is_private(h["ip"]):
                h["asn"] = None
                h["name"] = "内网"
            else:
                h["asn"] = None
                h["name"] = "未知"
        return {"route_class": "undetected", "as_list": [], "hops": log}
    try:
        db = ensure_db()
    except Exception:
        return {"route_class": "undetected", "as_list": [], "hops": []}
    try:
        log, _timeouts, _reached = probe_hops(ip, max_hops=max_hops, timeout=timeout)
    except PingProbeError as e:
        return {"route_class": "undetected", "as_list": [], "hops": [], "error": str(e)}

    asns = []
    for h in log:
        if h["ip"] is None:
            h["asn"] = None
            h["name"] = "超时(*)"
            continue
        a = lookup_asn(h["ip"], db=db)
        h["asn"] = a
        if a:
            h["name"] = _as_name(a)
        elif _is_private(h["ip"]):
            h["name"] = "内网"
        else:
            h["name"] = "未知"
        if a and not h["target"]:
            asns.append(a)

    # 有效路由跳 <3 跳 -> 无法判定 (禁止强行猜测)
    n_valid = sum(1 for h in log if h["ip"] and not h["target"])
    if n_valid < 3:
        return {"route_class": "undetected", "as_list": _dedup_asn(asns), "hops": log}

    interest = [a for a in asns if a in ALL_INTEREST_ASN]
    if not interest:
        # 有跳数但无法识别跨境AS (大量*号/CF拦截ICMP等) -> undetected
        return {"route_class": "undetected", "as_list": _dedup_asn(asns), "hops": log}

    has_premium = any(a in PREMIUM_ASN for a in interest)
    has_common = any(a in COMMON_ASN or a in FORBIDDEN_PREMIUM_ASN for a in interest)
    if has_premium and has_common:
        return {"route_class": "mixed", "as_list": _dedup_asn(interest), "hops": log}
    if has_premium:
        return {"route_class": "premium", "as_list": _dedup_asn(interest), "hops": log}
    return {"route_class": "common", "as_list": _dedup_asn(interest), "hops": log}


def get_class_label(route_class):
    return ROUTE_CLASS_LABEL.get(route_class, route_class)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="路由线路分类探测: 单测一个IP")
    ap.add_argument("ip", help="要探测的 IP")
    args = ap.parse_args()
    res = classify_route(args.ip)
    print("route_class:", res["route_class"])
    print("as_list:", res["as_list"])
    print("hops:")
    for h in res["hops"]:
        print("  %2d  %-15s  %-20s  %s%s" % (
            h["n"], h["ip"] or "*",
            (("AS%d" % h["asn"]) if h.get("asn") else h.get("name", "")),
            (("%sms" % h["time"]) if h.get("time") is not None else "-"),
            "  ✓目标" if h.get("target") else ""))