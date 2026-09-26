#!/usr/bin/env python3
"""
扫描策略控制律 (dynamic-equilibrium policy)

核心思想: 发现只是手段, 维护才是目的。
当 IP 库达到"动态平衡"(已收集到足够多、足够新鲜、覆盖足够多前缀的优质 IP,
且继续扫描的边际收益很低)时, 自动把每轮预算从"大范围发现"转向"针对存量
IP 的健康维护", 避免长期空烧家宽; 一旦质量下滑或基础量不足, 再自动切回发现。

**IPv4 / IPv6 各自独立评估**(v4 常常很快饱和, v6 往往还差得远, 共用一个模式
会让 v4 拖住 v6): 两种协议分别维护 active/fresh/prefixes/yield 与模式状态。

三种模式:
  discovery   发现/扩张: 库不够或最近仍在持续挖到新优质 IP
  maintenance 维护/守成: 库已饱和且新鲜度达标 -> 只做小比例探索 + 到期复测
  recovery    恢复: 存量 IP 大量陈旧/失效 -> 加大复测, 先把质量拉回来
"""
import ipaddress
import threading
import time

# ---- 判定阈值 ----
ACTIVE_SCORE = 40.0                 # 质量分达到该值算"可用"
TARGET_ACTIVE = 60                  # 期望保有的可用 IP 数(动态平衡目标, 按协议各算)
TARGET_PREFIXES = 8                 # 期望覆盖的独立前缀数(抗单点/单路由故障)
HEALTHY_WINDOW = 6 * 3600           # 可用 IP 在该时长内确认过才算"新鲜"
YIELD_WINDOW = 1800                 # 统计边际发现收益的滑动窗口(秒)
YIELD_MIN = 0.02                    # 每测 1 个 IP 新增有用 IP 比例低于此 -> 不值得继续大范围扫
OVERFILL_MULT = 3                   # 可用数超过目标该倍数即视为"过量", 不再因发现率而继续扩张
DEGRADE_RATIO = 0.6                 # 新鲜可用数 < active*该比例 -> 进入恢复
HYSTERESIS = 3                      # 连续 N 轮同向才切换模式, 防抖动

# ---- 预算分配 ----
MAINT_COUNT_FRACTION = 0.15         # 维护模式抽样数 = 基础抽样数 * 该比例(保留少量探索)
MAINT_VERIFY_MIN = 8
MAINT_BENCH_MIN = 4
RECOVERY_COUNT_FRACTION = 0.5

MODES = ("discovery", "maintenance", "recovery")
MODE_NAMES = {"discovery": "发现扩张", "maintenance": "健康维护", "recovery": "质量恢复"}
PROTOS = ("v4", "v6")

_STATE = {p: {"mode": "discovery", "streak": 0} for p in PROTOS}
_LOCK = threading.Lock()


def prefix_of(ip):
    """IPv4 取 /24, IPv6 取 /64, 作为"同路由邻居"的学习/多样性单元."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.version == 4:
        return ".".join(ip.split(".")[:3])
    # v6 用 /48: CF 的 v6 anycast 以 /48 公告, 同一 /48 内地址基本都可达
    return ":".join(a.exploded.split(":")[:3])


def set_mode(mode):
    """手动强制模式(同时作用于两种协议); mode='auto' 时恢复自动判定."""
    with _LOCK:
        for p in PROTOS:
            if mode == "auto":
                _STATE[p]["streak"] = 0
            elif mode in MODES:
                _STATE[p]["mode"] = mode
                _STATE[p]["streak"] = 0


def _decide(is_v6, conn, now, target_active, target_prefixes, force):
    proto = "ip LIKE '%:%'" if is_v6 else "ip NOT LIKE '%:%'"
    out = {"mode": "discovery", "active": 0, "fresh": 0, "prefixes": 0,
           "yield": 0.0, "overdue": 0, "reason": ""}
    try:
        rows = conn.execute(
            f"SELECT ip, last_ok_at FROM ips "
            f"WHERE ok_count>0 AND COALESCE(score,0)>=? AND {proto}",
            (ACTIVE_SCORE,)).fetchall()
        active = len(rows)
        fresh = sum(1 for _, lok in rows if lok and now - lok < HEALTHY_WINDOW)
        prefixes = len({prefix_of(ip) for ip, _ in rows})
        overdue = conn.execute(
            f"SELECT COUNT(*) FROM ips WHERE next_check_at<=? AND {proto}",
            (now,)).fetchone()[0]
        probes = conn.execute(
            f"SELECT COUNT(*) FROM ips WHERE tested_at>? AND {proto}",
            (now - YIELD_WINDOW,)).fetchone()[0]
        new_active = conn.execute(
            f"SELECT COUNT(*) FROM ips WHERE first_seen>? AND ok_count>0 "
            f"AND COALESCE(score,0)>=? AND {proto}",
            (now - YIELD_WINDOW, ACTIVE_SCORE)).fetchone()[0]
        out.update(active=active, fresh=fresh, prefixes=prefixes, overdue=overdue)
        out["yield"] = round(new_active / max(1, probes), 4)
    except Exception as e:
        out["reason"] = f"evaluate failed: {e}"
        return out

    active, fresh = out["active"], out["fresh"]
    need_more = active < target_active or out["prefixes"] < target_prefixes
    overfilled = active >= target_active * OVERFILL_MULT   # 已远超目标: 不必再扩张
    if need_more:
        want, why = "discovery", "库未饱和"
    elif not overfilled and out["yield"] >= YIELD_MIN:
        want, why = "discovery", "边际收益仍高"
    elif active and fresh < active * DEGRADE_RATIO:
        want, why = "recovery", "存量大量陈旧"
    else:
        want, why = "maintenance", "库已达动态平衡"

    key = "v6" if is_v6 else "v4"
    if force in MODES:
        out["mode"] = force
        out["reason"] = f"手动: {force}"
    else:
        with _LOCK:
            st = _STATE[key]
            prev = st["mode"]
            if want == prev:
                st["streak"] = 0
                mode = prev
            else:
                st["streak"] += 1
                if st["streak"] >= HYSTERESIS:
                    st["mode"] = want
                    st["streak"] = 0
                    mode = want
                else:
                    mode = prev
        out["mode"] = mode
        out["reason"] = f"{why} (趋向 {want})"
    return out


def evaluate_all(conn, now=None, target_active=TARGET_ACTIVE,
                 target_prefixes=TARGET_PREFIXES, force="auto"):
    """分别评估 IPv4 / IPv6 的库健康与应处模式(各带迟滞). 返回 {'v4':info,'v6':info}."""
    now = now or time.time()
    return {p: _decide(p == "v6", conn, now, target_active, target_prefixes, force)
            for p in PROTOS}


def scan_count(mode, base):
    """某协议该轮抽样数: 按各自模式缩放."""
    base = max(0, int(base))
    if base <= 0:
        return 0
    if mode == "maintenance":
        return max(30, int(base * MAINT_COUNT_FRACTION))
    if mode == "recovery":
        return max(50, int(base * RECOVERY_COUNT_FRACTION))
    return base


def shared_budget(mode, base_verify, base_bench, base_recheck, active=0):
    """两协议共用的 验证/测带宽/复测 预算(取两协议中更宽松者, 见调用方 max 合并).

    复测数保持用户设定值(不随库规模放大), 具体测谁由健康度调度按到期时间决定,
    避免大库时每轮复测量失控、空烧家宽; 恢复模式适度上浮以尽快拉回新鲜度。
    """
    base_verify = max(0, int(base_verify))
    base_bench = max(0, int(base_bench))
    base_recheck = max(0, int(base_recheck))
    if mode == "maintenance":
        # 维护期仍保留测带宽预算: 补齐缺失的带宽数据本身就是"健康"的一部分,
        # 不能因为已饱和就停止测量, 否则"有带宽数据"会长期停滞。
        return {
            "verify": max(MAINT_VERIFY_MIN, base_verify // 4),
            "bench": base_bench,
            "recheck": base_recheck,
        }
    if mode == "recovery":
        return {"verify": base_verify, "bench": base_bench,
                "recheck": int(base_recheck * 1.5)}
    return {"verify": base_verify, "bench": base_bench,
            "recheck": base_recheck}
