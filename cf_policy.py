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

import cf_health

# ---- 判定阈值(与 cf_health 共用同一口径, 避免各算各的) ----
ACTIVE_SCORE = cf_health.ACTIVE_SCORE       # 质量分达到该值算"可用"
HEALTHY_WINDOW = cf_health.HEALTHY_ACTIVE_WINDOW
TARGET_ACTIVE = 60                  # 期望保有的可用 IP 数(动态平衡目标, 按协议各算)
TARGET_PREFIXES = 8                 # 期望覆盖的独立前缀数(抗单点/单路由故障)
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

# ---- 监控节奏(库满/平衡后, 事件驱动而非一轮轮空转) ----
IDLE_CAP = 15 * 60                  # 无到期 IP 时最长休眠(秒)
EXPLORE_INTERVAL = 30 * 60          # 值守期低频探索间隔(秒): 定期找有没有更好的IP
EXPLORE_FRACTION = 0.1              # 值守探索抽样 = 基础抽样数 * 该比例(温和, 不空烧)
MONITOR_TICK = 60                   # 维护监控的最小节拍: 每 tick 处理一批到期 IP(秒)
MONITOR_BATCH = 200                 # 每个 tick 最多处理的到期 IP 数(限速)
LIFE_INTERVAL = 300                 # 纯监控期做一次生命周期维护(剔除/补充判定)的间隔(秒)
FILL_FRACTION = 0.3                 # "填充库容"阶段: 每轮抽样 = 基础抽样数 * 该比例(温和但持续, 直到达上限)
DEFAULT_DEFICIT_ACTIVE = 200        # 未指定时的 active 目标(缺员即触发补充)

MODES = ("discovery", "maintenance", "recovery")
MODE_NAMES = {"discovery": "发现扩张", "maintenance": "健康维护", "recovery": "质量恢复"}
PROTOS = ("v4", "v6")

_STATE = {p: {"mode": "discovery", "streak": 0, "inited": False} for p in PROTOS}
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
                _STATE[p]["inited"] = False   # 下一个评估立即重新定模式
            elif mode in MODES:
                _STATE[p]["mode"] = mode
                _STATE[p]["streak"] = 0
                _STATE[p]["inited"] = True


def _decide(is_v6, conn, now, target_active, target_prefixes, force):
    proto = "ip LIKE '%:%'" if is_v6 else "ip NOT LIKE '%:%'"
    out = {"mode": "discovery", "active": 0, "fresh": 0, "prefixes": 0,
           "yield": 0.0, "overdue": 0, "reason": ""}
    try:
        # 与生命周期/补充统一口径: active = state='active'(分数达标且近期确认过)
        rows = conn.execute(
            f"SELECT ip, last_ok_at FROM ips WHERE state=? AND {proto}",
            (cf_health.STATE_ACTIVE,)).fetchall()
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
            f"SELECT COUNT(*) FROM ips WHERE first_seen>? AND state=? AND {proto}",
            (now - YIELD_WINDOW, cf_health.STATE_ACTIVE)).fetchone()[0]
        out.update(active=active, fresh=fresh, prefixes=prefixes, overdue=overdue)
        out["yield"] = round(new_active / max(1, probes), 4)
    except Exception as e:
        out["reason"] = f"evaluate failed: {e}"
        return out

    active, fresh = out["active"], out["fresh"]
    degraded = active > 0 and fresh < active * DEGRADE_RATIO
    need_more = active < target_active or out["prefixes"] < target_prefixes
    if need_more:
        want, why = "discovery", "未达目标"
    elif target_active > 0:
        # 有明确目标: 达标即转维护(不再因"发现率"一直挖), 备胎由维护期低频补
        if degraded:
            want, why = "recovery", "存量陈旧"
        else:
            want, why = "maintenance", "已达目标"
    else:
        # 无目标(不限): 沿用"边际收益"判断
        overfilled = active >= int(target_active) * OVERFILL_MULT
        if not overfilled and out["yield"] >= YIELD_MIN:
            want, why = "discovery", "边际收益仍高"
        elif degraded:
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
            if not st.get("inited"):
                # 首次评估直接采用目标模式, 避免"开局先跑几轮完整发现"才切换
                st["mode"] = want
                st["inited"] = True
                st["streak"] = 0
                mode = want
            elif want == prev:
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
    # 深度处理(识别/送测)不再单独限流: 0 表示不限, 数量由 复测批量/地区补全/抽样数 自然决定
    verify = base_verify if base_verify > 0 else 10 ** 9
    if mode == "maintenance":
        return {"verify": verify, "bench": base_bench, "recheck": base_recheck}
    if mode == "recovery":
        return {"verify": verify, "bench": base_bench,
                "recheck": int(base_recheck * 1.5)}
    return {"verify": verify, "bench": base_bench, "recheck": base_recheck}
