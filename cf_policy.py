#!/usr/bin/env python3
"""
扫描策略控制律 (dynamic-equilibrium policy)

核心思想: 发现只是手段, 维护才是目的。
当 IP 库达到"动态平衡"(已收集到足够多、足够新鲜、覆盖足够多前缀的优质 IP,
且继续扫描的边际收益很低)时, 自动把每轮预算从"大范围发现"转向"针对存量
IP 的健康维护", 避免长期空烧家宽; 一旦质量下滑或基础量不足, 再自动切回发现。

三种模式:
  discovery   发现/扩张: 库不够或最近仍在持续挖到新优质 IP
  maintenance 维护/守成: 库已饱和且新鲜度达标 -> 只做小比例探索 + 到期复测
  recovery    恢复: 存量 IP 大量陈旧/失效 -> 加大复测, 先把质量拉回来

指标(全部由数据库实时计算, 无外部状态):
  active/fresh   质量分达标的 IP 数 / 其中近期仍确认存活的
  prefixes       有效 IP 覆盖的独立前缀(去重 /24 或 /64)数 -> 衡量多样性
  yield          近 YIELD_WINDOW 内"每测一个 IP 新增的有用 IP"比例 -> 边际收益
"""
import ipaddress
import threading
import time

# ---- 判定阈值 ----
ACTIVE_SCORE = 40.0                 # 质量分达到该值算"可用"
TARGET_ACTIVE = 60                  # 期望保有的可用 IP 数(动态平衡目标)
TARGET_PREFIXES = 8                 # 期望覆盖的独立前缀数(抗单点/单路由故障)
HEALTHY_WINDOW = 6 * 3600           # 可用 IP 在该时长内确认过才算"新鲜"
YIELD_WINDOW = 1800                 # 统计边际发现收益的滑动窗口(秒)
YIELD_MIN = 0.02                    # 每测 1 个 IP 新增有用 IP 比例低于此 -> 不值得继续大范围扫
DEGRADE_RATIO = 0.6                 # 新鲜可用数 < active*该比例 -> 进入恢复
HYSTERESIS = 3                      # 连续 N 轮同向才切换模式, 防抖动

# ---- 预算分配 ----
MAINT_COUNT_FRACTION = 0.15         # 维护模式下每轮抽样数 = 基础抽样数 * 该比例(保留少量探索)
MAINT_VERIFY_MIN = 8
MAINT_BENCH_MIN = 4
RECOVERY_COUNT_FRACTION = 0.5

MODES = ("discovery", "maintenance", "recovery")
MODE_NAMES = {"discovery": "发现扩张", "maintenance": "健康维护", "recovery": "质量恢复"}
_STATE = {"mode": "discovery", "streak": 0}
_LOCK = threading.Lock()


def prefix_of(ip):
    """IPv4 取 /24, IPv6 取 /64, 作为"同路由邻居"的学习/多样性单元."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.version == 4:
        return ".".join(ip.split(".")[:3])
    return ":".join(a.exploded.split(":")[:4])


def set_mode(mode):
    """手动强制模式; mode 为 'auto' 时恢复自动判定."""
    with _LOCK:
        if mode == "auto":
            _STATE["streak"] = 0
        elif mode in MODES:
            _STATE["mode"] = mode
            _STATE["streak"] = 0


def evaluate(conn, now=None, target_active=TARGET_ACTIVE,
             target_prefixes=TARGET_PREFIXES, force="auto"):
    """计算库当前健康概览并给出应处模式(带迟滞)。返回 dict, 不抛异常。"""
    now = now or time.time()
    out = {"mode": "discovery", "active": 0, "fresh": 0, "prefixes": 0,
           "yield": 0.0, "overdue": 0, "target_active": target_active,
           "target_prefixes": target_prefixes, "reason": ""}
    try:
        rows = conn.execute(
            "SELECT ip, last_ok_at FROM ips "
            "WHERE ok_count>0 AND COALESCE(score,0)>=?",
            (ACTIVE_SCORE,)).fetchall()
        active = len(rows)
        fresh = sum(1 for _, lok in rows if lok and now - lok < HEALTHY_WINDOW)
        prefixes = len({prefix_of(ip) for ip, _ in rows})
        overdue = conn.execute(
            "SELECT COUNT(*) FROM ips WHERE next_check_at<=?", (now,)).fetchone()[0]
        probes = conn.execute(
            "SELECT COUNT(*) FROM ips WHERE tested_at>?", (now - YIELD_WINDOW,)).fetchone()[0]
        new_active = conn.execute(
            "SELECT COUNT(*) FROM ips WHERE first_seen>? AND ok_count>0 "
            "AND COALESCE(score,0)>=?",
            (now - YIELD_WINDOW, ACTIVE_SCORE)).fetchone()[0]
        out.update(active=active, fresh=fresh, prefixes=prefixes, overdue=overdue)
        out["yield"] = round(new_active / max(1, probes), 4)
    except Exception as e:
        out["reason"] = f"evaluate failed: {e}"
        return out

    active, fresh = out["active"], out["fresh"]
    need_more = active < target_active or out["prefixes"] < target_prefixes
    still_productive = out["yield"] >= YIELD_MIN
    if need_more or still_productive:
        want = "discovery"
        why = ("库未饱和" if need_more else "边际收益仍高")
    elif active and fresh < active * DEGRADE_RATIO:
        want = "recovery"
        why = "存量大量陈旧"
    else:
        want = "maintenance"
        why = "库已达动态平衡"

    if force in MODES:
        mode = force
        out["reason"] = f"手动: {force}"
    else:
        with _LOCK:
            prev = _STATE["mode"]
            if want == prev:
                _STATE["streak"] = 0
                mode = prev
            else:
                _STATE["streak"] += 1
                if _STATE["streak"] >= HYSTERESIS:
                    _STATE["mode"] = want
                    _STATE["streak"] = 0
                    mode = want
                else:
                    mode = prev
        out["reason"] = f"{why} (趋向 {want})"
    out["mode"] = mode
    return out


def budgets(mode, base_count, base_verify, base_bench, base_recheck, active=0,
            base_count_v6=None, has_v4=True, has_v6=True):
    """按模式把每轮预算从发现/维护之间重新分配(v4/v6 抽样数各自独立)."""
    base_count = max(0, int(base_count)) if has_v4 else 0
    base_count_v6 = (max(0, int(base_count_v6 if base_count_v6 is not None else base_count))
                     if has_v6 else 0)
    base_verify = max(0, int(base_verify))
    base_bench = max(0, int(base_bench))
    base_recheck = max(0, int(base_recheck))
    if mode == "maintenance":
        frac, floor = MAINT_COUNT_FRACTION, 30
    elif mode == "recovery":
        frac, floor = RECOVERY_COUNT_FRACTION, 50
    else:
        frac, floor = 1.0, 1

    def scale(n, f, lo):
        return max(lo, int(n * f)) if n > 0 else 0

    if mode == "maintenance":
        verify = max(MAINT_VERIFY_MIN, base_verify // 4)
        bench = max(MAINT_BENCH_MIN, base_bench // 4) if base_bench else 0
        recheck = max(base_recheck, active * 2)
    elif mode == "recovery":
        verify, bench = base_verify, base_bench
        recheck = max(base_recheck, base_count, active * 2)
    else:
        verify, bench = base_verify, base_bench
        recheck = max(base_recheck, max(20, active // 2))
    return {
        "count": scale(base_count, frac, floor),
        "count_v6": scale(base_count_v6, frac, max(10, floor // 2)),
        "verify": verify,
        "bench": bench,
        "recheck": recheck,
    }
