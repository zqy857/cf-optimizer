#!/usr/bin/env python3
"""
IP 健康度模型 (health model)

把「扫描结果」抽象成一个持续衰减的质量分与分层复测计划, 让 IP 库长期保持健康:

  * 质量分 score (0~100): 可用率 + 延迟 + 带宽 + 地区已验证 + 新鲜度 的加权综合。
    可用率用 Laplace 平滑, 避免 1 次成功=100% 的假象; 新鲜度按半衰期指数衰减,
    长时间没再确认存活的 IP 分数自然下滑, 不会再"永远优秀"。
  * 复测计划 next_check_at: 分数越高复测越勤(30min), 越差越少(8h), 连续失败按
    2^n 指数退避(最多 64 倍), 既保证优质 IP 常新, 又不把预算浪费在反复失败的 IP 上。
  * 降级剔除: 曾经存活但长期(>HARD_TTL)无成功且持续失败的 IP, 会被判定失效并
    移入墓碑静默期, 交由扫描器重新发现, 避免"僵尸 IP"永久占据库容。

本模块只依赖标准库, 不碰数据库以外的状态; 供 cf_db / cf_web 共用。
"""
import time

# ---- 新鲜度 ----
FRESH_WINDOW = 3600                 # 1 小时内确认存活 => "新鲜"
SOFT_TTL = 3 * 86400                # 新鲜度半衰期(秒)
HARD_TTL = 14 * 86400               # 超过该时长无成功 => 视为失效(满足失败条件时降级)

# ---- 生命周期状态(与调度联动) ----
#   active    优质在册: 分数达标且近期确认存活 -> 高频监控
#   reserve   达标备用: 曾稳定可用但非当前热点 -> 低频监控, 缺员时提升
#   probation 观察: 近期连续失败 -> 指数退避, 恢复即回 active/reserve
#   dead      失效: 无有效成功记录 -> 交由剔除机制(墓碑+冷却)
STATE_ACTIVE = "active"
STATE_RESERVE = "reserve"
STATE_PROBATION = "probation"
STATE_DEAD = "dead"
STATES = (STATE_ACTIVE, STATE_RESERVE, STATE_PROBATION, STATE_DEAD)

# 分层监控周期(秒): active 30~60min, reserve 6~24h
ACTIVE_INT = (1800.0, 3600.0)
RESERVE_INT = (6 * 3600.0, 24 * 3600.0)
PROBATION_STREAK = 2                # 连续失败达到该值 -> 进入观察
STAGGER_JITTER = 0.15               # 到期时间抖动 ±15%, 让同周期 IP 错峰

# ---- 质量分参考值 ----
HEALTH_VERSION = 3                  # 评分/调度模型版本; 变更后启动时自动重算存量库
MAX_LAT = 1000.0                    # 延迟参考上限(ms): 0ms=>满分, >=1000ms=>0分
TARGET_BW = 100.0                   # 带宽参考(Mbps): 达到即带宽项满分(开方衰减)
W_AVAIL = 0.25                      # 可用率权重
W_LAT = 0.35                        # 延迟权重
W_BW = 0.40                         # 带宽权重(权重最高: 带宽未测不该算高分)
VERIFIED_BONUS = 0.05               # 已识别地区加分
COMPLETENESS_FLOOR = 0.55           # 数据完整度折扣下限
COMPLETENESS_SPAN = 0.45            # 完整度对折扣的影响幅度

# ---- 复测调度 ----
MIN_INTERVAL = 1800                 # 最高分优质 IP 复测间隔(30min)
MAX_INTERVAL = 8 * 3600             # 存活但低分 IP 复测间隔上限(8h)
DEAD_INTERVAL = 4 * 3600            # 已失效 IP 基础复测间隔(失败再退避)
MAX_BACKOFF_SHIFT = 6               # fail_streak 退避上限 2^6=64
MAX_INTERVAL_CAP = 7 * 86400        # 单次间隔硬上限(7d)
FLAP_FAIL_STREAK = 3                # 连续失败达到该值 + 长期无成功 => 判失效
ACTIVE_SCORE = 40.0                 # 质量分达到该值且新鲜 => active
HEALTHY_ACTIVE_WINDOW = 6 * 3600    # active 需在该时长内确认过存活


def _clamp(x, lo=0.0, hi=1.0):
    return lo if x < lo else (hi if x > hi else x)


def availability(ok_count, fail_count):
    """Laplace 平滑可用率: 1次成功不会是 100%, 1次失败也不会直接归零."""
    return (ok_count + 1.0) / (ok_count + fail_count + 2.0)


def recency(last_ok_at, now):
    """新鲜度: 距最近一次成功的时长, 半衰期 SOFT_TTL 指数衰减, 返回 0~1."""
    if not last_ok_at:
        return 0.0
    age = now - last_ok_at
    if age <= 0:
        return 1.0
    return 0.5 ** (age / SOFT_TTL)


def base_score(ok_count, fail_count, latency, bandwidth, verified):
    """时间无关的基础质量分(0~100). latency 单位 ms, bandwidth 单位 Mbps.

    关键维度(带宽/延迟)未测量时, 按"已测量的权重占比"做完整度折扣:
    数据越不全 -> 分数越低。因此"只测了延迟、没测带宽"的 IP 最高只能到
    ~53 分(黄区), 不会再仅凭连通就冲上高分; 只有真正实测过带宽的 IP 才能进绿区。
    """
    av = availability(ok_count, fail_count)
    lat = 0.0 if latency is None else _clamp(1.0 - latency / MAX_LAT)
    if bandwidth:
        bw = _clamp((bandwidth / TARGET_BW) ** 0.5)   # 开方: 高带宽边际收益递减
    else:
        bw = 0.0
    s = W_AVAIL * av + W_LAT * lat + W_BW * bw
    if verified:
        s += VERIFIED_BONUS
    known = W_AVAIL
    if latency is not None:
        known += W_LAT
    if bandwidth:
        known += W_BW
    completeness = known / (W_AVAIL + W_LAT + W_BW)
    s *= COMPLETENESS_FLOOR + COMPLETENESS_SPAN * completeness
    return round(_clamp(s) * 100.0, 2)


def score(ok_count, fail_count, latency, bandwidth, verified, last_ok_at, now=None):
    """带新鲜度衰减的最终质量分(0~100)."""
    now = now or time.time()
    base = base_score(ok_count, fail_count, latency, bandwidth, verified) / 100.0
    decay = 0.35 + 0.65 * recency(last_ok_at, now)
    return round(base * decay * 100.0, 2)


def interval(sc, ok_count, fail_streak, verified=False):
    """距离下次复测的间隔(秒). 高分勤测, 低分少测, 连续失败指数退避."""
    if ok_count <= 0:
        base = DEAD_INTERVAL
    else:
        s = _clamp((sc or 0.0) / 100.0)
        base = MAX_INTERVAL - (MAX_INTERVAL - MIN_INTERVAL) * s
        if not verified:
            base = min(MAX_INTERVAL, base * 1.5)      # 未验证地区稍降频
    backoff = 1 << min(int(fail_streak or 0), MAX_BACKOFF_SHIFT)
    return int(min(base * backoff, MAX_INTERVAL_CAP))


def next_check_at(sc, ok_count, fail_streak, last_ok_at, last_fail_at, tested_at,
                  verified=False, now=None):
    """下次复测时间.

    基准取最近一次真实探测时间(不含 now), 这样长期未被复测的 IP 会保持"逾期",
    调度器按到期时间升序即可自然地把最久未测的 IP 优先补测; 只有从未探测过
    (全为 0)的记录才用 now 兜底, 避免调度到过去。
    """
    now = now or time.time()
    last_probe = max(last_ok_at or 0.0, last_fail_at or 0.0, tested_at or 0.0)
    if last_probe <= 0:
        last_probe = now
    return last_probe + interval(sc, ok_count, fail_streak, verified)


def is_fresh(last_ok_at, now=None, window=FRESH_WINDOW):
    now = now or time.time()
    return bool(last_ok_at) and (now - last_ok_at) < window


def jitter(ip):
    """稳定的伪随机相位(±STAGGER_JITTER): 让同层、同周期的 IP 到期时间错开,
    避免"整点齐发"。基于 IP 自身哈希, 同一 IP 每次结果一致(不会漂移)。"""
    h = 2166136261
    for ch in (ip or "").encode():
        h = ((h ^ ch) * 16777619) & 0xFFFFFFFF
    return ((h % 1000) / 1000.0) * 2.0 * STAGGER_JITTER - STAGGER_JITTER


def classify(ok_count, fail_streak, sc, last_ok_at, now, verified=False):
    """由指标判定生命周期状态(纯函数), 供调度/剔除/补充共用, 保证口径一致。"""
    if (ok_count or 0) <= 0:
        return STATE_DEAD
    if (fail_streak or 0) >= PROBATION_STREAK:
        return STATE_PROBATION
    if sc >= ACTIVE_SCORE and last_ok_at and (now - last_ok_at) < HEALTHY_ACTIVE_WINDOW:
        return STATE_ACTIVE
    return STATE_RESERVE


def state_interval(state, sc, fail_streak=0, verified=False):
    """按状态给出监控周期(秒). active 短、reserve 长、probation 指数退避、dead 不调度。"""
    if state == STATE_DEAD:
        return 0.0
    if state == STATE_PROBATION:
        return float(interval(sc, 1, fail_streak, verified))
    lo, hi = ACTIVE_INT if state == STATE_ACTIVE else RESERVE_INT
    s = _clamp((sc or 0.0) / 100.0)
    return round(lo + (hi - lo) * (1.0 - s), 1)


def next_check_for(ip, state, sc, fail_streak, last_ok_at, last_fail_at, tested_at,
                   verified=False, now=None):
    """带抖动/错峰的下次监控时间; dead 直接返回探测时间以便剔除流程处理。"""
    now = now or time.time()
    if state == STATE_DEAD:
        return max(last_fail_at or 0.0, tested_at or 0.0, now)
    iv = state_interval(state, sc, fail_streak, verified)
    last_probe = max(last_ok_at or 0.0, last_fail_at or 0.0, tested_at or 0.0)
    if last_probe <= 0:
        last_probe = now
    return last_probe + iv * (1.0 + jitter(ip))


def health_refresh(conn, now=None, target_active=0):
    """按当前指标重算全库 score / next_check_at. 返回刷新行数.

    周期调用成本 O(行数); 调用方应按需限频(见 cf_db._maybe_refresh_health)。
    """
    target_active = int(target_active or 0)
    now = now or time.time()
    rows = conn.execute(
        "SELECT ip, ok_count, fail_count, fail_streak, latency_ms, lat_ewma_ms, "
        "bandwidth_mbps, bw_ewma_mbps, colo, last_ok_at, last_fail_at, tested_at, "
        "score, next_check_at, interval, state FROM ips").fetchall()
    # 第一遍: 算分 + 定 dead/probation(它们不参与 active 排名)
    parsed = []
    for (ip, ok, fail, fs, lat, latw, bw, bww, colo, lok, lfail, tested,
         old_sc, old_nxt, old_iv, old_st) in rows:
        lat_v = latw if latw is not None else lat
        bw_v = bww if bww is not None else bw
        verified = bool(colo)
        sc = score(ok, fail, lat_v, bw_v, verified, lok, now)
        if (ok or 0) <= 0:
            st = STATE_DEAD
        elif (fs or 0) >= PROBATION_STREAK:
            st = STATE_PROBATION
        else:
            st = None   # 候选: 按分数排名决定 active/reserve
        parsed.append([ip, ok, fs, sc, lok, lfail, tested, verified, st,
                       old_sc, old_nxt, old_iv, old_st])

    def _eligible(r):
        return (r[8] is None and r[3] >= ACTIVE_SCORE and r[4]
                and (now - r[4]) < HEALTHY_ACTIVE_WINDOW)

    # 第二遍: 每协议按分数排名, 前 target_active 名 -> active, 其余存活 -> reserve
    for is6 in (False, True):
        idx = [i for i, r in enumerate(parsed) if ((":" in r[0]) == is6)]
        elig = sorted((i for i in idx if _eligible(parsed[i])),
                      key=lambda i: -parsed[i][3])
        cap = target_active if target_active > 0 else len(elig)
        active_set = set(elig[:cap])
        for i in idx:
            if parsed[i][8] is None:
                parsed[i][8] = STATE_ACTIVE if i in active_set else STATE_RESERVE

    updates = []
    for r in parsed:
        (ip, ok, fs, sc, lok, lfail, tested, verified, st,
         old_sc, old_nxt, old_iv, old_st) = r
        iv = state_interval(st, sc, fs, verified)
        nxt = next_check_for(ip, st, sc, fs, lok, lfail, tested, verified, now)
        if (old_sc is None or abs(sc - old_sc) >= 0.05
                or abs(nxt - (old_nxt or 0)) >= 30
                or st != (old_st or "")
                or abs(iv - (old_iv or 0)) >= 1):
            updates.append((sc, nxt, iv, st, ip))
    if updates:
        conn.executemany(
            "UPDATE ips SET score=?, next_check_at=?, interval=?, state=? WHERE ip=?",
            updates)
    return len(updates)
