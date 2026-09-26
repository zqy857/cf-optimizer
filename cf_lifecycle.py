#!/usr/bin/env python3
"""
IP 生命周期: 剔除 与 补充 (闭环)

与健康度模型(cf_health)、调度策略(cf_policy)联动, 三者共用同一套"状态"口径:
  active / reserve / probation / dead   (cf_health.classify)

剔除(eviction):
  * 失效(dead)清退 —— 一律写墓碑 + 冷却, 避免同址被反复重测;
  * 前缀去重 —— 每个 v4 /24、v6 /48 最多保留 M 个(保护 pin/active/高分),
    防止同一路由邻居堆一堆、单点故障;
  * 国家均衡 —— 超额国家按质量低者先裁(保护 pin);
  * 库容上限 —— 超限按"保留价值"低者先裁(保护 pin, 其次保 active)。

补充(replenishment) —— 需求驱动:
  * 计算每协议 active 缺口 deficit 与可用 reserve 池;
  * 缺口 > 0 时优先从 reserve 提升(快速确认), 不足才触发有界探索;
  * 发现侧通过 fetch_hot24/fetch_hot_v6 的"前缀配额"避开已超额前缀 -> 不churn。

剔除与补充通过"缺口(deficit)"联动: 每轮先剔除, 再据缺口决定补位。
"""
import sqlite3
import time

import cf_health
import cf_policy

EVICT_COOLDOWN = 24 * 3600      # 被裁 IP 的墓碑静默
DEAD_SILENCE = 7 * 86400        # 失效 IP 静默
# 每个前缀的保留上限(多样性 vs 库容的平衡; 越小越"去重/多样", 库也越小).
# 默认较宽松: 只压掉病态集中(如单个 /24 堆 200+), 不破坏 1w+ 的储备规模;
# 想要严格多样(每 /24 仅留 3、每 /48 仅留 8)可在设置里调小。
PER24_MAX = 50                  # 每个 v4 /24 最多保留
PER48_MAX = 100                 # 每个 v6 /48 最多保留
GRAVE_EXPIRE_DAYS = 30
GRAVE_MAX_ROWS = 200000


def _grave_ts(now, silence):
    """使 known 冷却判断下恰好静默约 silence 秒(与 cf_db 的 eligible 约定一致)."""
    return now + silence - 3600


def _tombstone(conn, ips, now, silence):
    if not ips:
        return
    ts = _grave_ts(now, silence)
    conn.executemany("INSERT OR REPLACE INTO graveyard(ip,buried_at) VALUES(?,?)",
                     [(ip, ts) for ip in ips])


def _prefix(ip):
    return cf_policy.prefix_of(ip)


def _purge_graveyard(conn, now):
    try:
        conn.execute("DELETE FROM graveyard WHERE buried_at < ?",
                     (now - GRAVE_EXPIRE_DAYS * 86400,))
        conn.execute("DELETE FROM graveyard WHERE rowid NOT IN "
                     "(SELECT rowid FROM graveyard ORDER BY buried_at DESC LIMIT ?)",
                     (GRAVE_MAX_ROWS,))
    except Exception:
        pass


def _select_victims(conn, cond, limit, extra_order=""):
    """按"最该先裁"的顺序取受害者: pin=0 优先、非 active 优先、分数低者优先."""
    order = f"pin ASC, (CASE WHEN state='{cf_health.STATE_ACTIVE}' THEN 1 ELSE 0 END) ASC, " \
            f"COALESCE(score,0) ASC"
    return [r[0] for r in conn.execute(
        f"SELECT ip FROM ips WHERE {cond} ORDER BY {order}{extra_order} LIMIT ?",
        (int(limit),)).fetchall()]


def lifecycle_pass(conn, max_v4, max_v6, country_pct, target_active=0,
                   per24=None, per48=None, now=None):
    """一轮生命周期维护(剔除 + 计算补充缺口). 返回 (stats, deficits)."""
    per24 = int(per24) if per24 else PER24_MAX
    per48 = int(per48) if per48 else PER48_MAX
    now = now or time.time()
    stats = {"dead": 0, "dedup": 0, "balanced": 0, "capped": 0}
    _purge_graveyard(conn, now)

    # 1) 失效清退: 无有效成功记录, 或状态判为 dead
    dead = [r[0] for r in conn.execute(
        "SELECT ip FROM ips WHERE ok_count<=0 OR COALESCE(state,'')=?",
        (cf_health.STATE_DEAD,)).fetchall()]
    if dead:
        _tombstone(conn, dead, now, DEAD_SILENCE)
        conn.executemany("DELETE FROM ips WHERE ip=?", [(ip,) for ip in dead])
        stats["dead"] = len(dead)

    # 2) 前缀去重: 每个 /24、/48 保留质量最高的 M 个
    for proto, cap in (("ip NOT LIKE '%:%'", per24), ("ip LIKE '%:%'", per48)):
        rows = conn.execute(
            f"SELECT ip, pin, COALESCE(state,''), COALESCE(score,0) FROM ips "
            f"WHERE {proto}").fetchall()
        groups = {}
        for ip, pin, st, sc in rows:
            groups.setdefault(_prefix(ip), []).append((ip, pin, st, sc))
        victims = []
        for items in groups.values():
            if not cap or cap <= 0 or len(items) <= cap:
                continue
            items.sort(key=lambda x: ((x[1] or 0),
                                     1 if x[2] == cf_health.STATE_ACTIVE else 0,
                                     x[3]), reverse=True)
            for ip, pin, _st, _sc in items[cap:]:
                if pin:
                    continue
                victims.append(ip)
        if victims:
            _tombstone(conn, victims, now, EVICT_COOLDOWN)
            conn.executemany("DELETE FROM ips WHERE ip=?", [(ip,) for ip in victims])
            stats["dedup"] += len(victims)

    # 3) 国家均衡(按 colo->国家聚合), 超额低分先裁, 保护 pin
    if country_pct and int(country_pct) > 0:
        try:
            import cf_db  # 延迟导入: 复用 COLO_COUNTRY 映射
            country = cf_db._country
            for proto in ("ip NOT LIKE '%:%'", "ip LIKE '%:%'"):
                alive_cond = f"{proto} AND ok_count>0"
                alive = conn.execute(
                    f"SELECT COUNT(*) FROM ips WHERE {alive_cond}").fetchone()[0] or 0
                if alive <= 0:
                    continue
                cap = max(1, int(alive * int(country_pct) / 100))
                rows = conn.execute(
                    f"SELECT colo, COUNT(*) FROM ips WHERE {alive_cond} "
                    f"GROUP BY colo").fetchall()
                agg = {}
                for colo, cnt in rows:
                    c = country(colo) if colo else None
                    if c:
                        agg[c] = agg.get(c, 0) + cnt
                overs = [(c, cnt - cap) for c, cnt in agg.items() if cnt > cap]
                has_gap = any((cnt if colo else 0) < cap for colo, cnt in rows) \
                    or any(not colo for colo, _ in rows)
                if not overs or not has_gap:
                    continue
                for ctry, n_del in overs:
                    colos = [colo for colo, _ in rows
                             if colo and country(colo) == ctry]
                    if not colos:
                        continue
                    ph = ",".join("?" for _ in colos)
                    victims = [r[0] for r in conn.execute(
                        f"SELECT ip FROM ips WHERE {alive_cond} AND colo IN ({ph}) "
                        f"ORDER BY pin ASC, "
                        f"(CASE WHEN state='{cf_health.STATE_ACTIVE}' THEN 1 ELSE 0 END) ASC, "
                        f"COALESCE(score,0) ASC LIMIT ?",
                        tuple(colos) + (int(n_del),)).fetchall()]
                    if victims:
                        _tombstone(conn, victims, now, EVICT_COOLDOWN)
                        conn.executemany("DELETE FROM ips WHERE ip=?",
                                         [(ip,) for ip in victims])
                        stats["balanced"] += len(victims)
        except Exception:
            pass

    # 4) 库容上限: 超限按保留价值低者先裁
    for proto, limit in (("ip NOT LIKE '%:%'", max_v4), ("ip LIKE '%:%'", max_v6)):
        if not limit or int(limit) <= 0:
            continue
        alive = conn.execute(
            f"SELECT COUNT(*) FROM ips WHERE {proto}").fetchone()[0] or 0
        excess = alive - int(limit)
        if excess <= 0:
            continue
        victims = _select_victims(conn, proto, excess)
        if victims:
            _tombstone(conn, victims, now, EVICT_COOLDOWN)
            conn.executemany("DELETE FROM ips WHERE ip=?", [(ip,) for ip in victims])
            stats["capped"] += len(victims)

    deficits = replenish_need(conn, target_active, max_v4, max_v6)
    return stats, deficits


def replenish_need(conn, target_active=0, max_v4=0, max_v6=0):
    """每协议的补充需求. 语义: 只设"热目标"和"库上限", 备胎目标自动 = 上限 − 热目标.

    deficit          热缺口(active 不足): 需要发现/提升补 hot
    deficit_reserve  库容缺口(总库 < 上限): 维护期低频补备胎, 直到养到上限
    cap=0(不限) 时 reserve_goal=0, 行为退化为"到热目标即停"(不养备胎)
    """
    out = {}
    for key, proto, maxip in (("v4", "ip NOT LIKE '%:%'", max_v4),
                              ("v6", "ip LIKE '%:%'", max_v6)):
        active = conn.execute(
            f"SELECT COUNT(*) FROM ips WHERE {proto} AND state=?",
            (cf_health.STATE_ACTIVE,)).fetchone()[0] or 0
        reserve = conn.execute(
            f"SELECT COUNT(*) FROM ips WHERE {proto} AND state=?",
            (cf_health.STATE_RESERVE,)).fetchone()[0] or 0
        total = conn.execute(
            f"SELECT COUNT(*) FROM ips WHERE {proto}").fetchone()[0] or 0
        cap = int(maxip) if maxip and int(maxip) > 0 else 0
        tgt = int(target_active)
        if cap and tgt > cap:
            tgt = cap                       # 热目标不能超过库上限, 否则"补了又裁"抖动
        deficit = max(0, tgt - active)
        reserve_goal = max(0, cap - tgt) if cap else 0
        deficit_reserve = max(0, min(reserve_goal - reserve, cap - total)) if cap else 0
        out[key] = {"active": active, "reserve": reserve, "total": total,
                    "cap": cap, "target": tgt, "deficit": deficit,
                    "reserve_goal": reserve_goal, "deficit_reserve": deficit_reserve}
    return out


def fetch_promote(path, is_v6, limit, cooldown, now=None):
    """从 reserve 池取分数最高的若干 IP 用于"提升确认". 返回 [(ip, port)]."""
    proto = "ip LIKE '%:%'" if is_v6 else "ip NOT LIKE '%:%'"
    now = now or time.time()
    try:
        conn = sqlite3.connect(path)
        rows = conn.execute(
            f"SELECT ip, port FROM ips WHERE {proto} AND state=? "
            f"AND tested_at < ? ORDER BY COALESCE(score,0) DESC LIMIT ?",
            (cf_health.STATE_RESERVE, now - cooldown, limit)).fetchall()
        conn.close()
        return rows
    except Exception:
        return []
