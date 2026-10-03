#!/usr/bin/env python3
"""
IP 剔除(eviction): 纯按"超了就裁"的三件事。

与健康度模型(cf_health)、调度策略(cf_policy)共用同一套"状态"口径
(active / reserve / probation / dead, 见 cf_health.classify), 保证三边不各算各的。

  1. 失效清退 —— 一律写墓碑 + 冷却, 避免同址被反复重测
  2. 地区均衡 —— 单个国家占比超上限时, 按质量低者先裁(保护 pin)
  3. 库容上限 —— 超限按"保留价值"低者先裁(保护 pin, 其次保 active)

被裁掉的 IP 写进 graveyard 表, 在墓碑静默期内不会被重新发现/抽到
(见 cf_db 的 known 冷却判断)。墓碑按 buried_at 自行过期回收。

换血节流: 观测到不加限制时每轮能裁掉 170+ 个、整轮换血 300+, 而一轮只测
20 个带宽, 库 5 天就整体换一遍 -> IP 站不住、榜单一直翻新。所以地区均衡和
库容上限都加了每轮上限与滞回。

"补充"不在这里: 发现量完全由 cf_policy.decide 的 4 条规则按缺口决定,
不需要独立的补位流程。
"""
import sqlite3
import time

import cf_health

EVICT_COOLDOWN = 24 * 3600      # 被裁 IP 的墓碑静默
DEAD_SILENCE = 7 * 86400        # 失效 IP 静默
# 换血节流: 每轮"地区均衡"最多裁掉存活数的千分之三; 库容超 上限*1.05 才裁
BALANCE_TRIM_PCT = 0.3
CAP_SLACK = 1.05
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


def lifecycle_pass(conn, max_v4, max_v6, country_pct=0, now=None,
                   balance_trim_pct=None, cap_slack=None):
    """一轮剔除。返回 stats(各步各删了多少条)。"""
    trim_pct = float(balance_trim_pct) if balance_trim_pct is not None else BALANCE_TRIM_PCT
    slack = float(cap_slack) if cap_slack else CAP_SLACK
    now = now or time.time()
    stats = {"dead": 0, "balanced": 0, "capped": 0}
    _purge_graveyard(conn, now)

    # 1) 失效清退: 无有效成功记录, 或状态判为 dead
    dead = [r[0] for r in conn.execute(
        "SELECT ip FROM ips WHERE ok_count<=0 OR COALESCE(state,'')=?",
        (cf_health.STATE_DEAD,)).fetchall()]
    if dead:
        _tombstone(conn, dead, now, DEAD_SILENCE)
        conn.executemany("DELETE FROM ips WHERE ip=?", [(ip,) for ip in dead])
        stats["dead"] = len(dead)

    # 2) 地区均衡(按 colo->国家聚合), 超额的低分先裁, 保护 pin
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
                # 每轮裁剪上限: 其余超额留到后面的轮次, 避免"一轮砍掉 170+ 个"
                budget = max(1, int(alive * trim_pct / 100.0))
                overs = [(c, min(n, budget)) for c, n in overs]
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

    # 3) 库容上限: 超限按保留价值低者先裁
    for proto, limit in (("ip NOT LIKE '%:%'", max_v4), ("ip LIKE '%:%'", max_v6)):
        if not limit or int(limit) <= 0:
            continue
        alive = conn.execute(
            f"SELECT COUNT(*) FROM ips WHERE {proto}").fetchone()[0] or 0
        # 滞回: 顶格时每插一个就裁一个, 等于每轮强制换血。留出 slack 带,
        # 只在明显超限时才裁(用户也可以直接把上限调大)。
        excess = alive - max(int(limit), int(int(limit) * slack))
        if excess <= 0:
            continue
        victims = _select_victims(conn, proto, excess)
        if victims:
            _tombstone(conn, victims, now, EVICT_COOLDOWN)
            conn.executemany("DELETE FROM ips WHERE ip=?", [(ip,) for ip in victims])
            stats["capped"] += len(victims)

    return stats


def fetch_promote(path, is_v6, limit, cooldown, now=None):
    """从 reserve 池取分数最高的若干 IP 用于"提升确认"。返回 [(ip, port)]。"""
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