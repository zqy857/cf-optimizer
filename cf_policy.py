#!/usr/bin/env python3
"""
扫描策略: 只按"缺口"决定这一轮扫多少 —— 没有模式、没有迟滞、没有状态机。

全部规则就 4 条(v4 / v6 各自独立判断, 互不影响):

  1. 可用IP不足目标          -> 按你设定的量发现          (阶段: 发现)
  2. 库容低于上限            -> 按设定量的 30% 温和补库容   (阶段: 补库容)
  3. 都不够, 且距上次探索    -> 按设定量的 10% 低频找更优   (阶段: 探索)
     已超过 explore_interval
  4. 其余                    -> 不发现, 只做到期复测        (阶段: 值守)

**为什么不需要"三模式 + 迟滞"**:
每轮抽样量本来就由缺口决定, 旧的三模式(discovery / maintenance / recovery
+ 3 轮迟滞 + 手动 force)除了两件边角事之外什么都不做:
  * recovery 时把复测量放大 1.5 倍 —— 而到期复测本来就优先挑 next_check_at
    最早的(active 复测间隔最短, 必然排最前), 那点放大是边际收益;
  * target_active<=0(无目标)时改看"边际发现率" —— 本项目一直有目标, 死分支。
旧实现 210 行, 实际只有界面上的"扫描策略"下拉框在用它, 而它一直是 auto。
整块删除。

**为什么这样不会抖动/过冲**:
health_refresh 按质量分排名, 把 active 硬卡在 target_active 个, 所以
"不足就扫、够了就歇"是个自限开关 —— 不存在"扫过头再回调"的余地, 也就
不需要迟滞去平滑。active 掉到目标以下时下一轮立刻补回来。
"""
import time

import cf_health

# ---- 抽样比例 ----
FILL_FRACTION = 0.3                 # 补库容阶段: 设定量 x 该比例(上限)
EXPLORE_FRACTION = 0.1              # 低频探索阶段: 设定量 x 该比例
FILL_MIN = 50                       # 补库容阶段每轮至少扫多少(太小攒不起来)
EXPLORE_MIN = 20                    # 低频探索阶段每轮至少扫多少

# ---- 值守节奏(事件驱动, 不空转) ----
IDLE_CAP = 15 * 60                  # 没有到期 IP 时最长休眠(秒)
MONITOR_TICK = 60                   # 值守期最小节拍: 每个 tick 处理一批到期 IP(秒)
MONITOR_BATCH = 200                 # 每个 tick 最多处理的到期 IP 数(限速)
LIFE_INTERVAL = 300                 # 值守期做一次剔除的间隔(秒)

PHASE_NAMES = {"discover": "发现", "fill": "补库容",
               "explore": "探索", "monitor": "值守"}
PHASE_ORDER = ("discover", "fill", "explore", "monitor")

PROTOS = (("v4", "ip NOT LIKE '%:%'"), ("v6", "ip LIKE '%:%'"))


def decide(conn, target_active=0, max_v4=0, max_v6=0,
           count=0, count_v6=0, explore_due=False,
           explore_fraction=EXPLORE_FRACTION, now=None):
    """算出这一轮每个协议该发现多少个 IP。返回 {proto: {...}} + 汇总字段。

    target_active  可用IP目标(每协议各算)
    max_v4/max_v6  库容上限(0=不限); 备胎目标自动 = 上限 - 可用目标
    count/count_v6 每轮发现量(你设定的值)
    explore_due    值守期低频探索是否到点
    """
    now = now or time.time()
    tgt_all = max(0, int(target_active or 0))
    frac = max(0.0, float(explore_fraction))
    out = {}
    for key, proto, base, maxip in (("v4", PROTOS[0][1], count, max_v4),
                                    ("v6", PROTOS[1][1], count_v6, max_v6)):
        base = max(0, int(base or 0))
        cap = int(maxip or 0)
        # 可用IP: 质量分达标且近期确认过存活(cf_health 的 active 口径)
        act_rows = conn.execute(
            f"SELECT ip, last_ok_at FROM ips WHERE {proto} AND state=?",
            (cf_health.STATE_ACTIVE,)).fetchall()
        active = len(act_rows)
        fresh = sum(1 for _, lok in act_rows if lok and now - lok < cf_health.HEALTHY_ACTIVE_WINDOW)
        reserve = conn.execute(
            f"SELECT COUNT(*) FROM ips WHERE {proto} AND state=?",
            (cf_health.STATE_RESERVE,)).fetchone()[0] or 0
        total = conn.execute(
            f"SELECT COUNT(*) FROM ips WHERE {proto}").fetchone()[0] or 0

        # 热目标不能超过库上限, 否则"补满了又裁"来回抖
        tgt = min(tgt_all, cap) if cap > 0 else tgt_all
        deficit = max(0, tgt - active)
        # 备胎目标 = 上限 - 热目标; 只需养到上限, 不会把库撑爆
        reserve_goal = max(0, cap - tgt_all) if cap > 0 else 0
        deficit_reserve = max(0, min(reserve_goal - reserve, cap - total)) if cap > 0 else 0

        # ---- 4 条规则 ----
        if deficit > 0:
            n, phase = base, "discover"
        elif deficit_reserve > 0:
            # 只补真正缺的那几个, 不多扫。缺口常常只剩个位数, 固定按 30% 扫会让
            # "补库容 / 值守"每轮来回横跳(缺口 1 个却扫 150 个), 白费探测。
            n = max(FILL_MIN, min(base, int(base * FILL_FRACTION), deficit_reserve))
            phase = "fill"
        elif explore_due and base > 0:
            n, phase = max(EXPLORE_MIN, int(base * frac)), "explore"
        else:
            n, phase = 0, "monitor"

        out[key] = {"active": active, "fresh": fresh, "reserve": reserve,
                    "total": total, "target": tgt, "cap": cap,
                    "deficit": deficit, "deficit_reserve": deficit_reserve,
                    "count": n, "phase": phase}

    # 整体阶段 = 两个协议里"最在干活"的那个(决定界面显示与睡多久)
    phases = [out[k]["phase"] for k, _ in PROTOS]
    overall = next((p for p in PHASE_ORDER if p in phases), "monitor")
    out["phase"] = overall
    out["explore"] = overall != "monitor"          # 本轮是否在扫新 IP(影响轮间节奏)
    out["active"] = out["v4"]["active"] + out["v6"]["active"]
    out["fresh"] = out["v4"]["fresh"] + out["v6"]["fresh"]
    out["deficits"] = {k: {"active": out[k]["active"], "reserve": out[k]["reserve"],
                           "total": out[k]["total"], "target": out[k]["target"],
                           "deficit": out[k]["deficit"],
                           "deficit_reserve": out[k]["deficit_reserve"]}
                       for k, _ in PROTOS}
    return out