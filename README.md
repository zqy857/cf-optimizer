# 🚀 CF 优选IP 扫描管理台
![image.png](https://cloudfiles.dpdns.org/file/1786871754234_image.png)

基于 Cloudflare 官方 IP 地址池的 **优选 IP 持续扫描器**,带 **Web 图形管理界面**。纯 Python 标准库实现,**零第三方依赖**,Python 3.8+ 即可运行。

## ✨ 功能特性

- 🔍 **持续扫描**: 多端口并发拨号 + TLS 握手二次确认,自动发现可用 CF 边缘 IP
- 🧠 **邻域加权采样**: 命中过优质 IP 的 C 段优先抽样,达标命中率远高于纯随机
- 📊 **实时看板**: 已测/存活/已验证/带宽/平均延迟统计卡片 + 机房 / 国家 / 延迟 / 带宽分布图表
- 🚀 **带宽实测**: 内置测速模块,支持自定义测速域名(可配合自建 Cloudflare Worker 规避公共限流)
- 🌍 **地区识别**: 自动识别机房 (colo) 与国家/地区,支持按地区筛选导出
- 🛤️ **线路分类**: 去程 ASN 判定精品/普通/混合/未识别(CN2-GIA/9929/CMIN2 为精品,163/169/9808 为普通),表格悬停可查看逐跳 Traceroute 详情
- 📋 **结果表**: 可排序 / 多条件筛选 / 勾选批量操作,一键导出 `ADD.txt` / `CSV`
- ⚙️ **灵活配置**: 扫描参数随时通过 Web 界面调整并热重启
- 💾 **断点续扫**: 所有结果累积进 SQLite,随时退出,下次继续

## 📦 文件说明

| 文件 | 说明 |
|---|---|
| `cf_db.py` | 核心扫描引擎(命令行工具) |
| `cf_web.py` | Web 管理台(内置调用 cf_db) |
| `route_probe.py` | 路由线路分类探测器(去程 ASN 判定 + 逐跳 Traceroute) |
| `cf_speedtest_worker.js` | 自建测速 Cloudflare Worker(可选) |
| `cf_settings.json` | Web 界面保存的参数(可选,缺失时用默认值) |

## 🚀 快速开始

### 方式一:直接使用 Web 管理台(推荐)

```bash
# 下载 cf_web.py、cf_db.py、route_probe.py 到同一目录
python3 cf_web.py --db cf_ips.db
```

打开浏览器访问 `http://127.0.0.1:8787/` 即可看到管理台,点击「开始扫描」。

后台常驻运行:

```bash
python3 cf_web.py --db cf_ips.db --daemon --no-browser
```

停止:

```bash
python3 cf_web.py --stop
```

### 方式二:命令行直接扫描

```bash
python3 cf_db.py                      # 默认连续扫描,每轮抽 5000
python3 cf_db.py --operator ct        # 电信优选段
python3 cf_db.py --once               # 只跑一轮就退出
python3 cf_db.py --cycles 50 --gap 20 # 跑 50 轮,轮间歇 20 秒
python3 cf_db.py --ports 443,8443     # 只测 443 和 8443
python3 cf_db.py --no-tls-check       # 关闭 TLS 二次确认(更快但质量略低)
python3 cf_db.py --exploit 0.8        # 更多向优质 C 段倾斜
python3 cf_db.py --reverify           # 只复核库内现有优质 IP
python3 cf_db.py --route-check         # 开启线路分类检测(精品/普通/混合, 需要 ping 命令)
python3 cf_db.py --route-budget 100    # 每轮线路检测的 IP 数上限
python3 cf_db.py --route-stale-hours 12# 线路重测周期(小时)
python3 cf_db.py --ipv6                # 同时扫描 IPv6(用公开优选 v6 列表, 需本机有 IPv6)
python3 cf_db.py --stats              # 查看库统计 / 覆盖率
python3 cf_db.py --export top.txt     # 导出当前最优 N 条 (--top N, 可加 --region)
python3 cf_db.py --seed myadd.txt     # 把现有优选名单导入数据库作为种子
```

## 🔧 部署自建测速 Worker(可选)

公共测速服务 `speed.cloudflare.com` 在大量测速时可能被限流。可部署自己的测速 Worker:

1. 打开 [Cloudflare Workers](https://dash.cloudflare.com) → Workers & Pages → Create Worker
2. 粘贴 `cf_speedtest_worker.js` 内容 → Deploy
3. 记下 Worker 域名(如 `myspeedtest.xxx.workers.dev`)
4. 在管理台「测速域名」填入该域名,或在 `cf_settings.json` 中设置 `bench_host`

> 该 Worker 用全零块流式下发数据,规避免费版 10ms CPU 限制,可全速测带宽。

## ⚙️ 常用参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--ports` | 443,2053,2083,8443 | 探测端口 |
| `--count` | 5000 | 每轮发现候选数 |
| `--concurrency` | 150 | 并发探测数 |
| `--verify` | 400 | 每轮地区验证上限 |
| `--bench` | 20 | 每轮带宽实测上限 |
| `--bench-parallel` | 6 | 带宽实测并发 |
| `--exploit` | 0.6 | 优质 C 段加权比例 |
| `--max-latency` | 2000 | 延迟上限(ms) |
| `--tls-check` | 1 | TLS 二次确认开关 |
| `--route-check` | 1 | 线路分类检测开关 |
| `--route-budget` | 100 | 每轮线路检测的 IP 数上限 |
| `--route-stale-hours` | 6 | 有带宽 IP 的线路重测周期(小时) |
| `--ipv6` | 0 | 同时扫描 IPv6 |
| `--gap` | 10 | 轮间隔(秒) |

## 🌐 关于 IPv6 与精品线路识别

- **IPv4 精品线路**:去程 ASN 判定(CN2-GIA/9929/CMIN2 为精品)。但**精品在 CF 边缘 IP 中占比极低(通常不足 1%)**,需要测大量 IP 才有机会命中,`--route-budget` 越大命中率越高(默认 100)。
- **IPv6**:用公开「优选 v6 IP 列表」(运营商匹配 + 通用源)优先采样,命中率高;同时把 **CF 官方 v6 大段**纳入随机发现,覆盖更广。但 **IPv6 线路分类暂不支持 ASN 判定(离线库仅 v4 数据),一律显示"未识别",不参与精品识别**。需要本机有 IPv6 网络。

## 🛠 技术栈

- **Python 3.8+** 标准库(无第三方依赖)
- **SQLite**: 数据持久化
- **Cloudflare IP 地址池**: 官方路由数据
- **内置 HTTP 服务**: Web 管理界面

## 📄 许可证

[MIT](./LICENSE)
