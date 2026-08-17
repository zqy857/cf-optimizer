# 🚀 CF 优选IP 扫描管理台
![image.png](https://cloudfiles.dpdns.org/file/1786948130467_image.png)
![image.png](https://cloudfiles.dpdns.org/file/1786948153031_image.png)

基于 Cloudflare 官方 IP 地址池的 **优选 IP 持续扫描器**,带 **Web 图形管理界面**。纯 Python 标准库实现,**零第三方依赖**,Python 3.8+ 即可运行。

## ✨ 功能特性

- 🔍 **持续扫描**: 多端口并发拨号 + TLS 握手二次确认,自动发现可用 CF 边缘 IP
- 🧠 **邻域加权采样**: 命中过优质 IP 的 C 段优先抽样,达标命中率远高于纯随机
- 📊 **实时看板**: 已测/存活/已验证/带宽/平均延迟统计卡片 + 机房 / 国家 / 延迟 / 带宽分布图表
- 🚀 **带宽实测**: 内置测速模块,支持自定义测速域名(可配合自建 Cloudflare Worker 规避公共限流)
- 🌍 **地区识别**: 自动识别机房 (colo) 与国家/地区,支持按地区筛选导出
- 🛤️ **线路分类**: 去程 ASN 判定精品/普通/混合/未识别(CN2-GIA/9929/CMIN2 为精品,163/169/9808 为普通),表格悬停可查看逐跳 Traceroute 详情。ASN 用**纯标准库二分查找**(首次使用需联网下载 ip2asn 数据, 之后离线)
- 📋 **结果表**: 可排序 / 多条件筛选 / 勾选批量操作,一键导出 `ADD.txt` / `CSV`
- 🎯 **手动优选**: 从本地库抽候选现场重测, 取最优 N 条(可优先带宽/延迟), 勾选复制, 不落库
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

> **访问控制(默认开启)**:首次启动会自动生成登录凭据(用户名 + 随机密码),保存在同目录 `cf_secret.json`(权限 600),启动日志会打印账号密码;所有页面与 API 均需 Basic Auth。若机器上装了 `openssl`(Linux 一般自带),默认还会启用 **HTTPS(自签名证书)**,地址为 `https://...`,浏览器首次访问需信任自签名证书;不想用加密可把 `cf_secret.json` 里的 `https` 改为 `false` 重启,改密码直接编辑该文件。
>
> 注意:自签名 HTTPS 只加密传输、防局域网窥探,**不提供身份公证**;对外网开放管理台请务必保证强密码。

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

## 🖥️ Web 管理台使用说明

页面自上而下分为 5 块:

1. **扫描控制**: 地址源(官方全网 / CF官方 / 电信 / 联通 / 移动优选段)、端口、抽样数/轮、并发、验证预算、测带宽/轮、测速并连数、测速域名、地区补全、复核、线路检测预算与重测周期、优质 C 段比例、最大延迟, 以及 TLS 二次确认 / 线路分类 / 同时扫描 IPv6 开关。参数保存后热生效, 「开始扫描 / 停止」随时切换。
2. **统计卡片**: 已测试 / 存活 / 已验证地区 / 有带宽 / 平均延迟 / 最高带宽 / 最低延迟 / 覆盖率 / 精品线路 IP。
3. **图表**: 机房分布 / 国家地区分布 / 延迟分布 / 带宽分布 / 线路分布(前 12), 悬停可看明细。
4. **🎯 手动优选**: 见下方专节。
5. **本地IP列表**:
   - **筛选**: 机房(逗号分隔, 如 `HKG,NRT`)、最小带宽、最大延迟、IP 包含、端口、只显示精品线路、仅有带宽、仅IPv6(激活的筛选会高亮)
   - **排序**: 点击列头(带宽 / 延迟 / IP / 端口 / 机房 / 最近测试)
   - **勾选**: 复制选中(格式 `ip:端口#地区`, 精品自动带「精品」后缀) / 导出选中 txt / 清空选中, 跨页保留
   - **翻页跳转**, 一键导出 `ADD.txt` / `CSV`(跟随当前筛选条件)
   - **线路列**: 悬停可查看逐跳 Traceroute 与 ASN 列表

## 🎯 手动优选(从本地库抽候选现场重测)

后台扫描会持续把测过的 IP 累积进本地库。需要**少量精挑**时, 不必等后台扫描:

1. 在「手动优选」卡片设置: 数量 N、**优先带宽 / 优先延迟**、地区过滤、仅精品、仅有带宽、仅IPv6
2. 点「优选」: 先从本地库按筛选条件抽 `max(N×5, 20)` 个候选(上限 150), 再**现场重测**(连通探测 → 地区识别 → 实测带宽, 并发 20)
3. 取最优 N 条展示在下方表格(优先带宽 = 带宽↓ 延迟↑; 优先延迟 = 延迟↑ 带宽↓), 可勾选后「复制选中」或「复制全部」

> 重测到的延迟/带宽会作为普通测试记录更新回本地库(后台本就会持续测试); 但**优选清单本身不落库**, 只在页面展示复制, 随时可重跑。

## 🔌 Web API

| 接口 | 说明 |
|---|---|
| `GET /` | Web 管理界面 |
| `GET /api/status` | 运行状态 / 版本 / 日志 |
| `GET /api/stats` | 统计与分布数据 |
| `GET /api/table` | 本地 IP 列表(支持 `region` `minbw` `maxlat` `q` `port` `route` `hasbw` `v6` `v4` `sort` `top` 等筛选排序) |
| `GET /api/optimize` | 手动优选(`count` `prio=bw\|lat` `region` `route` `hasbw` `v6`) |
| `GET /api/copy` | 按 IP 列表返回 `ip:端口#地区` 格式(用于批量复制) |
| `GET /api/export?fmt=txt\|csv` | 导出 ADD.txt / CSV(跟随筛选条件) |
| `POST /api/control` | 开始 / 停止扫描 |
| `POST /api/settings` | 保存设置 |
| `POST /api/test` | 单 IP 手动测 延迟 / 带宽 / 线路 |

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
| `--once` | 0 | 只跑一轮就退出 |
| `--cycles` | 0 | 跑 N 轮后退出(0=无限) |
| `--gap` | 10 | 轮间隔(秒) |
| `--reverify` | 0 | 只复核库内现有优质 IP |
| `--seed` | 无 | 把名单文件导入数据库作为种子 |
| `--top` | 10 | `--export` 时导出的条数 |
| `--region` | 无 | `--export` 时按机房/地区过滤 |

## 🌐 关于 IPv6 与精品线路识别

- **IPv4 精品线路**:去程 ASN 判定(CN2-GIA/9929/CMIN2 为精品)。但**精品在 CF 边缘 IP 中占比极低(通常不足 1%)**,需要测大量 IP 才有机会命中,`--route-budget` 越大命中率越高(默认 100)。
- **IPv6**:用公开「优选 v6 IP 列表」(运营商匹配 + 通用源)优先采样,命中率高;同时把 **CF 官方 v6 大段**纳入随机发现,覆盖更广。**IPv6 同样支持去程线路分类**(ASN 判定与 v4 相同,首次使用需联网下载 ip2asn v6 数据)。需要本机有 IPv6 网络。
- **线路检测前提**:依赖系统 `ping`(ICMP TTL 递增探测)与出网 ICMP 回包。若代理/防火墙拦截 ICMP、或 NAS 的 ping 不支持 `-t` 参数,会显示"无法判定";此时悬停线路列或点「测线路」会显示具体原因(`route_error`)。首次使用需联网下载一次 ip2asn ASN 数据。
- **ping 权限不足(cap_net_raw)**:部分 NAS/精简 Linux 上非 root 用户 ping 会报 `Operation not permitted / missing cap_net_raw`。Web 界面顶部会显示红色横幅和修复命令,任选其一即可:
  ```bash
  sudo setcap cap_net_raw+ep $(which ping)      # 给 ping 加原始套接字能力(最通用)
  # 或
  sysctl -w net.ipv4.ping_group_range="0 2147483647"   # 放开无特权 ICMP 组范围
  ```
- **BusyBox ping 不支持 `-t`**:精简系统的 ping 可能没有 TTL 参数,此时会提示 `invalid option -- t`,请换装完整版 `iputils-ping`。

## 🛠 技术栈

- **Python 3.8+** 标准库(零第三方依赖)
- **SQLite**: 数据持久化
- **Cloudflare IP 地址池**: 官方路由数据
- **内置 HTTP 服务**: Web 管理界面
- **ip2asn 数据**: 去程线路 ASN 判定(首次联网下载一次, 之后离线)

## 📄 许可证

[MIT](./LICENSE)
