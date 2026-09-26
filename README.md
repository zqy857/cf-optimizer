# 🚀 CF 优选IP 扫描管理台
![image.png](https://cloudfiles.dpdns.org/file/1787702437419_image.png)
![image.png](https://cloudfiles.dpdns.org/file/1787702457481_image.png)
基于 Cloudflare 官方 IP 地址池的 **优选 IP 持续扫描器**,带 **Web 图形管理界面**。纯 Python 标准库实现,**零第三方依赖**,Python 3.8+ 即可运行。

## ✨ 功能特性

- 🔍 **持续扫描**: 多端口并发拨号 + TLS 握手二次确认,自动发现可用 CF 边缘 IP
- 🧠 **邻域加权采样**: 命中过优质 IP 的 C 段优先抽样,达标命中率远高于纯随机
- ❤️ **健康度模型**: 每个 IP 维护质量分(可用率/延迟/带宽/地区验证/新鲜度加权, 随时间衰减)与分层复测计划——优质 IP 勤测常新, 失败 IP 指数退避, 长期失效的"僵尸 IP"自动降级剔除, 让 IP 库长期保持健康
- 🧭 **IPv4 / IPv6 独立控制**: 两种协议可分别启用, 各自选择地址源(官方/电信/联通/移动)与每轮抽样数, 互不干扰
- ⚖️ **动态平衡调度**: 库收敛后自动从"发现扩张"切换到"健康维护"——只做小比例探索 + 到期复测, 不再一轮轮空扫浪费家宽; 质量下滑时自动转"恢复"; 可持续地长期值守
- 📊 **实时看板**: 已测/存活/已验证/带宽/平均延迟统计卡片 + 机房 / 国家 / 延迟 / 带宽分布图表
- 🚀 **带宽实测**: 内置测速模块,支持自定义测速域名(可配合自建 Cloudflare Worker 规避公共限流)
- 🌍 **地区识别**: 自动识别机房 (colo) 与国家/地区,支持按地区筛选导出
- 📋 **结果表**: 可排序 / 多条件筛选 / 勾选批量操作,一键导出 `ADD.txt` / `CSV`
- ⚙️ **灵活配置**: 扫描参数随时通过 Web 界面调整并热重启
- ⚙️ **系统设置**: 服务管理(网页端一键重启 / 停止服务、开机自启开关, 需 systemd 托管部署, 安装脚本自动配置 sudoers 授权) + BA 点击特效
- 💾 **断点续扫**: 所有结果累积进 SQLite,随时退出,下次继续; 库上限+墓碑机制控制体积
- 🖱️ **BA 点击特效**: 蔚蓝档案风格点击特效与光标拖尾(ba-click-fx, MIT), 面板可视化调参, 桌面/手机触屏均生效
- 🌗 **现代界面**: 左侧可折叠导航 + 多视图布局, 深浅色主题(自动跟随系统/手动切换), NASA 每日一图壁纸, 移动端完整适配

## 📦 文件说明

| 文件 | 说明 |
|---|---|
| `cf_db.py` | 核心扫描引擎(命令行工具) |
| `cf_health.py` | IP 健康度模型(质量分 / 分层复测调度 / 失效降级) |
| `cf_policy.py` | 动态平衡控制律(发现 ↔ 维护 ↔ 恢复 模式切换与预算重分配) |
| `cf_web.py` | Web 管理台(内置调用 cf_db) |
| `cf_autostart_install.sh` | systemd 开机自启安装脚本(生成服务单元 + sudoers 授权) |
| `cf_speedtest_worker.js` | 自建测速 Cloudflare Worker(可选) |
| `cf_settings.json` | Web 界面保存的参数(可选,缺失时用默认值) |
| `vendor/ba-click-fx.js` | 点击特效库 ba-click-fx(MIT, 本地自托管) |

> 运行时自动生成: `cf_secret.json`(登录凭据)、`apod_bg.jpg`(壁纸缓存)。

## 🚀 快速开始

### 方式一:直接使用 Web 管理台(推荐)

```bash
# 下载 cf_web.py、cf_db.py 到同一目录
python3 cf_web.py --db cf_ips.db
```

打开浏览器访问 `http://127.0.0.1:8787/` 即可看到管理台,点击「开始扫描」。

> **访问控制(默认开启)**:首次启动会自动生成登录凭据(用户名 + 随机密码),保存在同目录 `cf_secret.json`(权限 600),启动日志会打印账号密码;所有页面与 API 均需登录(表单登录会话或 HTTP Basic Auth)。改密码直接编辑该文件并**重启服务**。
>
> 注:管理台为纯 HTTP 明文服务,**自身不提供 TLS**。局域网内使用无碍;若需对外网开放,请务必保证强密码,并在前面套一层反向代理(如 nginx)提供 HTTPS。

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
python3 cf_db.py --ipv6                # 同时扫描 IPv6(用公开优选 v6 列表, 需本机有 IPv6)
python3 cf_db.py --stats              # 查看库统计 / 覆盖率
python3 cf_db.py --export top.txt     # 导出当前最优 N 条 (--top N, 可加 --region)
python3 cf_db.py --seed myadd.txt     # 把现有优选名单导入数据库作为种子
```

## 🖥️ Web 管理台使用说明

界面为**左侧可折叠导航**(移动端变抽屉)+ 右侧内容区, 共 4 个视图, 右上角 🌓 按钮切换主题(**自动跟随系统 → 浅色 → 深色** 循环):

1. **总览看板**: 统计卡片("已测试IP"为**历史累计**, 含已被清理的IP; 库内保留数见悬浮明细) + 机房 / 国家 / 延迟 / 带宽四类图表, 悬停看明细。
2. **扫描控制**(分组卡片): 
   - **地址源与协议**: IPv4 / IPv6 两个独立开关, 各自可选地址源与抽样数/轮(IPv6 关闭时该栏变灰); 
   - **探测与验证**: 端口、并发、最大延迟、TLS 二次确认、验证预算、测带宽/轮、测速并连数、测速域名; 
   - **复测保养与库策略**: 地区补全、复测/轮、优质 C 段比例、IPv4/IPv6 库上限、单国家占比、扫描策略(自动/发现/维护/恢复)、目标可用IP数、目标前缀数。 
   参数保存后热生效, 「开始扫描 / 停止」随时切换。
3. **IP 列表**:
   - **筛选**: 机房(逗号分隔, 如 `HKG,NRT`)、最小带宽、最大延迟、IP 包含、端口、仅有带宽、仅IPv6(激活的筛选会高亮)
   - **排序**: 点击列头(带宽 / 延迟 / IP / 端口 / 机房 / 最近测试 / 健康分)排序, 再次点击切换升/降序(列头显示 ▲/▼); 国家/地区、存活/失败 等列不参与排序
   - **勾选**: 复制选中(格式 `ip:端口#地区`) / 导出选中 txt / 清空选中, 跨页保留
   - **翻页跳转**, 一键导出 `ADD.txt` / `CSV`(跟随当前筛选条件)
4. **⚙️ 系统设置**(管理控制台):
   - **服务管理**: 查看服务运行状态与开机自启状态, 一键 **重启服务** / **停止服务**, 以及一个按当前状态自动切换文案的**开机自启开关**(已开启时显示「关闭开机自启」, 否则显示「开启开机自启」)。systemd 托管部署且已由安装脚本授予 sudo 权限时全部可用; 非托管(手动 / `--daemon` / 容器)或未授权时, 运行状态显示「运行中(非托管)」、开机自启显示「不适用」, 开关被禁用, 重启 / 停止退化为进程内操作(重启 = 自重启, 停止 = 退出进程, 停止后需到设备上重新启动或重启设备恢复); 提示会指引运行 `cf_autostart_install.sh` 注册为 systemd 服务以获得开机自启。
   - **点击特效**: 蔚蓝档案风格点击特效与光标拖尾开关、特效大小 / 不透明度 / 拖尾与点击速度滑杆、颜色跟随明暗主题或自定义; 所有调整即时生效并保存在浏览器本地。桌面与手机触屏均生效。

> **壁纸**: NASA 每日一图(APOD)自动解析并缓存在服务端(`apod_bg.jpg`), 访客直接加载本地图; 当日为视频时自动取最近图片日, 接口失败沿用旧图。可选在 `cf_settings.json` 加 `"nasa_api_key": "你的key"` 提升接口配额([api.nasa.gov](https://api.nasa.gov) 免费申请, DEMO_KEY 限 50 次/天)。

## 🖥️ 开机自启与常驻(systemd)

推荐用安装脚本把管理台注册为 systemd 服务(开机自启 + 崩溃自动重启), 并同时授予网页端「系统设置 → 服务管理」所需的 sudo 权限:

```bash
# 在部署目录(cf_web.py / cf_ips.db 同目录)执行; 需要 sudo 权限
bash cf_autostart_install.sh
# 若当前用户不能免密 sudo: SUDO_PASS='你的密码' bash cf_autostart_install.sh
# 指定运行用户/组(默认当前用户): RUN_USER=zqy RUN_GROUP=Administrators bash cf_autostart_install.sh
```

脚本会:

1. 生成 `cf-optimizer.service`(部署目录), 复制到 `/etc/systemd/system/` 并 `enable` + `restart`;
2. 生成 `cf-optimizer.sudoers`, 经 `visudo -cf` 校验后安装到 `/etc/sudoers.d/cf-optimizer`(权限 `0440`), 仅允许运行用户 **无密码** 对本服务执行 `systemctl {start,stop,restart,enable,disable,is-active,is-enabled}`, 供网页端按钮调用;
3. 校验服务状态并测试登录接口。

> 「系统设置 → 服务管理」中的重启 / 停止按钮与开机自启开关依赖上述 sudoers 授权; 未授权(或非 systemd 环境)时重启 / 停止仍可用(进程内兜底: 重启=自重启, 停止=退出进程), 开机自启开关不可用。
>
> 停止服务后网页将无法访问; 若已开启开机自启, 重启设备即可恢复, 否则需到设备上手动 `sudo systemctl start cf-optimizer.service`。

手动管理(不使用脚本):

```bash
sudo systemctl start|stop|restart|enable|disable cf-optimizer.service
sudo systemctl status cf-optimizer.service
```

## 🔌 Web API

| 接口 | 说明 |
|---|---|
| `GET /` | Web 管理界面 |
| `GET /api/status` | 运行状态 / 版本 / 日志 |
| `GET /api/stats` | 统计与分布数据 |
| `GET /api/table` | 本地 IP 列表(支持 `region` `minbw` `maxlat` `q` `port` `hasbw` `v6` `v4` `sort` `top` 等筛选排序) |
| `GET /api/copy` | 按 IP 列表返回 `ip:端口#地区` 格式(用于批量复制) |
| `GET /api/export?fmt=txt\|csv` | 导出 ADD.txt / CSV(跟随筛选条件) |
| `POST /api/control` | 开始 / 停止扫描 |
| `GET /api/service` | 服务状态(systemd 单元 / 运行 / 自启 / 可否控制) |
| `POST /api/service` | 服务控制(`{"action":"restart\|stop\|start\|enable\|disable"}`) |
| `POST /api/settings` | 保存设置 |
| `POST /api/test` | 单 IP 手动测 延迟 / 带宽 |

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
| `--count` | 5000 | IPv4 每轮发现候选数 |
| `--count-v6` | 同 --count | IPv6 每轮发现候选数(独立) |
| `--no-v4` | 关 | 关闭 IPv4 扫描 |
| `--v6-operator` | 公共 | IPv6 优选列表来源: cmcc(移动), 默认仅公共优选列表 |
| `--no-v6-official` | 关 | 不叠加 CF 官方 v6 大段(默认叠加, 用于随机发现新地址) |
| `--concurrency` | 400 | 并发探测数 |
| `--verify` | 30 | 每轮地区验证上限 |
| `--bench` | 40 | 每轮带宽实测上限 |
| `--bench-parallel` | 4 | 带宽实测并发 |
| `--exploit` | 0.6 | 优质 C 段加权比例 |
| `--max-latency` | 2000 | 延迟上限(ms) |
| `--tls-check` | 1 | TLS 二次确认开关 |
| `--ipv6` | 0 | 同时扫描 IPv6 |
| `--once` | 0 | 只跑一轮就退出 |
| `--cycles` | 0 | 跑 N 轮后退出(0=无限) |
| `--gap` | 5 | 轮间隔(秒) |
| `--reverify` | 0 | 只复核库内现有优质 IP |
| `--seed` | 无 | 把名单文件导入数据库作为种子 |
| `--top` | 100 | `--export` 时导出的条数 |
| `--region` | 无 | `--export` 时按机房/地区过滤 |
| `--max-ips-v4` | 0 | IPv4 库上限, 每轮结束超出部分按**健康分**低者先剔除, 死IP入墓碑静默7天免重测, 0=不限制 |
| `--max-ips-v6` | 0 | IPv6 库上限, 规则同上 |
| `--scan-mode` | auto | 扫描策略: auto=动态平衡后自动转维护 / discovery / maintenance / recovery |
| `--target-active` | 60 | 动态平衡目标: 期望保有的可用 IP 数 |
| `--target-prefixes` | 8 | 动态平衡目标: 期望覆盖的独立前缀数 |

## 🌐 关于 IPv6

- IPv6 地址池 = **公开优选 v6 列表**(公共列表始终纳入, 可选移动优选) + **CF 官方 v6 大段**(可在界面/`--no-v6-official` 关闭)。
- 优选列表是社区已筛好的具体地址, 命中率高; 官方大段(`2606:4700::/32` 等)命中率低但覆盖广, 用于随机发现新地址。需要本机有 IPv6 网络。
- 源可用性(实测): 公共优选(joname1)、移动优选(addressesapi cmcc-ipv6)、CF 官方 v6 均可用; **电信/联通优选 v6 源已失效(404), 已移除**。任一源不可用会自动跳过并回退到其余来源。

## ❤️ IP 库健康度模型(长期维护)

传统扫描器只记「测过/没测过」,IP 一旦存活就永久算存活,库会随库龄不断堆积僵尸 IP、且优质 IP 不会得到更多关注。本项目引入 `cf_health.py` 健康度模型:

- **质量分 score (0~100)**: `可用率(Laplace平滑,0.25) + 延迟(0.35) + 带宽(开方衰减,0.40) + 地区已验证 + 新鲜度(半衰期3天)` 加权; **关键维度(带宽/延迟)未测量时按"数据完整度"打折**——只测了延迟没测带宽的 IP 最高只能到黄区(~53分), 不再仅凭连通就冲上高分, 只有实测过带宽的 IP 才能进绿区。连续成功/失败、延迟与带宽的 EWMA 每次探测都更新, 避免被单次抖动误导。评分公式版本化(`HEALTH_VERSION`), 升级后首次启动自动重算存量库。
- **分层复测调度 `next_check_at`**: 分数越高复测越勤(最快 30 分钟),越低越少(最长 8 小时),连续失败按 `2^fail_streak` 指数退避(最多 64 倍);调度器按"最久到期优先"取件,任何 IP 都不会被无限饿死。复测期间对已达标 IP 只做 TCP(跳过重复 TLS 握手)以省资源。
- **失效降级**: 曾经存活但超过 `HARD_TTL`(14 天)无成功且连续失败达阈值的 IP 会被判定失效,移入墓碑静默后由扫描器重新发现,不再永久占据库容。
- **可视与排序**: 看板新增「新鲜存活(1h)」卡片,IP 列表新增「健康分」列(绿/黄/灰三档 + 新鲜度圆点)并默认按健康分排序;悬停可见新鲜/陈旧明细。

> 存量数据库首次启动会自动迁移(补列 + 回填 `last_ok_at`/`fail_streak` + 重算 score/next_check_at),无需手动处理,也不会丢失已有数据。

## ⚖️ 动态平衡调度(发现 → 维护)

扫描的目的不是"一直扫",而是"把库养好"。`cf_policy.py` 每轮实时评估库状态并自动决定重心:

| 指标 | 含义 |
|---|---|
| `active` / `fresh` | 质量分达标(≥40)的 IP 数 / 其中近期(6h)确认过存活的 |
| `prefixes` | 有效 IP 覆盖的独立前缀(/24、/64)数, 衡量多样性 |
| `yield` | 近 30 分钟内"每测 1 个 IP 新增的有用 IP"比例, 衡量边际收益 |

- **发现扩张 `discovery`**: 可用数/前缀数未达标, 或边际发现率仍高 → 保持大范围抽样。
- **健康维护 `maintenance`**: 库已饱和(可用数与前缀数达标且发现率低) → 抽样数降到约 15%, 只做小比例探索(捕捉路由变化/新机房) + 到期复测把存量保新, 不再空烧家宽。
- **质量恢复 `recovery`**: 存量浮现大量陈旧 → 优先加大复测把新鲜度拉回来。
- 指标若在**连续 3 轮**同向才切换(迟滞), 避免模式抖动。

> **IPv4 / IPv6 各自独立评估**: v4 通常很快饱和、v6 往往还差得多, 两种协议分别统计 active/fresh/prefixes/yield 并各自切换模式与抽样数——例如 v4 转"维护"时 v6 仍可保持"发现", 不会互相拖累。可用数超过目标的 3 倍视为"过量", 不再因发现率而继续扩张。

网页「扫描控制」可设 **扫描策略**(自动/强制发现/强制维护/强制恢复)、**目标可用IP数**、**目标前缀数**; 运行中顶部状态与进度条实时显示当前模式与 `可用/新鲜/前缀/发现率`。

## 🛠 技术栈

- **Python 3.8+** 标准库(零第三方依赖)
- **SQLite**: 数据持久化
- **Cloudflare IP 地址池**: 官方路由数据
- **内置 HTTP 服务**: Web 管理界面(含登录鉴权)
- [ba-click-fx](https://github.com/CialloKing/ba-click-fx)(MIT): 蔚蓝档案风格网页点击特效

## 📄 许可证

[MIT](./LICENSE)
