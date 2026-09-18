# 🚀 CF 优选IP 扫描管理台
![image.png](https://cloudfiles.dpdns.org/file/1787702437419_image.png)
![image.png](https://cloudfiles.dpdns.org/file/1787702457481_image.png)
基于 Cloudflare 官方 IP 地址池的 **优选 IP 持续扫描器**,带 **Web 图形管理界面**。纯 Python 标准库实现,**零第三方依赖**,Python 3.8+ 即可运行。

## ✨ 功能特性

- 🔍 **持续扫描**: 多端口并发拨号 + TLS 握手二次确认,自动发现可用 CF 边缘 IP
- 🧠 **邻域加权采样**: 命中过优质 IP 的 C 段优先抽样,达标命中率远高于纯随机
- 📊 **实时看板**: 已测/存活/已验证/带宽/平均延迟统计卡片 + 机房 / 国家 / 延迟 / 带宽分布图表
- 🚀 **带宽实测**: 内置测速模块,支持自定义测速域名(可配合自建 Cloudflare Worker 规避公共限流)
- 🌍 **地区识别**: 自动识别机房 (colo) 与国家/地区,支持按地区筛选导出
- 📋 **结果表**: 可排序 / 多条件筛选 / 勾选批量操作,一键导出 `ADD.txt` / `CSV`
- ⚙️ **灵活配置**: 扫描参数随时通过 Web 界面调整并热重启
- 🧭 **服务管理**: 网页端一键重启 / 停止服务、开启 / 关闭开机自启(需 systemd 托管部署, 安装脚本自动配置 sudoers 授权)
- 💾 **断点续扫**: 所有结果累积进 SQLite,随时退出,下次继续; 库上限+墓碑机制控制体积
- 🖱️ **BA 点击特效**: 蔚蓝档案风格点击特效与光标拖尾(ba-click-fx, MIT), 面板可视化调参, 桌面/手机触屏均生效
- 🌗 **现代界面**: 左侧可折叠导航 + 多视图布局, 深浅色主题(自动跟随系统/手动切换), NASA 每日一图壁纸, 移动端完整适配

## 📦 文件说明

| 文件 | 说明 |
|---|---|
| `cf_db.py` | 核心扫描引擎(命令行工具) |
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

界面为**左侧可折叠导航**(移动端变抽屉)+ 右侧内容区, 共 5 个视图, 右上角 🌓 按钮切换主题(**自动跟随系统 → 浅色 → 深色** 循环):

1. **总览看板**: 统计卡片("已测试IP"为**历史累计**, 含已被清理的IP; 库内保留数见悬浮明细) + 机房 / 国家 / 延迟 / 带宽四类图表, 悬停看明细。
2. **扫描控制**: 地址源(官方全网 / CF官方 / 电信 / 联通 / 移动优选段)、端口、抽样数/轮、并发、验证预算、测带宽/轮、测速并连数、测速域名、地区补全、复核、优质 C 段比例、最大延迟、库上限, 以及 TLS 二次确认 / 同时扫描 IPv6 开关。参数保存后热生效, 「开始扫描 / 停止」随时切换。
3. **IP 列表**:
   - **筛选**: 机房(逗号分隔, 如 `HKG,NRT`)、最小带宽、最大延迟、IP 包含、端口、仅有带宽、仅IPv6(激活的筛选会高亮)
   - **排序**: 点击列头(带宽 / 延迟 / IP / 端口 / 机房 / 最近测试)
   - **勾选**: 复制选中(格式 `ip:端口#地区`) / 导出选中 txt / 清空选中, 跨页保留
   - **翻页跳转**, 一键导出 `ADD.txt` / `CSV`(跟随当前筛选条件)
4. **⚙️ 服务管理**: 查看服务运行状态与开机自启状态, 一键 **重启服务** / **停止服务**, 以及 **开启 / 关闭开机自启**。systemd 托管部署且已由安装脚本授予 sudo 权限时全部可用; 非托管(手动 / 容器)或未授权时, 开机自启开关会被禁用, 重启 / 停止退化为进程内操作(重启 = 自重启, 停止 = 退出进程, 停止后需到设备上重新启动或重启设备恢复)。
5. **✨ 点击特效**: 蔚蓝档案风格点击特效与光标拖尾开关、特效大小 / 不透明度 / 拖尾与点击速度滑杆、颜色跟随明暗主题或自定义; 所有调整即时生效并保存在浏览器本地。桌面与手机触屏均生效。

> **壁纸**: NASA 每日一图(APOD)自动解析并缓存在服务端(`apod_bg.jpg`), 访客直接加载本地图; 当日为视频时自动取最近图片日, 接口失败沿用旧图。可选在 `cf_settings.json` 加 `"nasa_api_key": "你的key"` 提升接口配额([api.nasa.gov](https://api.nasa.gov) 免费申请, DEMO_KEY 限 50 次/天)。

## 🖥️ 开机自启与常驻(systemd)

推荐用安装脚本把管理台注册为 systemd 服务(开机自启 + 崩溃自动重启), 并同时授予网页端「服务管理」所需的 sudo 权限:

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

> 「服务管理」视图中重启 / 停止 / 开机自启开关依赖上述 sudoers 授权; 未授权(或非 systemd 环境)时重启 / 停止仍可用(进程内兜底: 重启=自重启, 停止=退出进程), 开机自启开关不可用。
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
| `--count` | 5000 | 每轮发现候选数 |
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
| `--max-ips-v4` | 0 | IPv4 库上限, 每轮结束超出部分按质量评分剔除(带宽/延迟优先保留), 死IP入墓碑静默7天免重测, 0=不限制 |
| `--max-ips-v6` | 0 | IPv6 库上限, 规则同上 |

## 🌐 关于 IPv6

- 用公开「优选 v6 IP 列表」(运营商匹配 + 通用源)优先采样,命中率高;同时把 **CF 官方 v6 大段**纳入随机发现,覆盖更广。需要本机有 IPv6 网络。

## 🛠 技术栈

- **Python 3.8+** 标准库(零第三方依赖)
- **SQLite**: 数据持久化
- **Cloudflare IP 地址池**: 官方路由数据
- **内置 HTTP 服务**: Web 管理界面(含登录鉴权)
- [ba-click-fx](https://github.com/CialloKing/ba-click-fx)(MIT): 蔚蓝档案风格网页点击特效

## 📄 许可证

[MIT](./LICENSE)
