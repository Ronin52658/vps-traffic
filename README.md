# VPS 流量监控面板

Agent 读取网卡计数和系统状态（CPU、负载、内存、Swap、硬盘、连接数、进程、运行时间，以及系统版本、内核、CPU 型号、虚拟化等配置信息）并推送到面板。有人打开面板时按“实时间隔”（默认 3 秒）上报、页面同步刷新；没人看时自动放慢到“空闲间隔”（默认 60 秒）省流量；面板按自定义周期累计流量，重置时保留历史周期。面板强制 HTTPS：只能经反代（如 Nginx Proxy Manager）用 `https://域名` 访问，需要密码登录；直接访问 `http://IP:端口` 会被拒绝，Agent 也必须走 HTTPS 上报。

## 文件

| 文件 | 用途 |
|---|---|
| server.py | 面板服务端，只用 Python 标准库（3.9+），数据存 SQLite |
| index.html | 网页界面，由 server.py 直接提供 |
| agent.sh | 被监控 VPS 上运行的 Agent（sh + awk + curl/wget） |
| install.sh | Agent 一键安装/卸载，从 GitHub 固定提交下载，内含 agent.sh 的 SHA256 |
| agent_pin.json | 面板生成安装命令用的固定版本：仓库、提交、install.sh 的 SHA256 |
| tools/pin_agent.sh | 更新 agent.sh 哈希、切换固定提交、检查 GitHub 上的文件 |
| install_panel.sh | 面板一键部署 |
| flags/ | 国旗图片（Noto Color Emoji，Apache 2.0），由面板提供 |
| icons/ | 网站图标（浏览器标签页、收藏夹、手机“添加到主屏幕”），favicon.svg 是源文件 |
| vps-traffic-panel.service | 面板的 systemd 模板（install_panel.sh 会用到） |
| demo/ | 演示站：mock.js 模拟后端，build_demo.py 从 index.html 生成 demo.html |

## 部署面板

准备一个域名解析到反代所在的机器，然后在面板机器上以 root 运行：

```sh
git clone https://github.com/Ronin52658/vps-traffic.git && cd vps-traffic
sh install_panel.sh --domain traffic.example.com --port 8080
```

再按下面“配置 HTTPS 反代”在 NPM 里加好域名，用 `https://traffic.example.com` 访问。

升级：`cd vps-traffic && git pull && sh install_panel.sh`（域名、端口等沿用原来的设置）。

结束后会打印访问地址和随机生成的登录密码。也可以用 `--ask-password` 交互输入自己的密码（至少 8 位，不会留在 shell 历史里），或 `--password 你的密码` 直接指定。

其他参数：
- `--proxy`：信任的反代地址（逗号分隔的 IP 或网段），默认 `127.0.0.1,::1,172.16.0.0/12`，覆盖本机和 Docker 里的 NPM。NPM 在另一台机器上时，填那台机器的 IP。信任列表里的地址可以绕过 HTTPS 检查、伪造访客 IP，这台机器上还跑着其他不受信任的 Docker 容器时，建议缩小到 NPM 所在的网段（`docker network inspect` 查看）。
- `--listen`：监听地址，默认 `0.0.0.0`（Docker 里的 NPM 需要能连到）。

重新运行 `install_panel.sh` 即可升级，数据库、密码、端口、时区、反代和 Telegram 设置都会保留。从旧版（root 运行、数据库在 `/opt/vps-traffic-panel`）升级时，数据库会自动搬到 `/var/lib/vps-traffic-panel`。卸载：`sh install_panel.sh --uninstall`（数据库保留）。

## 登录与安全

- 所有页面数据和接口都需要登录；只有 Agent 上报接口（靠 Token 认证）不需要。Agent 安装脚本不再由面板提供，改从 GitHub 下载。
- 密码只以 PBKDF2 哈希保存。同一 IP 连续输错 5 次锁定 15 分钟。
- 登录后在该浏览器保持 30 天，期间有访问会自动续期，关闭浏览器再打开不用重新输入密码。天数可用 `VT_SESSION_DAYS` 调整。
- 新增服务器、首页排序、面板名称、修改密码、备份还原、退出登录都在首页右上角的“设置”里。
- 复制命令：浏览器不允许自动复制时会帮你选中命令，手动复制即可。
- 在面板“设置”里修改密码，改完后其他设备的登录会失效。
- 退出登录会让这个会话立即失效，Cookie 即使被复制走也不能再用。
- 忘记密码：在仓库目录里运行 `sh install_panel.sh --ask-password`（至少 8 位）。
- 防跨站请求伪造：所有改动类请求必须由面板自己的网页发出（带专用请求头且 Origin 与地址一致），同一 IP 上其他端口的网页也无法冒用你的登录。
- 单个连接 20 秒没有完成请求就断开，同时最多处理 200 个连接，慢速连接拖不垮面板。
- 页面禁止被其他网站嵌入（防点击劫持），并设置了内容安全策略：只允许加载面板自己的脚本、样式和图片，也只能向面板自己发请求。
- 在“设置”里改密码时，原密码输错和登录共用限流。
- 登录限流两层：同一 IP 连续输错 5 次锁 15 分钟；所有 IP 合计 10 分钟内失败 30 次，暂停陌生 IP 登录 15 分钟。最近 30 天成功登录过的 IP 不受全局暂停影响，攻击者没法借此把你锁在门外。
- 强制 HTTPS：面板只接受“来自信任反代地址、且 `X-Forwarded-Proto: https`”的请求，不在信任列表里的来源（比如公网直接连端口）在建立连接后立即断开，连页面都拿不到，也占不住连接名额；反代没用 HTTPS 时网页显示“需要 HTTPS”、接口返回 403；Host 也必须是设置的域名。登录 Cookie 只经 HTTPS 发送，并下发 HSTS，浏览器之后自动只用 HTTPS。
- 紧急情况（例如证书过期进不去）可以在服务文件里把 `VT_REQUIRE_HTTPS=1` 改成 `0` 临时关闭，处理完记得改回来。

## 面板的权限

面板以专用系统用户 `vps-traffic`（无 shell、无家目录）运行，不是 root，并放在只读沙箱里：

- 程序文件在 `/opt/vps-traffic-panel`，属于 root，面板只能读
- 唯一可写的是数据目录 `/var/lib/vps-traffic-panel`（数据库、备份临时文件、还原前的安全副本）
- 不能提权，只保留绑定 1024 以下端口的能力；看不到其他进程；系统调用限制在普通服务范围内
- 可以用 `systemd-analyze security vps-traffic-panel` 查看沙箱评分

## 配置 HTTPS 反代（Nginx Proxy Manager）

1. NPM 里新增 Proxy Host：Domain 填部署时的 `--domain`，Forward 填 `http` + 面板机器的 IP + 端口 8080（NPM 和面板在同一台时，填 Docker 网桥网关地址，如 `172.17.0.1`，用 `docker network inspect` 查看；或这台机器的公网 IP）。
2. SSL 页签申请 Let's Encrypt 证书，开启 Force SSL（建议也开 HTTP/2、HSTS）。
3. 用 `https://域名` 登录。打开时 NPM 报 502，或看到“需要 HTTPS”，说明请求不是从信任的反代、或不是经 HTTPS 来的：检查 NPM 的来源地址是否在 `--proxy` 列表里（`journalctl -u vps-traffic-panel` 可看到当前的信任列表）。
4. 建议在防火墙/安全组里关闭 8080 对公网的访问，只让反代连。面板本身也会拒绝非反代的请求，这一步是多一层保护。

面板的登录 Cookie 现在属于域名，不再和同一 IP 上其他端口的面板共用。

### 从旧版（IP:端口 直接访问）升级

1. 先在 NPM 里配好域名和证书，再运行 `sh install_panel.sh --domain 你的域名`。
2. 升级后旧 Agent（配置的是 `http://IP:端口`）上报会被拒绝。Agent 会把这段时间的流量攒着，不会丢。
3. 用 `https://域名` 登录面板，到每台服务器的“设置”里复制新的安装命令，在 VPS 上重新运行（Token 不变）；Agent 改走 HTTPS 后会把攒下的流量一次补上。

## 加入 VPS

面板点“新增服务器”，复制生成的命令在 VPS 上以 root 运行（三行一起粘贴）：

```sh
curl -fsSL --proto '=https' -o /root/vps-traffic-install.sh https://raw.githubusercontent.com/Ronin52658/vps-traffic/<提交>/install.sh
echo "<install.sh 的 SHA256>  /root/vps-traffic-install.sh" | sha256sum -c - && sh /root/vps-traffic-install.sh --ref <提交> --server 'https://traffic.example.com' --token <TOKEN> --interval 3
rm -f /root/vps-traffic-install.sh
```

- 脚本固定在 `agent_pin.json` 指定的提交，不跟随分支变化；仓库之后再改，已生成的命令装出来的仍是同一份代码。
- 两层校验：命令先校验 install.sh 的 SHA256（来自面板的 `agent_pin.json`），install.sh 再校验 agent.sh 的 SHA256（写在 install.sh 里），任何一层不一致都中止，不会改动 VPS。
- 可选参数加在第二行末尾：`--iface eth0` 指定网卡（默认自动检测默认路由），`--interval 3` 初始上报间隔（秒）。

### VPS 连不上 GitHub

服务器“设置”里的安装命令下方有“VPS 连不上 GitHub？”，展开后有两种装法，面板会按这台服务器的 Token 生成好命令：

- **手动上传**：在能访问 GitHub 的机器（比如面板机器）上下载固定提交的 `install.sh` 和 `agent.sh`，传到 VPS 的 `/root/`，再运行
  `sh install.sh --agent-file agent.sh --server ... --token ...`。全程不需要 VPS 访问 GitHub。
- **经镜像下载**：在原命令的下载地址前加镜像前缀，并给 install.sh 加 `--mirror https://ghfast.top/`，agent.sh 也会经同一个镜像下载。镜像是第三方服务，可能失效，换成别的前缀即可（格式为 `https://镜像地址/` 后面直接接 GitHub 原地址）。

两种方式都照样校验 SHA256：install.sh 的哈希由面板给出，agent.sh 的哈希写在 install.sh 里，文件被改过就会中止安装，所以经第三方镜像或手动传文件都不会装上被篡改的版本。

### 发布新版 Agent

1. 修改 `agent.sh` 或 `install.sh`；改过 agent.sh 的话运行 `sh tools/pin_agent.sh hash`，把新哈希写进 install.sh
2. 提交并推送到 GitHub
3. `sh tools/pin_agent.sh pin <刚才的提交>` 更新 `agent_pin.json`，再提交推送
4. `sh tools/pin_agent.sh check` 确认 GitHub 上的文件可下载且哈希一致
5. 面板机器上拉取新代码，重新运行 `sh install_panel.sh`；之后生成的安装命令就会用新提交

合并 PR 时请用 “Create a merge commit”，保留原提交哈希（squash / rebase 会产生新哈希，旧的固定提交虽然仍可通过 PR 访问，但最好重新 pin 到 main 上的提交）。
也可以不改文件，用 `VT_AGENT_REPO`、`VT_AGENT_COMMIT`、`VT_AGENT_INSTALL_SHA256` 环境变量覆盖（写在面板的 systemd 服务里）。

### 刷新间隔

在“设置”→“刷新间隔”里设置两个值，Agent 每次上报后会按面板的回应自动调整，不需要登录 VPS 修改：

- 实时间隔（默认 3 秒）：最近 90 秒内有人在用面板时使用，页面也按这个间隔刷新
- 空闲间隔（默认 60 秒）：没人看时使用。打开面板后，最多要等一个空闲间隔，网速才切到实时

每次上报（含系统信息）连同 TCP 握手约 1.3 KB。一直按 3 秒上报每台每月约 1.1 GB；按 60 秒约 55 MB。所以空闲时放慢很重要。

旧版 Agent 不认识面板下发的间隔，需要在每台 VPS 上重新运行一次面板里的安装命令（Token 不变，数据不受影响）。
卸载：把安装命令第二行末尾的参数换成 `--uninstall`（即 `sh /root/vps-traffic-install.sh --uninstall`），其余不变。

## Agent 的权限

Agent 由 systemd 以临时普通用户（`DynamicUser`）运行，不是 root，并放在只读沙箱里：

- 整个系统只读，`/home` 不可见，只有自己的状态目录 `/var/lib/private/vps-traffic` 可写
- 不能提权、没有任何 capability、不能加载内核模块、不能改系统时间和主机名
- 只能使用 IPv4/IPv6、本地 socket 和读路由表，系统调用限制在普通服务的范围内
- 配置文件 `/etc/vps-traffic/agent.conf`（含 Token）只有 root 能读，由 systemd 读取后以环境变量交给 Agent
- 上报时 Token 经标准输入交给 curl，不出现在命令行参数里，本机其他用户用 `ps` 看不到

可以用 `systemd-analyze security vps-traffic-agent` 查看沙箱评分。

已知影响：如果系统给 `/proc` 开启了 `hidepid`，进程数只会统计到 Agent 自己；少数容器里“虚拟化”一栏可能为空。其余功能不受影响。

从旧版（root 运行）升级：在 VPS 上重新运行一次面板里的安装命令即可，安装脚本会清理旧的状态目录（只损失几秒的计数）。

## 重置规则

- 每月固定日：例如 31 号，小月自动改在当月最后一天
- 每隔 N 天：从起算日期开始每 N 天一轮
- 仅手动重置：周期不会自动结束

所有重置点以 `VT_TZ` 时区（默认 Asia/Shanghai）的 0 点计算。修改规则时，当前周期起点不变，按新规则重算结束时间。

## 计费方式

双向相加、仅上行、仅下行、取较大方向。额度百分比、告警与用量条都按计费方式计算。

## 服务器配置与系统监控

- 首页卡片：在线时长、系统版本、核心数、CPU（含负载）、内存、硬盘、流量周期用量，以及实时网速和本周期累计。顶部汇总在线数、实时总网速、今日流量、内存和硬盘总用量。
- 详情页“监控”分页：系统信息（系统、内核、CPU 型号、架构/虚拟化、IP、运行时间、主机名、网卡）、当前状态，以及 CPU、负载、内存与 Swap、硬盘、网络速率、网络连接、进程七张折线图；可选实时、1 小时、6 小时、24 小时、7 天。
- IP 取的是面板看到的上报来源地址；NAT 机显示的是它的出口 IP。
- 国旗：面板第一次看到某台机器的 IP 时，会向 ipinfo.io（失败时改用 ip-api.com）查一次国家，结果存库，之后不再重复查询。查询由面板服务器发出，只发送该 IP。也可以在服务器设置里手动填两位国家代码覆盖自动结果。国旗是图片（`flags/` 目录，取自 Noto Color Emoji），Windows 上也能正常显示。
- 不显示价格和到期时间。
- 监控数据按分钟保存 7 天；“实时”用面板内存里最近约 240 次上报。
- Agent 只读取 /proc、df 等本机信息，不监听端口，也不执行任何来自面板的命令。
- 旧版 Agent 不会上报系统信息，需要在 VPS 上重新运行一次面板里的安装命令（Token 不变）。

## 区间查询

- 单台服务器：详情页“区间查询”，选开始和结束日期（例如 10-23 至 12-26），显示下行、上行、合计、计费用量和每日柱状图。快捷按钮有本周期、上个周期、近 7 天、近 30 天、本月、上月。
- 全部服务器：首页“区间统计”，列出每台在这段时间的流量和合计，点某一行可跳到该服务器的区间明细。
- 按整天统计，含首尾两天，最长 400 天（与小时明细保留天数一致）。

## 备份与还原

在“设置”里：

- 下载备份：一个 `.db` 文件，包含所有服务器设置、Agent Token、周期历史与小时明细。不含登录密码哈希和会话密钥（拿到备份的人不能登录面板），但内含 Agent Token，请妥善保管。
- 从备份还原：先验证文件（格式、完整性、表结构），再完全替换当前数据。还原前自动保存 `traffic.db.before-restore-时间`（保留最近 5 份）；当前登录密码、会话密钥和登录白名单不变；备份里的触发器和视图一律删除，每个字段都会重新校验（异常值改成默认值、格式不对或重复的 Token 换新），被人改过的备份文件既不能篡改密码，也不能往页面里塞脚本。

迁移面板：旧面板下载备份 → 新面板还原 → 各台 VPS 把 `/etc/vps-traffic/agent.conf` 的 `SERVER` 改成新地址后 `systemctl restart vps-traffic-agent`。

## Telegram 告警（可选）

在 `/etc/vps-traffic-panel.env`（权限 600，只有 root 能读）里填上 `VT_TG_TOKEN` 和 `VT_TG_CHAT`，然后 `systemctl restart vps-traffic-panel`。不要写在服务文件里：服务文件所有用户都能读。旧版写在服务文件里的设置，升级时会自动搬过去。

用量到 80%、95%、100% 时各提醒一次；周期中途调高额度后，按新额度重新计算提醒。

## 数据保留

- 周期记录：永久保留
- 每小时明细：保留 400 天

## 已知限制

- 上报失败时 Agent 会累积增量并在下次补送；如果补送时已跨过重置点，这部分会计入新周期
- 只统计一张网卡；Docker/TUN 等虚拟网卡不计入
- 面板收到上报但响应丢失时，该次增量可能重复计算一次
