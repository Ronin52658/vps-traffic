# VPS 流量监控面板

一个轻量的 VPS 流量与状态监控面板：每台 VPS 上跑一个 sh 写的 Agent，把网卡流量和系统状态推送到面板；面板按你设定的周期累计流量、到量提醒，并能做延迟监测和离线通知。

- **面板**：Python 标准库（3.9+）+ SQLite，单个网页，无需安装任何依赖
- **Agent**：只用 `sh` + `awk` + `curl`/`wget`，不监听端口、不执行面板下发的命令，以非 root 沙箱运行
- **安装可验证**：Agent 从 GitHub 固定提交下载，安装前双层 SHA256 校验
- **强制 HTTPS**：面板只能经反代（如 Nginx Proxy Manager）以 `https://域名` 访问

## 功能

| 功能 | 说明 |
|---|---|
| 流量统计 | 按日/周期累计上下行，自定义重置规则和计费方式，历史周期永久保留 |
| 系统监控 | CPU、负载、内存/Swap、硬盘、连接数、进程、运行时间、系统配置，折线图最长 7 天 |
| 实时刷新 | 有人看面板时按实时间隔（默认 3 秒）上报，没人看时放慢到空闲间隔（默认 60 秒）省流量 |
| 延迟监测 | ICMP / TCP，指定由哪些服务器测哪些目标，数据保留 30 天 |
| 分组 | 自定义分组，一台可属于多个分组，首页汇总和列表按当前分组显示 |
| Telegram | 流量到 80% / 95% / 100% 提醒，VPS 离线 / 恢复上线通知 |
| 区间查询 | 单台或全部服务器任意日期区间的流量 |
| 备份还原 | 一键下载 / 还原数据库，还原时逐项校验 |

## 快速开始

### 1. 部署面板

准备一个域名解析到反代所在的机器，在面板机器上以 root 运行：

```sh
git clone https://github.com/Ronin52658/vps-traffic.git && cd vps-traffic
sh install_panel.sh --domain traffic.example.com --port 8080
```

结束后会打印随机生成的登录密码。想自己设密码，加 `--ask-password`（至少 8 位，不会留在 shell 历史里）。

| 参数 | 说明 |
|---|---|
| `--domain` | 面板域名，首次安装必填 |
| `--port` | 监听端口，默认 8080 |
| `--listen` | 监听地址，默认 `0.0.0.0`（Docker 里的 NPM 需要能连到） |
| `--proxy` | 信任的反代地址（逗号分隔的 IP 或网段），默认 `127.0.0.1,::1,172.16.0.0/12` |
| `--cloudflare on\|off` | 域名开了 Cloudflare 代理（橙色云朵）时必须 `on` |
| `--tz` | 时区，默认 `Asia/Shanghai`，所有重置点按这个时区的 0 点计算 |
| `--ask-password` / `--password` | 交互输入 / 直接指定登录密码 |
| `--uninstall` | 卸载面板（数据库保留） |

- `--proxy`：NPM 在另一台机器上时填那台的 IP。信任列表里的地址可以伪造访客 IP，同机还跑着不受信任的 Docker 容器时，建议缩小到 NPM 所在网段（`docker network inspect` 查看）。
- `--cloudflare on`：不开的话，面板看到的访客和 VPS 的 IP 都是 Cloudflare 节点地址，国旗和登录限流都会出错。开启后，仅当连到 NPM 的是 Cloudflare 节点时才采信 `CF-Connecting-IP`。Cloudflare 的 SSL 模式要用 Full 或 Full (strict)。

### 2. 配置 HTTPS 反代（Nginx Proxy Manager）

1. 新增 Proxy Host：Domain 填 `--domain` 的域名；Forward 填 `http` + 面板机器 IP + 8080。NPM 和面板在同一台时，填 Docker 网桥网关（如 `172.17.0.1`）或本机公网 IP。
2. SSL 页签申请 Let's Encrypt 证书，开启 Force SSL（建议也开 HTTP/2、HSTS）。
3. 用 `https://域名` 登录。
4. 建议在防火墙 / 安全组里关掉 8080 的公网访问，只让反代连。

报 502 或页面显示“需要 HTTPS”：说明请求不是从信任的反代、或不是经 HTTPS 来的。检查 NPM 的来源地址是否在 `--proxy` 列表里，`journalctl -u vps-traffic-panel` 可以看到当前的信任列表。

### 3. 加入 VPS

面板首页“设置”→“新增服务器”，复制生成的三行命令，在 VPS 上以 root 运行：

```sh
if command -v curl >/dev/null; then curl -fsSL --proto '=https' -o /root/vps-traffic-install.sh <地址>; else wget -q --https-only -O /root/vps-traffic-install.sh <地址>; fi
echo "<install.sh 的 SHA256>  /root/vps-traffic-install.sh" | sha256sum -c - && sh /root/vps-traffic-install.sh --ref <提交> --server 'https://traffic.example.com' --token <TOKEN> --interval 3
rm -f /root/vps-traffic-install.sh
```

- 命令固定在 `agent_pin.json` 指定的提交，仓库之后再改，同一条命令装出来的仍是同一份代码。
- 双层校验：命令先校验 install.sh，install.sh 再校验 agent.sh（哈希写在 install.sh 里），任一不一致都中止，不改动 VPS。
- 可选参数加在第二行末尾：`--iface eth0` 指定网卡（默认按默认路由自动检测）。
- 卸载：`sh /root/vps-traffic-install.sh --uninstall`（第二行末尾的参数换成 `--uninstall`）。

**VPS 连不上 GitHub**：服务器“设置”里安装命令下方展开“VPS 连不上 GitHub？”，面板会生成两种装法：

- **手动上传**：在能访问 GitHub 的机器上下载固定提交的 `install.sh` 和 `agent.sh`，传到 VPS 的 `/root/`，运行 `sh install.sh --agent-file agent.sh --server ... --token ...`。
- **经镜像下载**：下载地址前加镜像前缀，并给 install.sh 加 `--mirror https://ghfast.top/`。镜像失效时换别的前缀即可。

两种方式都照样校验 SHA256，镜像或传输途中被改过的文件装不上。

### 4. 更新 Agent

Agent 版本和面板固定的版本不一致时，首页卡片显示“Agent 需更新”。在要升级的 VPS 上以 root 运行（可以用终端工具的“发送到所有会话”批量执行）：

```sh
wget -qO- https://raw.githubusercontent.com/Ronin52658/vps-traffic/main/update.sh | sh
```

- 读取 main 分支的 `agent_pin.json`，下载固定提交的 install.sh 并校验后以 `--upgrade` 运行；面板地址、Token、网卡、间隔沿用原配置，流量数据不受影响。
- 已是最新时什么都不做；`FORCE=1` 强制重装（`... | FORCE=1 sh`）。
- 连不上 GitHub：`wget -qO- https://ghfast.top/https://raw.githubusercontent.com/Ronin52658/vps-traffic/main/update.sh | MIRROR=https://ghfast.top/ sh`
- 面板没有一键更新，Agent 也不会自动更新，升级始终由你在 VPS 上执行。建议先升一台观察几分钟再批量。

### 5. 升级面板

```sh
cd vps-traffic && git pull && sh install_panel.sh
```

数据库、密码、域名、端口、时区、反代、Cloudflare 和 Telegram 设置都会保留。

## 使用说明

### 重置规则与计费

- **每月固定日**：例如 31 号，小月自动改在当月最后一天
- **每隔 N 天**：从起算日期开始每 N 天一轮
- **仅手动重置**：周期不会自动结束

修改规则时当前周期起点不变，按新规则重算结束时间。计费方式可选双向相加、仅上行、仅下行、取较大方向，额度百分比、提醒和用量条都按计费方式计算。

### 刷新间隔

“设置”→“刷新间隔”。Agent 每次上报后按面板的回应自动调整，不用登录 VPS 修改：

- **实时间隔**（默认 3 秒）：最近 90 秒内有人在看面板时使用
- **空闲间隔**（默认 60 秒）：没人看时使用；打开面板后最多等一个空闲间隔切到实时

每次上报约 1.3 KB：一直按 3 秒上报每台每月约 1.1 GB，按 60 秒约 55 MB。

### 系统监控

- 首页卡片：在线时长、系统、CPU、内存、硬盘、流量周期用量、实时网速。顶部汇总在线数、总网速、今日流量、内存和硬盘用量。
- 详情页“监控”：系统信息、Agent 版本，以及 CPU、负载、内存与 Swap、硬盘、网速、连接数、进程七张图，可选实时 / 1 小时 / 6 小时 / 24 小时 / 7 天。数据按分钟保存 7 天。
- IP 是面板看到的上报来源地址（NAT 机显示出口 IP）。双栈机器分别显示 IPv4 和 IPv6，超过一天没见到的地址不再显示。
- 国旗：第一次见到某个 IP 时向 ipinfo.io（备用 ip-api.com）查一次国家并存库，只发送这个 IP；也可以在服务器设置里手动填两位国家代码。

### 分组

“设置”→“分组”→“管理分组”，或在单台服务器的“设置”分页里勾选所属分组。

- 一台服务器可以属于多个分组，删除分组不会删除服务器。
- 首页顶部出现分组栏（“全部”+ 自定义分组），切换后顶部汇总、服务器列表和“区间统计”都只算当前分组，浏览器会记住上次的选择。

### 延迟监测

“设置”→“延迟监测”→“管理测试目标”：

- **任务视图**：添加目标（ICMP 或 TCP、IP / 域名、端口、间隔 30–300 秒），勾选由哪些服务器测。
- **服务器视图**：按服务器勾选要测哪些目标。
- 详情页“延迟”分页：1 小时到 30 天或自定义区间；每个目标显示当前延迟、丢包率、抖动，可开关曲线，“平滑峰值”压掉偶发尖刺。
- 测法：ICMP 每次 5 个包；TCP 每次连 3 次只量建连时间，超过 2 秒算丢失。抖动为相邻两次延迟差的平均值。
- 数据每分钟一个点，保留 30 天。每个“目标 × 服务器”组合 30 天约 2.6 MB。修改目标地址、方式或端口会清空该目标的历史。
- 显示“无法探测”：VPS 不允许普通用户 ping 时，在 VPS 上运行 `sysctl -w net.ipv4.ping_group_range="0 2147483647"`，或改用 TCP。

### 区间查询

- 单台：详情页“区间查询”，显示下行、上行、合计、计费用量和每日柱状图，有本周期、上个周期、近 7 / 30 天、本月、上月等快捷按钮。
- 全部：首页“区间统计”，点某一行跳到该服务器的明细。
- 按整天统计，含首尾两天，最长 400 天。

### Telegram 通知

在 `/etc/vps-traffic-panel.env`（权限 600）里填上：

```sh
VT_TG_TOKEN=机器人Token
VT_TG_CHAT=聊天ID
```

然后 `systemctl restart vps-traffic-panel`。不要写进服务文件，服务文件所有用户都能读。

- **流量提醒**：用量到 80%、95%、100% 各提醒一次；周期中途调高额度后按新额度重新计算。
- **离线 / 上线通知**：“设置”→“离线通知”。超过设定时间（默认 3 分钟，1–60 分钟可调）没上报算离线，恢复时附带离线时长；多台同时变化合并成一条。
  - 判定时间至少是“空闲间隔 × 2 + 30 秒”，Agent 放慢上报时不会误判。
  - 面板刚重启的几分钟内不判定离线。
  - 单台服务器可以在它的“设置”分页里关掉通知。
  - “发送测试消息”可检查配置，失败时显示 Telegram 返回的原因。

### 备份与还原

“设置”里：

- **下载备份**：一个 `.db` 文件，包含服务器设置、Agent Token、周期历史和小时明细；不含登录密码和会话密钥，但含 Token，请妥善保管。
- **从备份还原**：先校验格式、完整性和表结构，再完全替换当前数据。还原前自动保存 `traffic.db.before-restore-时间`（保留最近 5 份）；当前密码和会话不变；每个字段都重新校验，被改过的备份既改不了密码，也塞不进脚本。

**迁移面板**：旧面板下载备份 → 新面板还原 → 各台 VPS 把 `/etc/vps-traffic/agent.conf` 里的 `SERVER` 改成新地址，再 `systemctl restart vps-traffic-agent`。

### 数据保留

| 数据 | 保留 |
|---|---|
| 周期记录 | 永久 |
| 每小时流量明细 | 400 天 |
| 系统监控（每分钟） | 7 天 |
| 延迟监测（每分钟） | 30 天 |

## 安全

### 登录

- 除 Agent 上报接口（Token 认证）外，所有页面和接口都要登录。
- 密码以 PBKDF2 哈希保存。登录保持 30 天、有访问自动续期（`VT_SESSION_DAYS` 可调）；改密码后其他设备失效，退出登录立即作废该会话。
- 登录限流：同一 IP 连续输错 5 次锁 15 分钟；全部 IP 10 分钟内失败 30 次时暂停陌生 IP 登录 15 分钟，最近 30 天成功登录过的 IP 不受影响。
- 忘记密码：在仓库目录运行 `sh install_panel.sh --ask-password`。

### 面板防护

- **强制 HTTPS**：只接受来自信任反代、且 `X-Forwarded-Proto: https`、Host 为设置域名的请求；其他来源建立连接后立即断开。Cookie 只经 HTTPS 发送，并下发 HSTS。
- **防跨站请求伪造**：改动类请求必须带专用请求头且 Origin 与地址一致；Cookie 为 SameSite=Strict。
- **内容安全策略**：只加载面板自己的脚本、样式和图片，禁止被其他网站嵌入。
- **抗慢速攻击**：单个连接 20 秒未完成请求即断开，最多同时处理 200 个连接。
- 证书过期等紧急情况进不去时，可在服务文件里把 `VT_REQUIRE_HTTPS=1` 临时改成 `0`，处理完记得改回。

### 面板的权限

面板以专用系统用户 `vps-traffic`（无 shell、无家目录）运行，不是 root：

- 程序文件 `/opt/vps-traffic-panel` 属于 root，面板只读
- 唯一可写的是数据目录 `/var/lib/vps-traffic-panel`
- 不能提权，看不到其他进程，系统调用限制在普通服务范围内

### Agent 的权限

Agent 由 systemd 以临时普通用户（`DynamicUser`）运行，不是 root：

- 整个系统只读、`/home` 不可见，只有自己的状态目录可写
- 不能提权、运行时没有任何 capability。能力边界集只留 `CAP_NET_RAW`，仅为让系统自带的 ping 能启动；因为 `NoNewPrivileges`，ping 实际只能用内核给普通用户的 ICMP
- 只能使用 IPv4 / IPv6、本地 socket 和读路由表
- 配置文件 `/etc/vps-traffic/agent.conf`（含 Token）只有 root 能读；上报时 Token 经标准输入交给 curl，`ps` 看不到
- 只读 /proc、df 等本机信息；延迟监测只接收“测哪个 IP / 域名、哪个端口、多久一次”，面板和 Agent 两边都校验，无法注入命令或参数

两者都可以用 `systemd-analyze security vps-traffic-panel` / `vps-traffic-agent` 查看沙箱评分。

## 文件

| 文件 | 用途 |
|---|---|
| `server.py` | 面板服务端 |
| `index.html` | 网页界面，由 server.py 直接提供 |
| `install_panel.sh` | 面板一键部署 / 升级 / 卸载 |
| `vps-traffic-panel.service` | 面板的 systemd 模板 |
| `agent.sh` | VPS 上运行的 Agent |
| `install.sh` | Agent 安装 / 升级 / 卸载，内含 agent.sh 的 SHA256 |
| `update.sh` | 在 VPS 上升级已装的 Agent |
| `agent_pin.json` | 固定的 Agent 版本：提交、install.sh 与 agent.sh 的 SHA256 |
| `tools/pin_agent.sh` | 更新哈希、切换固定提交、检查 GitHub 上的文件 |
| `flags/` | 国旗图片（Noto Color Emoji，Apache 2.0） |
| `icons/` | 网站图标 |
| `demo/` | 演示站：`mock.js` 模拟后端，`build_demo.py` 生成 `demo.html` |

## 发布新版 Agent

1. 修改 `agent.sh` 或 `install.sh`；改了 agent.sh 就运行 `sh tools/pin_agent.sh hash`，把新哈希写进 install.sh
2. 提交并推送
3. `sh tools/pin_agent.sh pin <刚才的提交>` 更新 `agent_pin.json`，再提交推送
4. `sh tools/pin_agent.sh check` 确认 GitHub 上的文件可下载且哈希一致
5. 面板机器上升级面板，之后生成的安装命令就用新提交；已装的 VPS 运行 update.sh 升级

合并 PR 请用 “Create a merge commit” 保留原提交哈希。也可以用环境变量 `VT_AGENT_REPO`、`VT_AGENT_COMMIT`、`VT_AGENT_INSTALL_SHA256` 覆盖固定版本。

## 已知限制

- 只统计一张网卡，Docker / TUN 等虚拟网卡不计入
- 上报失败时 Agent 会攒着增量下次补送；补送时已跨过重置点的话，这部分计入新周期
- 面板收到上报但响应丢失时，该次增量可能重复计算一次
- `/proc` 开了 `hidepid` 时进程数只统计到 Agent 自己；少数容器里“虚拟化”一栏可能为空
