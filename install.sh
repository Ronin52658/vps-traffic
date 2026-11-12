#!/bin/sh
# Agent 一键安装 / 卸载（从 GitHub 固定提交下载，校验 SHA256 后才安装）
#   面板“新增服务器”会生成完整命令：先下载本脚本并校验 SHA256，再运行
#   安装：sh install.sh --ref <提交> --server <面板> --token <TOKEN> [--iface eth0] [--interval 3]
#   连不上 GitHub 时：
#     --agent-file ./agent.sh   用手动传上来的 agent.sh（同样校验 SHA256，不联网下载）
#     --mirror <前缀>           经镜像下载，例如 --mirror https://ghfast.top/（下载后同样校验 SHA256，镜像改不了内容）
#   卸载：sh install.sh --uninstall
set -e

# agent.sh 的 SHA256：agent.sh 每次修改后用 sh tools/pin_agent.sh hash 更新
REPO="Ronin52658/vps-traffic"
AGENT_SHA256="c5804c0d25cc74581be6cb69247da8996fa558cc86e1b7b3e0a62dea0ed07d58"

SERVER="" TOKEN="" IFACE="auto" INTERVAL=3 UNINSTALL=0 REF="" AGENT_FILE="" MIRROR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF=$2; shift 2 ;;
    --agent-file) AGENT_FILE=$2; shift 2 ;;
    --mirror) MIRROR=$2; shift 2 ;;
    --server) SERVER=${2%/}; shift 2 ;;
    --token) TOKEN=$2; shift 2 ;;
    --iface) IFACE=$2; shift 2 ;;
    --interval) INTERVAL=$2; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) echo "未知参数：$1"; exit 1 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "请用 root 运行"; exit 1; }

if [ "$UNINSTALL" = 1 ]; then
  systemctl disable --now vps-traffic-agent 2>/dev/null || true
  rm -f /etc/systemd/system/vps-traffic-agent.service
  systemctl daemon-reload
  rm -rf /opt/vps-traffic /etc/vps-traffic /var/lib/vps-traffic /var/lib/private/vps-traffic
  echo "已卸载"
  exit 0
fi

[ -n "$SERVER" ] && [ -n "$TOKEN" ] || { echo "需要 --server 与 --token"; exit 1; }
# 这些值会写进配置文件，只接受安全字符
printf '%s' "$SERVER" | grep -Eq '^https?://[]A-Za-z0-9.:[-]+(/[A-Za-z0-9._~/-]*)?$' || { echo "--server 格式不对：$SERVER"; exit 1; }
printf '%s' "$TOKEN" | grep -Eq '^[A-Za-z0-9_-]{16,128}$' || { echo "--token 格式不对"; exit 1; }
printf '%s' "$IFACE" | grep -Eq '^[A-Za-z0-9_.@:-]{1,15}$' || { echo "--iface 格式不对：$IFACE"; exit 1; }
printf '%s' "$INTERVAL" | grep -Eq '^[0-9]{1,3}$' || { echo "--interval 须为数字"; exit 1; }
if [ -n "$AGENT_FILE" ]; then
  [ -f "$AGENT_FILE" ] || { echo "找不到 $AGENT_FILE"; exit 1; }
else
  # 只接受完整的 40 位提交哈希，不接受分支或标签（分支内容会变）
  printf '%s' "$REF" | grep -Eq '^[0-9a-f]{40}$' || { echo "需要 --ref <40 位提交哈希>（或用 --agent-file 指定手动上传的 agent.sh）"; exit 1; }
  [ -z "$MIRROR" ] || printf '%s' "$MIRROR" | grep -Eq '^https://[A-Za-z0-9.:/_-]+/$' \
    || { echo "--mirror 须为 https:// 开头、/ 结尾的地址，例如 https://ghfast.top/"; exit 1; }
fi
command -v sha256sum >/dev/null 2>&1 || { echo "缺少 sha256sum（coreutils）"; exit 1; }

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; else wget -q --https-only -O "$2" "$1"; fi
}

# 先下载到临时文件并校验，通过后才替换正在用的 agent.sh
mkdir -p /opt/vps-traffic
TMP=$(mktemp /opt/vps-traffic/.agent.sh.XXXXXX)
trap 'rm -f "$TMP"' EXIT
if [ -n "$AGENT_FILE" ]; then
  cat "$AGENT_FILE" > "$TMP"
  SRC_DESC="本地文件 $AGENT_FILE"
else
  URL="${MIRROR}https://raw.githubusercontent.com/$REPO/$REF/agent.sh"
  fetch "$URL" "$TMP" || { echo "下载失败：$URL"; echo "连不上 GitHub 可以加 --mirror 镜像前缀，或手动上传 agent.sh 后用 --agent-file"; exit 1; }
  SRC_DESC="$REF"
fi
GOT=$(sha256sum "$TMP" | awk '{print $1}')
if [ "$GOT" != "$AGENT_SHA256" ]; then
  echo "agent.sh 的 SHA256 校验失败，已中止安装"
  echo "  期望：$AGENT_SHA256"
  echo "  实际：$GOT"
  exit 1
fi
echo "agent.sh 校验通过（$SRC_DESC）"

# 旧版以 root 运行时留下的状态目录：先停掉旧 Agent 再删除，交给 systemd 重建（只损失几秒的计数）
if [ -d /var/lib/vps-traffic ] && [ ! -L /var/lib/vps-traffic ]; then
  systemctl stop vps-traffic-agent 2>/dev/null || true
  rm -rf /var/lib/vps-traffic
fi
mkdir -p /etc/vps-traffic
chmod 755 "$TMP"
mv -f "$TMP" /opt/vps-traffic/agent.sh

umask 077
cat > /etc/vps-traffic/agent.conf <<EOF
SERVER="$SERVER"
TOKEN="$TOKEN"
IFACE="$IFACE"
INTERVAL="$INTERVAL"
EOF

cat > /etc/systemd/system/vps-traffic-agent.service <<'EOF'
[Unit]
Description=VPS Traffic Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/bin/sh /opt/vps-traffic/agent.sh
Restart=always
RestartSec=5

# ---- 降权：每次启动分配一个临时普通用户，不是 root ----
DynamicUser=yes
# 配置文件只有 root 能读；systemd 以 root 读取后作为环境变量交给 Agent
EnvironmentFile=/etc/vps-traffic/agent.conf
# 唯一可写的目录（实际位于 /var/lib/private/vps-traffic，由 systemd 创建并交给临时用户）
StateDirectory=vps-traffic
StateDirectoryMode=0700
UMask=0077

# ---- 只读沙箱 ----
NoNewPrivileges=yes
# 只留 CAP_NET_RAW：系统自带的 ping 带有这个文件能力，边界集里没有它时 ping 根本无法执行。
# 因为 NoNewPrivileges=yes，ping 运行时也拿不到这个能力，只能用内核给普通用户的 ICMP（ping_group_range）
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
# 只允许联网（IPv4/IPv6）、本地 socket 和读路由表（自动识别网卡用）
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/vps-traffic-agent.service
systemctl daemon-reload
systemctl enable vps-traffic-agent >/dev/null 2>&1
systemctl restart vps-traffic-agent
sleep 2
state=$(systemctl is-active vps-traffic-agent)
echo "安装完成，状态：$state（以普通用户 + 只读沙箱运行）"
if [ "$state" != "active" ]; then
  echo "启动失败，最近日志："
  journalctl -u vps-traffic-agent -n 20 --no-pager 2>/dev/null
fi
