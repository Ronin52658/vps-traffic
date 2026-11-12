#!/bin/sh
# Agent 一键安装 / 卸载
#   安装：curl -fsSL <面板>/install.sh | sh -s -- --server <面板> --token <TOKEN> [--iface eth0] [--interval 3]
#   卸载：curl -fsSL <面板>/install.sh | sh -s -- --uninstall
set -e
SERVER="" TOKEN="" IFACE="auto" INTERVAL=3 UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
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

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1"; else wget -qO- "$1"; fi
}

# 旧版以 root 运行时留下的状态目录：先停掉旧 Agent 再删除，交给 systemd 重建（只损失几秒的计数）
if [ -d /var/lib/vps-traffic ] && [ ! -L /var/lib/vps-traffic ]; then
  systemctl stop vps-traffic-agent 2>/dev/null || true
  rm -rf /var/lib/vps-traffic
fi
mkdir -p /opt/vps-traffic /etc/vps-traffic
fetch "$SERVER/agent.sh" > /opt/vps-traffic/agent.sh
chmod 755 /opt/vps-traffic/agent.sh

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
CapabilityBoundingSet=
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
