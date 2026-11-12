#!/bin/sh
# 面板一键部署 / 升级：在解压后的 vps-traffic 目录里以 root 运行
#   sh install_panel.sh [--port 8080] [--password 你的密码] [--tz Asia/Shanghai]
#   sh install_panel.sh --password 新密码       （只想重设密码时也可以这样用）
#   sh install_panel.sh --ask-password          （交互输入密码，不留在历史记录里）
#   sh install_panel.sh --uninstall             （保留数据库 /var/lib/vps-traffic-panel）
set -e
PORT="" PASSWORD="" TZNAME="" UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ask-password)
      # 交互输入密码，不会留在 shell 历史和进程列表里
      stty -echo 2>/dev/null; printf '新密码（至少 8 位）：'; read -r PASSWORD; stty echo 2>/dev/null; echo
      shift ;;
    --port) PORT=$2; shift 2 ;;
    --password) PASSWORD=$2; shift 2 ;;
    --tz) TZNAME=$2; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) echo "未知参数：$1"; exit 1 ;;
  esac
done
[ "$(id -u)" = "0" ] || { echo "请用 root 运行"; exit 1; }
DIR=/opt/vps-traffic-panel
DATA=/var/lib/vps-traffic-panel
SVC=/etc/systemd/system/vps-traffic-panel.service
USR=vps-traffic

if [ "$UNINSTALL" = 1 ]; then
  systemctl disable --now vps-traffic-panel 2>/dev/null || true
  rm -f "$SVC"; systemctl daemon-reload
  rm -rf "$DIR"
  echo "已卸载，数据库保留在 $DATA（不需要的话 rm -rf $DATA，并 userdel $USR）"
  exit 0
fi

SRC=$(cd "$(dirname "$0")" && pwd)
for f in server.py index.html agent_pin.json vps-traffic-panel.service; do
  [ -f "$SRC/$f" ] || { echo "缺少 $f，请在解压后的目录里运行"; exit 1; }
done
command -v python3 >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq python3; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || { echo "需要 Python 3.9 以上"; exit 1; }

# 升级时沿用原来的端口和时区（没有指定新值的话）
if [ -f "$SVC" ]; then
  [ -n "$PORT" ] || PORT=$(sed -n 's/^Environment=VT_PORT=//p' "$SVC" | head -1)
  [ -n "$TZNAME" ] || TZNAME=$(sed -n 's/^Environment=VT_TZ=//p' "$SVC" | head -1)
  OLD_PROXIES=$(sed -n 's/^Environment=VT_TRUSTED_PROXIES=//p' "$SVC" | head -1)
  OLD_TG_TOKEN=$(sed -n 's/^Environment=VT_TG_TOKEN=//p' "$SVC" | head -1)
  OLD_TG_CHAT=$(sed -n 's/^Environment=VT_TG_CHAT=//p' "$SVC" | head -1)
fi
PORT=${PORT:-8080}
TZNAME=${TZNAME:-Asia/Shanghai}

# 专用系统用户：没有 shell、没有家目录
id "$USR" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$USR"

# 程序文件：root 所有，面板只能读
mkdir -p "$DIR/flags"
rm -f "$DIR/agent.sh" "$DIR/install.sh"   # 旧版由面板提供 Agent 脚本，现改从 GitHub 下载
cp "$SRC/server.py" "$SRC/index.html" "$SRC/agent_pin.json" "$DIR/"
cp "$SRC"/flags/* "$DIR/flags/"
chown -R root:root "$DIR"
chmod -R u=rwX,go=rX "$DIR"

# 旧版数据库在 /opt/vps-traffic-panel 里：搬到数据目录
mkdir -p "$DATA"
if ls "$DIR"/traffic.db* >/dev/null 2>&1; then
  systemctl stop vps-traffic-panel 2>/dev/null || true
  if [ -f "$DATA/traffic.db" ]; then
    echo "注意：$DATA 里已有数据库，旧位置的数据库改名保留为 $DIR/legacy-*"
    for f in "$DIR"/traffic.db*; do mv "$f" "$DIR/legacy-$(basename "$f")"; done
  else
    mv "$DIR"/traffic.db* "$DATA/"
    echo "已把数据库从 $DIR 迁移到 $DATA"
  fi
fi
chown -R "$USR:$USR" "$DATA"
chmod 700 "$DATA"

# 敏感设置（Telegram）放在只有 root 能读的环境文件；旧版写在服务文件里的值自动搬过来
ENVF=/etc/vps-traffic-panel.env
if [ ! -f "$ENVF" ]; then
  ( umask 077
    { echo "# 面板的敏感设置，只有 root 能读；改完 systemctl restart vps-traffic-panel"
      echo "VT_TG_TOKEN=$OLD_TG_TOKEN"
      echo "VT_TG_CHAT=$OLD_TG_CHAT"; } > "$ENVF" )
  [ -n "$OLD_TG_TOKEN" ] && echo "已把 Telegram 设置从服务文件移到 $ENVF"
fi
chown root:root "$ENVF"; chmod 600 "$ENVF"

# systemd 服务：按模板生成，保留原来的端口、时区和反代设置
sed -e "s/^Environment=VT_PORT=.*/Environment=VT_PORT=$PORT/" \
    -e "s#^Environment=VT_TZ=.*#Environment=VT_TZ=$TZNAME#" \
    "$SRC/vps-traffic-panel.service" > "$SVC"
[ -n "$OLD_PROXIES" ] && sed -i "s#^\#Environment=VT_TRUSTED_PROXIES=.*#Environment=VT_TRUSTED_PROXIES=$OLD_PROXIES#" "$SVC"
chmod 644 "$SVC"

# 密码：以面板用户身份写入，保证数据库文件归属正确
# 密码经标准输入传给 server.py，不出现在进程列表里
setpw() { printf '%s\n' "$1" | runuser -u "$USR" -- env VT_DB="$DATA/traffic.db" python3 "$DIR/server.py" --set-password - >/dev/null; }
if [ -n "$PASSWORD" ]; then
  setpw "$PASSWORD"
elif [ ! -f "$DATA/traffic.db" ]; then
  PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')
  setpw "$PASSWORD"
fi

systemctl daemon-reload
systemctl enable vps-traffic-panel >/dev/null 2>&1
systemctl restart vps-traffic-panel
sleep 2
state=$(systemctl is-active vps-traffic-panel || true)

IP=$(curl -4 -fsS -m 5 https://api.ipify.org 2>/dev/null || curl -4 -fsS -m 5 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
echo
echo "部署完成，状态：$state（以 $USR 用户 + 只读沙箱运行）"
echo "访问地址：http://$IP:$PORT"
if [ -n "$PASSWORD" ]; then echo "登录密码：$PASSWORD"; else echo "登录密码：沿用原来的密码"; fi
echo "数据目录：$DATA"
if [ "$state" != "active" ]; then
  echo; echo "启动失败，最近日志："
  journalctl -u vps-traffic-panel -n 30 --no-pager 2>/dev/null || true
fi
echo
echo "如果打不开，请在防火墙和云厂商安全组放行 TCP $PORT 端口。"
