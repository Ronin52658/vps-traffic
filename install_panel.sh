#!/bin/sh
# 面板一键部署 / 升级：在仓库目录里以 root 运行。面板强制 HTTPS，只能经反代（如 Nginx Proxy Manager）访问
#   sh install_panel.sh --domain traffic.example.com [--port 8080] [--proxy 127.0.0.1,::1,172.16.0.0/12]
#                       [--listen 0.0.0.0] [--password 你的密码] [--tz Asia/Shanghai]
#   升级时不用再写 --domain 等参数，沿用原来的设置
#   sh install_panel.sh --password 新密码       （只想重设密码时也可以这样用）
#   sh install_panel.sh --ask-password          （交互输入密码，不留在历史记录里）
#   sh install_panel.sh --uninstall             （保留数据库 /var/lib/vps-traffic-panel）
set -e
PORT="" PASSWORD="" TZNAME="" UNINSTALL=0 DOMAIN="" PROXIES="" LISTEN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ask-password)
      # 交互输入密码，不会留在 shell 历史和进程列表里
      stty -echo 2>/dev/null; printf '新密码（至少 8 位）：'; read -r PASSWORD; stty echo 2>/dev/null; echo
      shift ;;
    --port) PORT=$2; shift 2 ;;
    --domain) DOMAIN=$2; shift 2 ;;
    --proxy) PROXIES=$2; shift 2 ;;
    --listen) LISTEN=$2; shift 2 ;;
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
  echo "已卸载，数据库保留在 $DATA，敏感设置保留在 /etc/vps-traffic-panel.env"
  echo "（不需要的话 rm -rf $DATA /etc/vps-traffic-panel.env，并 userdel $USR）"
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
  [ -n "$PROXIES" ] || PROXIES=$(sed -n 's/^Environment=VT_TRUSTED_PROXIES=//p' "$SVC" | head -1)
  [ -n "$LISTEN" ] || LISTEN=$(sed -n 's/^Environment=VT_LISTEN=//p' "$SVC" | head -1)
  OLD_URL=$(sed -n 's/^Environment=VT_PUBLIC_URL=//p' "$SVC" | head -1)
  OLD_TG_TOKEN=$(sed -n 's/^Environment=VT_TG_TOKEN=//p' "$SVC" | head -1)
  OLD_TG_CHAT=$(sed -n 's/^Environment=VT_TG_CHAT=//p' "$SVC" | head -1)
fi
PORT=${PORT:-8080}
TZNAME=${TZNAME:-Asia/Shanghai}
PROXIES=${PROXIES:-127.0.0.1,::1,172.16.0.0/12}
LISTEN=${LISTEN:-0.0.0.0}

# 面板域名：强制 HTTPS 后必须有。升级时沿用原来的；示例值不算
DOMAIN=${DOMAIN#https://}; DOMAIN=${DOMAIN#http://}; DOMAIN=${DOMAIN%%/*}; DOMAIN=${DOMAIN%:443}
if [ -n "$DOMAIN" ]; then
  PUBLIC_URL="https://$DOMAIN"
elif [ -n "$OLD_URL" ] && [ "$OLD_URL" != "https://traffic.example.com" ] && [ "${OLD_URL#https://}" != "$OLD_URL" ]; then
  PUBLIC_URL=$OLD_URL
else
  echo "面板已改为强制 HTTPS，请用 --domain 指定反代用的域名，例如："
  echo "  sh install_panel.sh --domain traffic.example.com"
  exit 1
fi
printf '%s' "${PUBLIC_URL#https://}" | grep -Eq '^[A-Za-z0-9.-]+(:[0-9]{1,5})?$' || { echo "域名格式不对：$PUBLIC_URL"; exit 1; }
printf '%s' "$PROXIES" | grep -Eq '^[0-9A-Fa-f.:/,]+$' || { echo "--proxy 格式不对：$PROXIES"; exit 1; }
printf '%s' "$TZNAME" | grep -Eq '^[A-Za-z0-9_+/-]{1,64}$' || { echo "--tz 格式不对：$TZNAME"; exit 1; }
printf '%s' "$PORT" | grep -Eq '^[0-9]{1,5}$' || { echo "--port 须为数字"; exit 1; }
printf '%s' "$LISTEN" | grep -Eq '^[0-9A-Fa-f.:]+$' || { echo "--listen 格式不对：$LISTEN"; exit 1; }

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

# systemd 服务：按模板生成，保留原来的端口、时区、域名和反代设置
sed -e "s/^Environment=VT_PORT=.*/Environment=VT_PORT=$PORT/" \
    -e "s#^Environment=VT_TZ=.*#Environment=VT_TZ=$TZNAME#" \
    -e "s#^Environment=VT_LISTEN=.*#Environment=VT_LISTEN=$LISTEN#" \
    -e "s#^Environment=VT_PUBLIC_URL=.*#Environment=VT_PUBLIC_URL=$PUBLIC_URL#" \
    -e "s#^Environment=VT_TRUSTED_PROXIES=.*#Environment=VT_TRUSTED_PROXIES=$PROXIES#" \
    "$SRC/vps-traffic-panel.service" > "$SVC"
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

echo
echo "部署完成，状态：$state（以 $USR 用户 + 只读沙箱运行）"
echo "访问地址：$PUBLIC_URL（强制 HTTPS，直接访问 IP:$PORT 会被拒绝）"
if [ -n "$PASSWORD" ]; then echo "登录密码：$PASSWORD"; else echo "登录密码：沿用原来的密码"; fi
echo "数据目录：$DATA"
if [ "$state" != "active" ]; then
  echo; echo "启动失败，最近日志："
  journalctl -u vps-traffic-panel -n 30 --no-pager 2>/dev/null || true
fi
echo
echo "反代设置（Nginx Proxy Manager）：域名 ${PUBLIC_URL#https://} → http://<这台机器的 IP>:$PORT，"
echo "  申请 Let's Encrypt 证书并开启 Force SSL。反代来源须在信任列表内：$PROXIES"
echo "建议在防火墙/安全组里不要对公网开放 TCP $PORT（只让反代访问）。"
