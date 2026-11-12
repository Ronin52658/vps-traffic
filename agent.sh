#!/bin/sh
# VPS 流量监控 Agent：每 INTERVAL 秒读取网卡计数和系统状态，推送到面板
# 只读取 /proc、df 等本机信息；不监听端口，也不执行面板下发的任何命令
# 依赖：sh、awk、df、curl 或 wget（Debian 默认即有）
# 以 systemd 的临时普通用户运行：配置由 systemd 以 root 读取后通过环境变量传入，
# 状态目录由 systemd 的 StateDirectory 提供（$STATE_DIRECTORY）
CONF=${CONF:-/etc/vps-traffic/agent.conf}
STATE_DIR=${STATE_DIR:-${STATE_DIRECTORY:-/var/lib/vps-traffic}}
STATE="$STATE_DIR/state"
[ -r "$CONF" ] && . "$CONF"

: "${SERVER:?SERVER 未设置}"
: "${TOKEN:?TOKEN 未设置}"
INTERVAL=${INTERVAL:-3}
IFACE=${IFACE:-auto}
SERVER=${SERVER%/}

mkdir -p "$STATE_DIR" 2>/dev/null
[ -w "$STATE_DIR" ] || { echo "状态目录 $STATE_DIR 不可写" >&2; exit 1; }

detect_iface() {
  i=$(ip route show default 2>/dev/null | awk '{for(n=1;n<NF;n++) if($n=="dev"){print $(n+1); exit}}')
  [ -z "$i" ] && i=$(ip -6 route show default 2>/dev/null | awk '{for(n=1;n<NF;n++) if($n=="dev"){print $(n+1); exit}}')
  [ -z "$i" ] && i=$(awk 'NR>2{l=$0; sub(/^[ \t]+/,"",l); n=substr(l,1,index(l,":")-1); if(n!="lo"){print n; exit}}' /proc/net/dev)
  echo "$i"
}

# 输出 "rx tx"（以字串形式输出，避免 awk 浮点转换）
read_counters() {
  awk -v want="$1" 'NR>2{
    l=$0; sub(/^[ \t]+/,"",l); p=index(l,":")
    if (substr(l,1,p-1)==want) { split(substr(l,p+1),f," "); print f[1], f[9]; exit }
  }' /proc/net/dev
}

# 上报成功时输出面板的回应（含面板设定的刷新间隔）
post() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 15 -X POST \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d "$1" "$SERVER/api/report" 2>/dev/null
  else
    wget -q -T 15 -O - \
      --header="Authorization: Bearer $TOKEN" --header="Content-Type: application/json" \
      --post-data="$1" "$SERVER/api/report" 2>/dev/null
  fi
}

# ---- 系统状态 ----
# /proc/stat 第一行：返回 “总时间 空闲时间”
read_cpu() { awk '/^cpu /{t=0; for(i=2;i<=9;i++) t+=$i; printf "%.0f %.0f", t, $5+$6; exit}' /proc/stat; }

clean() { printf '%s' "$1" | tr -d '"\\' | tr -d '\000-\037' | cut -c1-120; }

# 动态指标：CPU、负载、内存、Swap、硬盘、连接数、进程数、运行时间
sys_json() {
  set -- $(read_cpu)
  if [ -n "$cpu_t" ] && [ "$1" -gt "$cpu_t" ]; then
    cpu=$(awk -v a=$(($1 - cpu_t)) -v b=$(($2 - cpu_i)) 'BEGIN{printf "%.1f", 100*(a-b)/a}')
  else
    cpu=0
  fi
  cpu_t=$1 cpu_i=$2
  read -r l1 l2 l3 _ < /proc/loadavg
  read -r up _ < /proc/uptime
  up=${up%.*}
  mem=$(awk '/^MemTotal:/{t=$2}/^MemAvailable:/{a=$2}/^MemFree:/{f=$2}/^Buffers:/{b=$2}/^Cached:/{c=$2}
    /^SwapTotal:/{st=$2}/^SwapFree:/{sf=$2}
    END{if(a=="")a=f+b+c; printf "%.0f,%.0f,%.0f,%.0f", t*1024, (t-a)*1024, st*1024, (st-sf)*1024}' /proc/meminfo)
  disk=$(df -kP / 2>/dev/null | awk 'NR==2{printf "%.0f,%.0f", $2*1024, $3*1024}')
  [ -n "$disk" ] || disk="0,0"
  tf="" uf=""
  for x in /proc/net/tcp /proc/net/tcp6; do [ -r "$x" ] && tf="$tf $x"; done
  for x in /proc/net/udp /proc/net/udp6; do [ -r "$x" ] && uf="$uf $x"; done
  tcp=$( [ -n "$tf" ] && awk 'FNR>1{n++} END{print n+0}' $tf || echo 0)
  udp=$( [ -n "$uf" ] && awk 'FNR>1{n++} END{print n+0}' $uf || echo 0)
  procs=$(set -- /proc/[0-9]*; echo $#)
  printf '{"cpu":%s,"load":[%s,%s,%s],"mem":[%s],"disk":[%s],"tcp":%s,"udp":%s,"procs":%s,"uptime":%s}' \
    "$cpu" "$l1" "$l2" "$l3" "$mem" "$disk" "$tcp" "$udp" "$procs" "$up"
}

# 静态信息：系统、内核、CPU 型号、核心数、虚拟化（首次和之后每 10 分钟发一次）
info_json() {
  os=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | head -1)
  model=$(awk -F: '/^(model name|Hardware|cpu model|Processor)[ \t]*:/{sub(/^[ \t]+/,"",$2); print $2; exit}' /proc/cpuinfo)
  cores=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
  virt=$(systemd-detect-virt 2>/dev/null || echo "")
  printf '{"os":"%s","kernel":"%s","arch":"%s","cpu_model":"%s","cores":%s,"virt":"%s"}' \
    "$(clean "$os")" "$(clean "$(uname -r)")" "$(clean "$(uname -m)")" "$(clean "$model")" "${cores:-0}" "$(clean "$virt")"
}

save_state() {
  printf '%s %s %s %s %s\n' "$ifc" "$last_rx" "$last_tx" "$pend_rx" "$pend_tx" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
}

# 读取上次状态：网卡 上次rx 上次tx 未送出rx 未送出tx
s_ifc="" last_rx="" last_tx="" pend_rx=0 pend_tx=0
[ -f "$STATE" ] && read -r s_ifc last_rx last_tx pend_rx pend_tx < "$STATE"
pend_rx=${pend_rx:-0}; pend_tx=${pend_tx:-0}

HOST=$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-')
ifc="" cpu_t="" cpu_i="" info_at=""

while :; do
  if [ "$IFACE" = "auto" ]; then ifc=$(detect_iface); else ifc=$IFACE; fi
  # 网卡变了：重新记基准，不计算差值
  if [ -n "$s_ifc" ] && [ "$s_ifc" != "$ifc" ]; then last_rx=""; last_tx=""; fi
  s_ifc=$ifc

  set -- $(read_counters "$ifc")
  if [ $# -eq 2 ]; then
    cur_rx=$1 cur_tx=$2
    if [ -z "$last_rx" ]; then
      d_rx=0 d_tx=0
    else
      # 计数器变小代表重开机或网卡重建，直接以当前值为增量
      if [ "$cur_rx" -ge "$last_rx" ]; then d_rx=$((cur_rx - last_rx)); else d_rx=$cur_rx; fi
      if [ "$cur_tx" -ge "$last_tx" ]; then d_tx=$((cur_tx - last_tx)); else d_tx=$cur_tx; fi
    fi
    last_rx=$cur_rx last_tx=$cur_tx
    pend_rx=$((pend_rx + d_rx)) pend_tx=$((pend_tx + d_tx))
    sys=$(sys_json)
    info=""
    if [ -z "$info_at" ] || [ $((up - info_at)) -ge 600 ] || [ "$up" -lt "$info_at" ]; then
      info=",\"info\":$(info_json)"; info_at=$up
    fi
    body=$(printf '{"rx":%s,"tx":%s,"iface":"%s","hostname":"%s","sys":%s%s}' "$pend_rx" "$pend_tx" "$ifc" "$HOST" "$sys" "$info")
    if resp=$(post "$body"); then
      pend_rx=0 pend_tx=0
      # 跟随面板“设置”里的刷新间隔（只接受 1–300 秒）
      n=$(printf '%s' "$resp" | sed -n 's/.*"interval": *\([0-9][0-9]*\).*/\1/p')
      if [ -n "$n" ] && [ "$n" -ge 1 ] && [ "$n" -le 300 ]; then INTERVAL=$n; fi
    fi
    save_state
  else
    echo "找不到网卡 '$ifc'，请在 $CONF 设置 IFACE" >&2
  fi
  sleep "$INTERVAL"
done
