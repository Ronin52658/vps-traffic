#!/bin/sh
# VPS 流量监控 Agent：每 INTERVAL 秒读取网卡计数和系统状态，推送到面板
# 只读取 /proc、df 等本机信息；不监听端口，也不执行面板下发的任何命令。
# 延迟监测：面板只下发“探测目标”（类型、IP/域名、端口、间隔），Agent 严格校验后自己用 ping 或 TCP 连接测量
# 依赖：sh、awk、df、curl 或 wget（Debian 默认即有）；ICMP 测试需要 ping，TCP 测试需要 curl
# 以 systemd 的临时普通用户运行：配置由 systemd 以 root 读取后通过环境变量传入，
# 状态目录由 systemd 的 StateDirectory 提供（$STATE_DIRECTORY）
# 固定用 C 语言环境：德语、法语等环境下 awk 会把小数点输出成逗号（12,5），JSON 就坏了
export LC_ALL=C
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
PROBES="$STATE_DIR/probes"      # 面板下发的探测目标：id,类型,主机,端口,间隔;…
LAT_DIR="$STATE_DIR/lat"        # 待上报的延迟结果，每次探测一个文件
mkdir -p "$LAT_DIR"

detect_iface() {
  i=$(ip route show default 2>/dev/null | awk '{for(n=1;n<NF;n++) if($n=="dev"){print $(n+1); exit}}')
  [ -z "$i" ] && i=$(ip -6 route show default 2>/dev/null | awk '{for(n=1;n<NF;n++) if($n=="dev"){print $(n+1); exit}}')
  # 没有 ip 命令（精简系统/容器）时，直接读内核路由表找默认路由网卡
  [ -z "$i" ] && i=$(awk 'NR>1 && $2=="00000000" && $8=="00000000"{print $1; exit}' /proc/net/route 2>/dev/null)
  [ -z "$i" ] && i=$(awk '$1=="00000000000000000000000000000000" && $2=="00" && $10!="lo"{print $10; exit}' /proc/net/ipv6_route 2>/dev/null)
  # 仍然找不到：取流量最大的非 lo 网卡（不再取第一张，第一张常是 ifb0、docker0 之类的虚拟网卡）
  [ -z "$i" ] && i=$(awk 'NR>2{l=$0; sub(/^[ \t]+/,"",l); p=index(l,":"); n=substr(l,1,p-1); split(substr(l,p+1),f," ");
    if(n!="lo" && f[1]+f[9]>=best){best=f[1]+f[9]; b=n}} END{print b}' /proc/net/dev)
  echo "$i"
}

# 输出 "rx tx"（以字串形式输出，避免 awk 浮点转换）
read_counters() {
  awk -v want="$1" 'NR>2{
    l=$0; sub(/^[ \t]+/,"",l); p=index(l,":")
    if (substr(l,1,p-1)==want) { split(substr(l,p+1),f," "); print f[1], f[9]; exit }
  }' /proc/net/dev
}

# Token 不放进命令行参数（本机任何用户都能用 ps 看到），改从标准输入或私有配置文件交给 curl/wget
case "$TOKEN" in *[!A-Za-z0-9_-]*) echo "TOKEN 含非法字符" >&2; exit 1 ;; esac
if ! command -v curl >/dev/null 2>&1; then
  WGETRC="$STATE_DIR/wgetrc"
  ( umask 077; printf 'header = Authorization: Bearer %s\n' "$TOKEN" > "$WGETRC" )
  export WGETRC
fi

# 上报成功时输出面板的回应（含面板设定的刷新间隔）
post() {
  if command -v curl >/dev/null 2>&1; then
    printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" |
      curl -fsS -m 15 -K - -X POST -H "Content-Type: application/json" \
        -d "$1" "$SERVER/api/report" 2>/dev/null
  else
    wget -q -T 15 -O - --header="Content-Type: application/json" \
      --post-data="$1" "$SERVER/api/report" 2>/dev/null
  fi
}

# 双栈机器：平时上报走哪个协议由系统决定（通常是 IPv6），面板只能看到这一个地址。
# 每 10 分钟分别强制用 IPv4、IPv6 各发一个只记地址的小请求，面板就能同时显示两个公网 IP。
# 只有单栈的机器，另一个协议会连不上，直接忽略
post_ip() {
  if command -v curl >/dev/null 2>&1; then
    printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" |
      curl "-$1" -fsS -m 10 -K - -X POST -H "Content-Type: application/json" \
        -d '{"ip_only":1}' "$SERVER/api/report" >/dev/null 2>&1
  else
    wget "-$1" -q -T 10 -O /dev/null --header="Content-Type: application/json" \
      --post-data='{"ip_only":1}' "$SERVER/api/report" >/dev/null 2>&1
  fi
}

# ---- 系统状态 ----
# /proc/stat 第一行：返回 “总时间 空闲时间”
read_cpu() { awk '/^cpu /{t=0; for(i=2;i<=9;i++) t+=$i; printf "%.0f %.0f", t, $5+$6; exit}' /proc/stat; }

clean() { printf '%s' "$1" | tr -d '"\\' | tr -d '\000-\037' | cut -c1-120; }

# 动态指标：CPU、负载、内存、Swap、硬盘、连接数、进程数、运行时间
# 结果写进变量 sys，必须在当前 shell 里调用（不能用 $(...)）：CPU 使用率要和上一次的计数比较，
# 上一次的计数存在 cpu_t/cpu_i 里，放进子 shell 就丢了，CPU 会一直是 0
build_sys() {
  set -- $(read_cpu)
  if [ -n "$cpu_t" ] && [ "$1" -gt "$cpu_t" ]; then
    # iowait 计数偶尔倒退，结果夹到 0–100
    cpu=$(awk -v a=$(($1 - cpu_t)) -v b=$(($2 - cpu_i)) 'BEGIN{v=100*(a-b)/a; if(v<0)v=0; if(v>100)v=100; printf "%.1f", v}')
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
  sys=$(printf '{"cpu":%s,"load":[%s,%s,%s],"mem":[%s],"disk":[%s],"tcp":%s,"udp":%s,"procs":%s,"uptime":%s}' \
    "$cpu" "$l1" "$l2" "$l3" "$mem" "$disk" "$tcp" "$udp" "$procs" "$up")
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

# ---- 延迟监测 ----
# 输出“发出 收到 平均ms 抖动ms 最大ms”；收到为 -1 表示探测本身出错（没有 ping、没有权限等）
probe_icmp() {
  # 字面 IP 指定协议族；域名交给 ping 自己选（纯 IPv6 的机器也能 ping 域名）
  case "$1" in *:*) f=-6 ;; *[!0-9.]*) f="" ;; *) f=-4 ;; esac
  $TMO ping $f -n -q -c 5 -i 1 -W 2 -- "$1" 2>/dev/null | awk '
    /packets transmitted/ {s=$1; r=$4}
    /(rtt|round-trip)/ {split($0, a, "="); gsub(/[ a-z]/, "", a[2]); n=split(a[2], v, "/"); avg=v[2]; mx=v[3]; if (n >= 4) jit=v[4]}
    END { if (s == "") print "0 -1 0 0 0"; else printf "%d %d %s %s %s\n", s, r, (avg == "" ? 0 : avg), (jit == "" ? 0 : jit), (mx == "" ? 0 : mx) }'
}

# TCP：连 3 次，只量建立连接的时间（连不上或超过 2 秒算丢失）
probe_tcp() {
  command -v curl >/dev/null 2>&1 || { echo "0 -1 0 0 0"; return; }
  h=$1; case "$h" in *:*) h="[$h]" ;; esac
  out="" k=0
  while [ $k -lt 3 ]; do
    t=$($TMO curl -s -o /dev/null --connect-timeout 2 -m 2 -w '%{time_connect}' "telnet://$h:$2" </dev/null 2>/dev/null)
    out="$out ${t:-0}"; k=$((k + 1))
  done
  printf '%s\n' "$out" | awk '{ for (i = 1; i <= NF; i++) { s++; v = $i * 1000; if (v > 0) { r++; sum += v; if (v > mx) mx = v;
      if (p != "") { d = v - p; if (d < 0) d = -d; j += d; jn++ } p = v } }
    printf "%d %d %.2f %.2f %.2f\n", s, r, (r ? sum / r : 0), (jn ? j / jn : 0), mx }'
}

run_probe() {   # id 类型 主机 端口（在后台子进程里运行）
  IFS=' 	
'
  run="$LAT_DIR/.run.$1"
  : > "$run"
  trap 'rm -f "$run"' EXIT
  if [ "$2" = tcp ]; then res=$(probe_tcp "$3" "$4"); else res=$(probe_icmp "$3"); fi
  set -- "$1" $res
  [ $# -eq 6 ] || return
  f="$LAT_DIR/$(date +%s).$1"
  printf '[%s,%s,%s,%s,%s,%s]' "$1" "$2" "$3" "$4" "$5" "$6" > "$f.tmp" && mv "$f.tmp" "$f"
}

# 单次探测最多 25 秒（DNS 卡住时也不会无限挂着）；没有 timeout 命令就不限制
TMO=""; command -v timeout >/dev/null 2>&1 && TMO="timeout 25"

# 后台探测循环：每 5 秒看一次哪些目标到时间了，到了就在后台跑一次
prober() {
  set -f
  while :; do
    now=$(date +%s)
    if [ -f "$PROBES" ]; then
      old_ifs=$IFS; IFS=';'
      for item in $(cat "$PROBES"); do
        IFS=,; set -- $item; IFS=';'
        [ $# -eq 5 ] || continue
        id=$1 kind=$2 host=$3 port=$4 iv=$5
        # 再校验一遍：面板被攻破也只能让 Agent ping/连接一个 IP 或域名，不能注入参数
        case "$id$port$iv" in *[!0-9]*|"") continue ;; esac
        case "$kind" in icmp|tcp) ;; *) continue ;; esac
        case "$host" in -*|*[!A-Za-z0-9.:-]*|"") continue ;; esac
        [ "$iv" -ge 30 ] && [ "$iv" -le 300 ] || continue
        eval "last=\${last_$id:-0}"
        # 上一次还没测完（例如 DNS 卡住）就不再叠加；标记超过 2 分钟视为残留
        if [ -f "$LAT_DIR/.run.$id" ] && [ -z "$(find "$LAT_DIR/.run.$id" -mmin +2 2>/dev/null)" ]; then continue; fi
        if [ $((now - last)) -ge "$iv" ]; then
          eval "last_$id=$now"
          run_probe "$id" "$kind" "$host" "$port" &
        fi
      done
      IFS=$old_ifs
    fi
    sleep 5
  done
}

# 选出这次要上报的延迟结果（最多 300 条，设到 lat_files）；积压超过 2000 条时丢掉最旧的
lat_pick() {
  n=$(ls "$LAT_DIR" | grep -c '^[0-9]*\.[0-9]*$')
  [ "$n" -gt 2000 ] && ls "$LAT_DIR" | grep '^[0-9]*\.[0-9]*$' | sort -n | head -n $((n - 2000)) | (cd "$LAT_DIR" && xargs rm -f)
  lat_files=$(ls "$LAT_DIR" | grep '^[0-9]*\.[0-9]*$' | sort -n | head -n 300)
}

lat_json() {
  [ -n "$lat_files" ] || return
  printf ',"lat":['
  first=1
  for f in $lat_files; do
    # 只带格式正确的结果；坏的那条丢掉，免得整条上报一直失败、流量也一直送不出去
    line=$(cat "$LAT_DIR/$f" 2>/dev/null)
    case "$line" in
      \[*\]) ;;
      *) continue ;;
    esac
    printf '%s' "$line" | grep -Eq '^\[[0-9]{1,9},[0-9]{1,4},-?[0-9]{1,4}(,[0-9]{1,6}(\.[0-9]{1,6})?){3}\]$' || continue
    [ $first = 1 ] || printf ','
    printf '%s' "$line"; first=0
  done
  printf ']'
}

save_state() {
  printf '%s %s %s %s %s\n' "$ifc" "$last_rx" "$last_tx" "$pend_rx" "$pend_tx" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
}

# 读取上次状态：网卡 上次rx 上次tx 未送出rx 未送出tx
s_ifc="" last_rx="" last_tx="" pend_rx=0 pend_tx=0
[ -f "$STATE" ] && read -r s_ifc last_rx last_tx pend_rx pend_tx < "$STATE"
# 状态文件损坏（例如断电）时不能带着非数字进算术：dash 会直接报错退出，systemd 重启后又读到同一个坏文件，无限循环
num_ok() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ ${#1} -le 18 ]; }
num_ok "$last_rx" && num_ok "$last_tx" || { last_rx="" last_tx=""; }
num_ok "$pend_rx" && num_ok "$pend_tx" || { pend_rx=0 pend_tx=0; }

HOST=$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-')
ifc="" cpu_t="" cpu_i="" info_at=""
prober &

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
    build_sys
    info=""
    if [ -z "$info_at" ] || [ $((up - info_at)) -ge 600 ] || [ "$up" -lt "$info_at" ]; then
      info=",\"info\":$(info_json)"; info_at=$up
      ( post_ip 4; post_ip 6 ) &
    fi
    lat_pick
    lat=$(lat_json)
    body=$(printf '{"rx":%s,"tx":%s,"iface":"%s","hostname":"%s","sys":%s%s%s}' "$pend_rx" "$pend_tx" "$(clean "$ifc")" "$HOST" "$sys" "$info" "$lat")
    if resp=$(post "$body"); then
      pend_rx=0 pend_tx=0
      [ -n "$lat_files" ] && (cd "$LAT_DIR" && rm -f $lat_files)
      lat_files=""
      # 更新延迟探测目标（只接受安全字符；面板没带这个字段时保持不变）
      case "$resp" in *'"probes"'*)
        p=$(printf '%s' "$resp" | sed -n 's/.*"probes": *"\([A-Za-z0-9.:,;-]*\)".*/\1/p')
        [ "$p" = "$(cat "$PROBES" 2>/dev/null)" ] || printf '%s' "$p" > "$PROBES" ;;
      esac
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
