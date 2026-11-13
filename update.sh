#!/bin/sh
# 升级本机的 VPS 流量 Agent：沿用原来的面板地址、Token、网卡和上报间隔，流量数据不受影响
#
#   wget -qO- https://raw.githubusercontent.com/Ronin52658/vps-traffic/main/update.sh | sh
#   或：wget -q https://raw.githubusercontent.com/Ronin52658/vps-traffic/main/update.sh && bash update.sh
#
# 连不上 GitHub 时经镜像下载（下载的文件照样校验 SHA256，镜像改不了内容）：
#   wget -qO- https://ghfast.top/https://raw.githubusercontent.com/Ronin52658/vps-traffic/main/update.sh | MIRROR=https://ghfast.top/ sh
#
# 做的事情：读取仓库 main 分支的 agent_pin.json（当前固定的提交和 install.sh 的 SHA256）→
# 下载该提交的 install.sh 并校验 → 运行 install.sh --upgrade（它会再校验 agent.sh 的 SHA256）。
# 已经是最新版本时什么都不做；FORCE=1 强制重装。
set -e

REPO="Ronin52658/vps-traffic"
MIRROR="${MIRROR:-}"
CONF=/etc/vps-traffic/agent.conf
AGENT=/opt/vps-traffic/agent.sh

say() { printf '%s\n' "$*"; }
die() { printf '升级失败：%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "请用 root 运行"
[ -f "$CONF" ] || die "这台还没装过 Agent（没有 $CONF），请用面板里这台服务器的安装命令"
command -v sha256sum >/dev/null 2>&1 || die "缺少 sha256sum（coreutils）"
if [ -n "$MIRROR" ]; then
  printf '%s' "$MIRROR" | grep -Eq '^https://[A-Za-z0-9.:/_-]+/$' || die "MIRROR 须为 https:// 开头、/ 结尾，例如 https://ghfast.top/"
fi

fetch() {   # 地址 保存到
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' -m 60 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -T 60 -O "$2" "$1"
  else
    die "需要 curl 或 wget"
  fi
}

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
RAW="${MIRROR}https://raw.githubusercontent.com/$REPO"

# 1. 当前固定的版本
fetch "$RAW/main/agent_pin.json" "$T/pin.json" || die "下载 agent_pin.json 失败（连不上 GitHub 可以设置 MIRROR）"
pick() { tr -d '\n' < "$T/pin.json" | sed -n "s/.*\"$1\": *\"\\([0-9a-f]*\\)\".*/\\1/p"; }
C=$(pick commit)
H=$(pick install_sha256)
A=$(pick agent_sha256)
printf '%s' "$C" | grep -Eq '^[0-9a-f]{40}$' || die "agent_pin.json 里没有有效的提交号"
printf '%s' "$H" | grep -Eq '^[0-9a-f]{64}$' || die "agent_pin.json 里没有有效的 install.sh 哈希"
SHORT=$(printf '%s' "$C" | cut -c1-7)

# 2. 已经是最新就不动
if [ -f "$AGENT" ] && [ -n "$A" ] && [ "${FORCE:-0}" != 1 ]; then
  CUR=$(sha256sum "$AGENT" | awk '{print $1}')
  if [ "$CUR" = "$A" ]; then
    say "已经是最新版本（$SHORT），无需升级"
    exit 0
  fi
fi

# 3. 下载固定提交的 install.sh，校验后运行升级
fetch "$RAW/$C/install.sh" "$T/install.sh" || die "下载 install.sh 失败"
GOT=$(sha256sum "$T/install.sh" | awk '{print $1}')
[ "$GOT" = "$H" ] || die "install.sh 的 SHA256 校验失败（期望 $H，实际 $GOT）"
say "install.sh 校验通过（$SHORT），开始升级…"
if [ -n "$MIRROR" ]; then
  sh "$T/install.sh" --ref "$C" --upgrade --mirror "$MIRROR"
else
  sh "$T/install.sh" --ref "$C" --upgrade
fi
