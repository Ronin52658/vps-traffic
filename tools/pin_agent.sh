#!/bin/sh
# 维护 Agent 的固定版本（在仓库根目录运行）
#   sh tools/pin_agent.sh hash          agent.sh 改动后：把它的 SHA256 写进 install.sh
#   sh tools/pin_agent.sh pin <提交>     该提交推到 GitHub 后：让面板改用这个提交安装 Agent
#                                       （检查该提交里 install.sh 与 agent.sh 的哈希一致，再写 agent_pin.json）
#   sh tools/pin_agent.sh check         检查 agent_pin.json 指向的提交在 GitHub 上可下载且哈希正确
set -e
cd "$(dirname "$0")/.."
REPO=$(sed -n 's/^REPO="\(.*\)"$/\1/p' install.sh | head -1)

case "$1" in
  hash)
    h=$(sha256sum agent.sh | awk '{print $1}')
    sed -i "s/^AGENT_SHA256=\".*\"$/AGENT_SHA256=\"$h\"/" install.sh
    echo "install.sh 的 AGENT_SHA256 = $h"
    echo "下一步：提交并推送，然后运行 sh tools/pin_agent.sh pin <该提交>"
    ;;
  pin)
    c=$(git rev-parse --verify "${2:?需要提交}^{commit}")
    want=$(git show "$c:install.sh" | sed -n 's/^AGENT_SHA256="\(.*\)"$/\1/p')
    got=$(git show "$c:agent.sh" | sha256sum | awk '{print $1}')
    [ "$want" = "$got" ] || { echo "提交 $c 里 install.sh 记录的 agent.sh 哈希不一致，先运行 hash 再提交"; exit 1; }
    ih=$(git show "$c:install.sh" | sha256sum | awk '{print $1}')
    printf '{\n  "repo": "%s",\n  "commit": "%s",\n  "install_sha256": "%s",\n  "agent_sha256": "%s"\n}\n' "$REPO" "$c" "$ih" "$got" > agent_pin.json
    cat agent_pin.json
    echo "确认 $c 已推送到 GitHub，然后提交 agent_pin.json 并升级面板（sh install_panel.sh）"
    ;;
  check)
    eval "$(python3 -c 'import json;d=json.load(open("agent_pin.json"));print("R=%s C=%s H=%s"%(d["repo"],d["commit"],d["install_sha256"]))')"
    t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
    curl -fsSL -o "$t/install.sh" "https://raw.githubusercontent.com/$R/$C/install.sh"
    curl -fsSL -o "$t/agent.sh" "https://raw.githubusercontent.com/$R/$C/agent.sh"
    echo "$H  $t/install.sh" | sha256sum -c -
    a=$(sed -n 's/^AGENT_SHA256="\(.*\)"$/\1/p' "$t/install.sh")
    echo "$a  $t/agent.sh" | sha256sum -c -
    ;;
  *) sed -n '2,7p' "$0"; exit 1 ;;
esac
