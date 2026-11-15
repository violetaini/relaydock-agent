package handler

// agentUpgradeScript verifies and atomically replaces the currently running executable.
const agentUpgradeScript = `
set -euo pipefail
SELF_BIN="${RELAYDOCK_UPGRADE_SELF:?Running agent executable path is required}"
[ -f "$SELF_BIN" ] && [ -x "$SELF_BIN" ] || { echo "ERROR: Running Agent is not executable: $SELF_BIN" >&2; exit 1; }
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/relaydock-upgrade.XXXXXXXX")"
STAGED_BIN=""
cleanup() { rm -rf -- "$WORK_DIR"; if [ -n "$STAGED_BIN" ]; then rm -f -- "$STAGED_BIN"; fi; }
trap cleanup EXIT
echo "=========================================="
echo "  RelayDock Agent Upgrade"
echo "=========================================="

ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH_NAME="amd64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# 镜像链 — 顺序尝试,任一成功即停。版本在启动脚本前已经固定并比较，避免
# releases/latest 在元数据检查和下载之间变化导致意外降级。GitHub 优先,失败再自动降级到 CDN 代理。
# 注:GitHub Release binary 实际重定向到 objects.githubusercontent.com,该域名只有 A 记录(无 AAAA),
# 纯 v6 机器(如澳门 Debee mo-d.2ha.me)直连 github 会 "network is unreachable" → 会快速失败(近乎即时,
# 非超时)后降级到 ghproxy / gh-proxy(v4+v6 双栈反代)。
MIRRORS=(
    "https://github.com/violetaini/relaydock-agent/releases/download/__AGENT_RELEASE_TAG__/relaydock-agent-linux-${ARCH_NAME}"
    "https://gh-proxy.com/https://github.com/violetaini/relaydock-agent/releases/download/__AGENT_RELEASE_TAG__/relaydock-agent-linux-${ARCH_NAME}"
    "https://mirror.ghproxy.com/https://github.com/violetaini/relaydock-agent/releases/download/__AGENT_RELEASE_TAG__/relaydock-agent-linux-${ARCH_NAME}"
)
# 优先 curl,没有就用 wget;两者都没就按发行版包管理器装一个 — 跟 install.sh 同款逻辑
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    echo "未检测到 curl/wget,尝试自动安装 curl..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y curl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm curl
    elif command -v zypper >/dev/null 2>&1; then
        zypper -n install curl
    else
        echo "ERROR: 无法识别系统包管理器,请手动安装 curl 或 wget" >&2
        exit 1
    fi
fi
# --connect-timeout TCP 握手最长 10s;--max-time 整个传输上限 180s — 镜像偶发卡死时,不加 max-time 会无声 hang。
dl() { # dl <url> <outfile>
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 --max-time 180 -o "$2" "$1"
    else
        wget -q --connect-timeout=10 --read-timeout=180 -O "$2" "$1"
    fi
}
# 二进制与同名 .sig 签名必须来自【同一镜像】,两者都成功才算该镜像可用。
download_ok=0
for url in "${MIRRORS[@]}"; do
    echo "Downloading from $url ..."
    if dl "$url" "$WORK_DIR/agent" && dl "${url}.sig" "$WORK_DIR/agent.sig"; then
        download_ok=1
        break
    fi
    echo "  → 该镜像失败(二进制或签名缺失),尝试下一个..."
done
if [ "$download_ok" != "1" ]; then
    echo "ERROR: 所有镜像均下载失败(二进制或签名不可达)" >&2
    exit 1
fi

chmod +x "$WORK_DIR/agent"
echo "Download complete, binary size: $(du -h "$WORK_DIR/agent" | cut -f1)"

# 签名校验:用【当前正在运行】的 agent 内嵌公钥校验新二进制,通过才替换。
# 私钥离线(GitHub secret / 本地未提交脚本),主控与本仓库都没有 → 主控被攻破也签不出能过校验的二进制。

echo "Verifying signature ..."
if ! "$SELF_BIN" __verify-update "$WORK_DIR/agent" "$WORK_DIR/agent.sig"; then
    echo "ERROR: 升级二进制签名校验失败,已拒绝替换" >&2
    rm -f "$WORK_DIR/agent" "$WORK_DIR/agent.sig"
    exit 1
fi
echo "Signature OK."

# 替换二进制(systemd Restart=always 会在 agent 退出后拉起新版本)。
# 直接 cp 到 /usr/local/bin/relaydock-agent 会触发 "Text file busy",因为正在运行的 relaydock-agent 进程占着该 inode。
# 改成"先 cp 到旁路文件,再原子 mv 覆盖" — Linux rename(2) 不影响正在执行的进程映射的旧 inode,
# 新 inode 接管该路径,旧 inode 直到进程退出才释放。
STAGED_BIN="$(mktemp "$(dirname "$SELF_BIN")/.relaydock-agent.new.XXXXXXXX")"
cp "$WORK_DIR/agent" "$STAGED_BIN"
chmod 0755 "$STAGED_BIN"
mv -f -- "$STAGED_BIN" "$SELF_BIN"
STAGED_BIN=""
rm -f "$WORK_DIR/agent"
echo "Binary replaced; agent will exit and systemd will restart with new version."
`
