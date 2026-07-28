#!/usr/bin/env bash
# 手动升级 mmw-agent 到 GitHub release(默认 latest,可指定版本如 v0.1.4)。
#
# 适用场景:UI "升级"按钮卡住、agent 进程没换、需要绕过卡死 handler 强制刷新。
#
# 用法:
#   bash upgrade-agent.sh              # 升级到 GitHub latest
#   bash upgrade-agent.sh v0.1.4       # 升级到指定 tag
#
# 兼容:
#   - systemd (Debian/Ubuntu/CentOS 等) — systemctl restart mmw-agent
#   - OpenRC (Alpine LXC 等)            — rc-service mmw-agent restart
#   - 都不在则用 supervise-daemon / 裸 nohup 启动(打印提示由用户接管)
#
# 失败兜底:
#   - 下载失败 → 退出,不动现有 binary
#   - 替换前自动备份到 /usr/local/bin/mmw-agent.bak-<timestamp>,启动失败可手动回滚
#
set -euo pipefail

REPO="violetaini/relaydock-agent"
BIN="/usr/local/bin/mmw-agent"
TARGET="${1:-latest}"

err() { echo "[ERROR] $*" >&2; exit 1; }
log() { echo "[$(date +%H:%M:%S)] $*"; }

# 必须 root(写 /usr/local/bin + 控制服务)
[ "$(id -u)" = 0 ] || err "请用 root 运行"

# 只接受稳定 X.Y.Z 版本。无法确认当前或目标版本时必须拒绝，避免把可用
# agent 替换成较旧版本。
is_stable_version() {
    local candidate="${1#v}"
    case "$candidate" in
        ""|*[^0-9.]*|.*|*.|*..*) return 1 ;;
    esac
    local part1 part2 part3 extra
    IFS='.' read -r part1 part2 part3 extra <<< "$candidate"
    [ -n "$part1" ] && [ -n "$part2" ] && [ -n "$part3" ] && [ -z "${extra:-}" ]
}

# 输出 -1/0/1，分别表示第一个版本小于/等于/大于第二个版本。
compare_stable_versions() {
    local left1 left2 left3 left_extra right1 right2 right3 right_extra
    IFS='.' read -r left1 left2 left3 left_extra <<< "${1#v}"
    IFS='.' read -r right1 right2 right3 right_extra <<< "${2#v}"
    if (( 10#$left1 < 10#$right1 )); then echo -1; return; fi
    if (( 10#$left1 > 10#$right1 )); then echo 1; return; fi
    if (( 10#$left2 < 10#$right2 )); then echo -1; return; fi
    if (( 10#$left2 > 10#$right2 )); then echo 1; return; fi
    if (( 10#$left3 < 10#$right3 )); then echo -1; return; fi
    if (( 10#$left3 > 10#$right3 )); then echo 1; return; fi
    echo 0
}

# 1. 探测架构
ARCH=$(uname -m)
case $ARCH in
    x86_64)        ARCH_NAME="amd64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
    *) err "不支持的架构: $ARCH" ;;
esac
log "架构: $ARCH_NAME"

# 2. 读取当前版本。新版 agent 提供隐藏 __version 子命令；旧版本无法确认时
# fail closed，避免手动脚本成为绕过面板升级保护的入口。
CURRENT_VERSION="$($BIN __version 2>/dev/null || true)"
CURRENT_VERSION="${CURRENT_VERSION#v}"
is_stable_version "$CURRENT_VERSION" || err "无法读取当前 Agent 的稳定版本；为防止降级，拒绝自动替换"
log "当前版本: v$CURRENT_VERSION"

TMP="$(mktemp /tmp/mmw-agent-new.XXXXXX)"
RELEASE_JSON="$(mktemp /tmp/mmw-agent-release.XXXXXX)"
trap 'rm -f "$TMP" "$TMP.sig" "$RELEASE_JSON"' EXIT

# 3. 解析目标版本 path(URL 前缀由镜像链各自接上)。latest 先解析为固定 tag，
# 这样下载时不会因 GitHub latest 指向变化而绕过版本比较。
if [ "$TARGET" = "latest" ]; then
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 --max-time 60 -o "$RELEASE_JSON" "https://api.github.com/repos/${REPO}/releases/latest"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --connect-timeout=10 --read-timeout=60 -O "$RELEASE_JSON" "https://api.github.com/repos/${REPO}/releases/latest"
    else
        err "没有 curl/wget,无法读取 GitHub 最新版本"
    fi
    TAG="$(sed -n 's/^[[:space:]]*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$RELEASE_JSON" | head -n 1)"
    [ -n "$TAG" ] || err "无法解析 GitHub 最新 release tag"
    log "目标: GitHub latest ($TAG)"
else
    # 允许带或不带 v 前缀
    case "$TARGET" in v*) TAG="$TARGET" ;; *) TAG="v$TARGET" ;; esac
    log "目标: $TAG"
fi

TARGET_VERSION="${TAG#v}"
is_stable_version "$TARGET_VERSION" || err "目标版本不是稳定 X.Y.Z release: $TAG"
comparison="$(compare_stable_versions "$TARGET_VERSION" "$CURRENT_VERSION")"
if (( comparison <= 0 )); then
    err "拒绝降级: 目标 v$TARGET_VERSION 不高于当前 v$CURRENT_VERSION"
fi
PATH_SUFFIX="releases/download/v${TARGET_VERSION}/mmw-agent-linux-${ARCH_NAME}"

# 4. 下载到临时位置(--max-time 防止网络卡死无限等)
# 镜像链 — GitHub 优先,失败再自动降级到 CDN 代理。纯 v6 机器直连 github 会"network is unreachable"
# (release binary 重定向到无 AAAA 的 objects.githubusercontent.com),会快速失败后降级到
# ghproxy/gh-proxy(v4+v6 双栈反代)。
MIRRORS=(
    "https://github.com/${REPO}/${PATH_SUFFIX}"
    "https://gh-proxy.com/https://github.com/${REPO}/${PATH_SUFFIX}"
    "https://mirror.ghproxy.com/https://github.com/${REPO}/${PATH_SUFFIX}"
)
download_ok=0
for URL in "${MIRRORS[@]}"; do
    log "下载 $URL ..."
    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL --connect-timeout 10 --max-time 180 -o "$TMP" "$URL"; then
            download_ok=1; break
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q --connect-timeout=10 --read-timeout=180 -O "$TMP" "$URL"; then
            download_ok=1; break
        fi
    else
        err "没有 curl/wget,无法下载"
    fi
    log "  → 该镜像失败,尝试下一个..."
done
[ "$download_ok" = "1" ] || err "所有镜像均下载失败(GitHub + ghproxy + gh-proxy 全部不可达)"
SIZE=$(du -h "$TMP" | cut -f1)
NEW_MD5=$(md5sum "$TMP" | awk '{print $1}')
log "下载完成: $SIZE, md5=$NEW_MD5"

# 4b. 签名校验:下载同名 .sig,用【已装】agent 的内嵌公钥验签(私钥离线,主控/本仓库都没有)。
# 当前版本已通过 __version 门槛,也必须支持 __verify-update；任何缺失、超时或
# 校验错误都 fail closed，不能让手动脚本绕过面板升级入口的签名要求。
SIG="$TMP.sig"
sig_ok=0
for URL in "${MIRRORS[@]}"; do
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 --max-time 60 -o "$SIG" "${URL}.sig" && { sig_ok=1; break; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q --connect-timeout=10 --read-timeout=60 -O "$SIG" "${URL}.sig" && { sig_ok=1; break; }
    fi
done
if [ "$sig_ok" = 1 ] && [ -x "$BIN" ] && command -v timeout >/dev/null 2>&1; then
    log "校验签名..."
    set +e
    VOUT=$(timeout 15 "$BIN" __verify-update "$TMP" "$SIG" 2>&1); VRC=$?
    set -e
    [ "$VRC" = 0 ] || err "签名校验失败或无法完成(rc=$VRC,拒绝升级): $VOUT"
    log "✅ 签名校验通过"
else
    err "未获取到签名、当前 Agent 不可执行或系统缺少 timeout，拒绝升级"
fi

# 5. 与现有 binary 对比;一样就不动
if [ -f "$BIN" ]; then
    OLD_MD5=$(md5sum "$BIN" | awk '{print $1}')
    if [ "$OLD_MD5" = "$NEW_MD5" ]; then
        log "现有 binary 已是该版本 (md5=$NEW_MD5),无需替换"
        exit 0
    fi
    BAK="${BIN}.bak-$(date +%s)"
    cp "$BIN" "$BAK"
    log "已备份: $BAK (md5=$OLD_MD5)"
fi

# 6. 原子替换(避免 "text file busy" — 旧进程占着 inode 不能直接 cp 覆盖)
chmod +x "$TMP"
mv -f "$TMP" "$BIN"
rm -f "$SIG" "$RELEASE_JSON"
trap - EXIT
log "已替换 $BIN"

# 7. 重启服务 — 顺序探测,谁活跃用谁
restarted=0
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 \
   && systemctl list-unit-files mmw-agent.service >/dev/null 2>&1; then
    log "systemd 模式: systemctl restart mmw-agent"
    systemctl restart mmw-agent
    restarted=1
elif command -v rc-service >/dev/null 2>&1 \
     && rc-service --exists mmw-agent 2>/dev/null; then
    log "OpenRC 模式: rc-service mmw-agent restart"
    rc-service mmw-agent restart
    restarted=1
elif pgrep -f "/usr/local/bin/mmw-agent" >/dev/null 2>&1; then
    # 裸 nohup 模式 — kill 老进程,新 binary 需要用户原命令再启
    log "[WARN] 检测到非 systemd/OpenRC 模式 mmw-agent 进程,本脚本不自动重启"
    log "[WARN] 请你手动:pkill -f /usr/local/bin/mmw-agent && nohup /usr/local/bin/mmw-agent -c <config> &"
else
    log "[WARN] 未检测到 mmw-agent 进程或服务,二进制已替换但需要手动启动"
fi

# 8. 验证
sleep 3
if [ $restarted -eq 1 ]; then
    if pgrep -f "/usr/local/bin/mmw-agent" >/dev/null 2>&1; then
        log "✅ 升级完成,agent 正在运行"
    else
        log "[ERROR] agent 进程未起来,查看 journalctl -u mmw-agent / /var/log/mmw-agent.log 排查"
        log "[ERROR] 回滚命令: mv $BAK $BIN && systemctl restart mmw-agent  # 或 rc-service mmw-agent restart"
        exit 1
    fi
fi

log "done"
