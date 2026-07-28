package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const agentUninstallCallbackPath = "/api/remote/agent/uninstall-complete"

const (
	agentUninstallRunnerTimeout   = "300"
	agentUninstallRunnerKillAfter = "60"
)

var agentUninstallCallbackTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)

const agentUninstallV2CleanupScript = `#!/bin/sh
set -u

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

RUNTIME_DIR=/run
[ -d "$RUNTIME_DIR" ] || RUNTIME_DIR=/var/run
STATE_FILE=${1:-}
RC_TEMP=""
CURL_CONFIG=""
NGINX_STATE_DIR=""
LOCAL_RECOVERY_DIR=""
PRESERVE_NGINX_STATE=0
PRESERVE_LOCAL_RECOVERY=0
PRESERVE_CALLBACK_RECOVERY=0
CALLBACK_URL=""
CALLBACK_TOKEN=""
CLEANUP_ID=""
CALLBACK_READY=0
LOCAL_CLEANUP_MUTATED=0
LOCAL_CLEANUP_COMMITTED=0
BAOTA_BRIDGE_REMOVED=0
FINAL_SUCCESS=false
FINAL_ERROR="cleanup runner failed"

cleanup_runtime() {
    [ -z "$RC_TEMP" ] || rm -f "$RC_TEMP"
    [ -z "$CURL_CONFIG" ] || rm -f "$CURL_CONFIG"
    if [ -n "$NGINX_STATE_DIR" ] && [ "$PRESERVE_NGINX_STATE" != "1" ]; then
        rm -rf "$NGINX_STATE_DIR"
    fi
    if [ -n "$LOCAL_RECOVERY_DIR" ] && [ "$PRESERVE_LOCAL_RECOVERY" != "1" ]; then
        rm -rf "$LOCAL_RECOVERY_DIR"
    fi
    if [ "$PRESERVE_CALLBACK_RECOVERY" != "1" ]; then
        [ -z "$STATE_FILE" ] || rm -f "$STATE_FILE"
        rm -f "$0"
    fi
}

log_cleanup() {
    command -v logger >/dev/null 2>&1 && logger -t arcway-agent-uninstall "$1" || true
}

load_callback_state() {
    [ -n "$STATE_FILE" ] && [ -r "$STATE_FILE" ] || return 1
    [ "$(stat -c '%a:%u' "$STATE_FILE" 2>/dev/null)" = "600:0" ] || return 1
    {
        IFS= read -r STATE_HEADER || return 1
        IFS= read -r CALLBACK_URL || return 1
        IFS= read -r CALLBACK_TOKEN || return 1
        IFS= read -r CLEANUP_ID || return 1
    } < "$STATE_FILE"
    [ "$STATE_HEADER" = "ARCWAY_AGENT_UNINSTALL_V2_STATE" ] || return 1
    [ -n "$CALLBACK_URL" ] && [ -n "$CALLBACK_TOKEN" ] || return 1
    [ "${#CALLBACK_TOKEN}" -ge 43 ] && [ "${#CALLBACK_TOKEN}" -le 128 ] || return 1
    case "$CALLBACK_TOKEN" in *[!A-Za-z0-9_-]*) return 1 ;; esac
    [ "${#CLEANUP_ID}" -eq 32 ] || return 1
    case "$CLEANUP_ID" in *[!0-9a-f]*) return 1 ;; esac
}

# ARCWAY_CALLBACK_SYNC_BEGIN
prepare_completion_callback() {
    CURL_CONFIG="$RUNTIME_DIR/arcway-agent-uninstall-$CLEANUP_ID.curl"
    {
        printf 'url = "%s"\n' "$CALLBACK_URL"
        printf 'request = "POST"\n'
        printf 'header = "Authorization: Bearer %s"\n' "$CALLBACK_TOKEN"
        printf 'header = "Content-Type: application/json"\n'
    } > "$CURL_CONFIG" || return 1
    chmod 0600 "$CURL_CONFIG" || return 1
}

preflight_completion_callback() {
    # An invalid credential must reach the exact callback handler and receive
    # its deliberate 401 response. This verifies DNS, TLS, routing and handler
    # availability without consuming the real one-time callback credential.
    PREFLIGHT_HTTP_CODE=$(curl --silent --show-error --connect-timeout 3 --max-time 10 \
        --output /dev/null --write-out '%{http_code}' --request POST \
        --header 'Authorization: Bearer arcway-uninstall-preflight' \
        --url "$CALLBACK_URL" 2>/dev/null) || return 1
    [ "$PREFLIGHT_HTTP_CODE" = "401" ]
}

send_completion_callback() {
    if [ "$FINAL_SUCCESS" = true ]; then
        CALLBACK_BODY=$(printf '{"success":true,"cleanup_id":"%s"}' "$CLEANUP_ID")
        # A committed local uninstall cannot be rolled back merely because its
        # completion proof crosses a transient network outage. Spend most of
        # the runner budget retrying it before retaining manual recovery state.
        CALLBACK_MAX_ATTEMPTS=12
    else
        CALLBACK_BODY=$(printf '{"success":false,"cleanup_id":"%s","error":"%s"}' "$CLEANUP_ID" "$FINAL_ERROR")
        CALLBACK_MAX_ATTEMPTS=4
    fi

    CALLBACK_ATTEMPT=0
    while [ "$CALLBACK_ATTEMPT" -lt "$CALLBACK_MAX_ATTEMPTS" ]; do
        CALLBACK_HTTP_CODE=$(curl --silent --show-error --connect-timeout 3 --max-time 10 \
            --output /dev/null --write-out '%{http_code}' \
            --config "$CURL_CONFIG" --data-binary "$CALLBACK_BODY" 2>/dev/null) || CALLBACK_HTTP_CODE="000"
        case "$CALLBACK_HTTP_CODE" in
            2??) return 0 ;;
            # A lost 2xx response is retried with the one-time credential. The
            # panel then returns 409 because the durable callback was consumed;
            # that is positive acknowledgement, not an uninstall failure.
            409) return 0 ;;
        esac
        CALLBACK_ATTEMPT=$((CALLBACK_ATTEMPT + 1))
        [ "$CALLBACK_ATTEMPT" -ge "$CALLBACK_MAX_ATTEMPTS" ] || sleep 3
    done
    return 1
}
# ARCWAY_CALLBACK_SYNC_END

finish_runner() {
    RUNNER_STATUS=$?
    trap - EXIT
    trap '' HUP INT TERM
    if [ "$LOCAL_CLEANUP_COMMITTED" != "1" ] && [ "$LOCAL_CLEANUP_MUTATED" = "1" ] && \
        command -v restore_local_cleanup >/dev/null 2>&1; then
        if ! restore_local_cleanup; then
            PRESERVE_LOCAL_RECOVERY=1
            PRESERVE_NGINX_STATE=1
            FINAL_SUCCESS=false
            FINAL_ERROR="${FINAL_ERROR}; automatic Agent recovery failed"
            log_cleanup "automatic Agent recovery failed; retained recovery files at $LOCAL_RECOVERY_DIR"
            RUNNER_STATUS=1
        fi
    fi
    if [ "$CALLBACK_READY" -eq 1 ]; then
        if ! send_completion_callback; then
            if [ "$LOCAL_CLEANUP_COMMITTED" = "1" ] && [ "$FINAL_SUCCESS" = true ]; then
                # Local deletion is already complete and verified. Preserve the
                # root-only state and idempotent runner so an operator can retry
                # the state sync without reinstalling an Agent that was removed.
                PRESERVE_CALLBACK_RECOVERY=1
                log_cleanup "local cleanup committed but completion callback failed; retry with: /bin/sh $0 $STATE_FILE"
                RUNNER_STATUS=0
            else
                log_cleanup "completion callback failed before local cleanup committed"
                RUNNER_STATUS=1
            fi
        fi
    fi
    cleanup_runtime
    exit "$RUNNER_STATUS"
}

if ! load_callback_state; then
    cleanup_runtime
    exit 1
fi
CALLBACK_READY=1
trap finish_runner EXIT
trap 'FINAL_SUCCESS=false; FINAL_ERROR="cleanup interrupted"; exit 130' HUP INT TERM

# The API response must leave the Agent before this runner stops its parent.
sleep 2

if ! prepare_completion_callback; then
    FINAL_ERROR="could not prepare completion callback"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi
if ! preflight_completion_callback; then
    FINAL_ERROR="completion callback preflight failed"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi

exec 9>"$RUNTIME_DIR/arcway-agent-uninstall.lock"
if ! flock -w 30 9; then
    FINAL_ERROR="cleanup lock timed out"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi

# Keep the Agent's ExecStartPre bridge from recreating its loaders while the
# uninstall runner removes them and stops the Agent service.
exec 8>"$RUNTIME_DIR/arcway-nginx-bridge.lock"
chmod 0600 "$RUNTIME_DIR/arcway-nginx-bridge.lock"
if ! flock -w 30 8; then
    FINAL_ERROR="Nginx bridge cleanup lock timed out"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi

# ARCWAY_BAOTA_BRIDGE_CLEANUP_BEGIN
BAOTA_NGINX_PREFIX=/www/server/nginx
BAOTA_NGINX_BIN="$BAOTA_NGINX_PREFIX/sbin/nginx"
BAOTA_NGINX_CONF="$BAOTA_NGINX_PREFIX/conf/nginx.conf"
BAOTA_HTTP_LOADER=/www/server/panel/vhost/nginx/zz_arcway_loader.conf
BAOTA_STREAM_LOADER=/www/server/panel/vhost/nginx/tcp/zz_arcway_loader.conf
ARCWAY_LOADER_MARKER='# Managed by Arcway. BaoTa loads this file inside the matching Nginx context.'
BAOTA_NGINX_WAS_RUNNING=0

backup_arcway_loader() {
    LOADER_PATH="$1"
    LOADER_NAME="$2"
    if [ ! -e "$LOADER_PATH" ] && [ ! -L "$LOADER_PATH" ]; then
        return 0
    fi
    if [ -L "$LOADER_PATH" ] || [ ! -f "$LOADER_PATH" ]; then
        echo "ERROR: reserved Arcway loader path is not a regular file: $LOADER_PATH" >&2
        return 1
    fi
    LOADER_FIRST_LINE=$(sed -n '1p' "$LOADER_PATH" 2>/dev/null || true)
    if [ "$LOADER_FIRST_LINE" != "$ARCWAY_LOADER_MARKER" ]; then
        echo "ERROR: refusing to remove a non-Arcway file at reserved loader path: $LOADER_PATH" >&2
        return 1
    fi
    cp -a "$LOADER_PATH" "$NGINX_STATE_DIR/$LOADER_NAME" || return 1
    : > "$NGINX_STATE_DIR/$LOADER_NAME.present" || return 1
}

restore_arcway_loader() {
    LOADER_PATH="$1"
    LOADER_NAME="$2"
    rm -f "$LOADER_PATH" || return 1
    if [ -f "$NGINX_STATE_DIR/$LOADER_NAME.present" ]; then
        cp -a "$NGINX_STATE_DIR/$LOADER_NAME" "$LOADER_PATH" || return 1
    fi
}

baota_nginx_is_running() {
    BAOTA_NGINX_REAL=$(readlink -f "$BAOTA_NGINX_BIN" 2>/dev/null || true)
    for BAOTA_PROCESS_DIR in /proc/[0-9]*; do
        [ -r "$BAOTA_PROCESS_DIR/cmdline" ] || continue
        BAOTA_PROCESS_COMMAND=$(tr '\000' ' ' < "$BAOTA_PROCESS_DIR/cmdline" 2>/dev/null || true)
        case "$BAOTA_PROCESS_COMMAND" in
            *"nginx: master process "*) ;;
            *) continue ;;
        esac
        case "$BAOTA_PROCESS_COMMAND" in *"$BAOTA_NGINX_BIN"*) return 0 ;; esac
        BAOTA_PROCESS_EXE=$(readlink -f "$BAOTA_PROCESS_DIR/exe" 2>/dev/null || true)
        if [ -n "$BAOTA_NGINX_REAL" ] && [ "$BAOTA_PROCESS_EXE" = "$BAOTA_NGINX_REAL" ]; then
            return 0
        fi
    done
    return 1
}

validate_baota_nginx() {
    "$BAOTA_NGINX_BIN" -p "$BAOTA_NGINX_PREFIX/" -c "$BAOTA_NGINX_CONF" -t >/dev/null 2>&1
}

reload_baota_nginx() {
    "$BAOTA_NGINX_BIN" -p "$BAOTA_NGINX_PREFIX/" -c "$BAOTA_NGINX_CONF" -s reload >/dev/null 2>&1
}

restore_baota_bridge() {
    BAOTA_RESTORE_OK=1
    restore_arcway_loader "$BAOTA_HTTP_LOADER" http || BAOTA_RESTORE_OK=0
    restore_arcway_loader "$BAOTA_STREAM_LOADER" stream || BAOTA_RESTORE_OK=0
    if [ "$BAOTA_RESTORE_OK" = "1" ]; then
        validate_baota_nginx || BAOTA_RESTORE_OK=0
    fi
    if [ "$BAOTA_RESTORE_OK" = "1" ] && [ "$BAOTA_NGINX_WAS_RUNNING" = "1" ]; then
        reload_baota_nginx || BAOTA_RESTORE_OK=0
    fi
    [ "$BAOTA_RESTORE_OK" = "1" ]
}

fail_baota_bridge_cleanup() {
    BAOTA_FAILURE_MESSAGE="$1"
    echo "ERROR: $BAOTA_FAILURE_MESSAGE" >&2
    if ! restore_baota_bridge; then
        PRESERVE_NGINX_STATE=1
        echo "ERROR: failed to restore the previous BaoTa Nginx loader state" >&2
        echo "ERROR: loader recovery files retained at $NGINX_STATE_DIR" >&2
    fi
    return 1
}

cleanup_baota_bridge() {
    BAOTA_LOADER_PRESENT=0
    for BAOTA_LOADER_PATH in "$BAOTA_HTTP_LOADER" "$BAOTA_STREAM_LOADER"; do
        if [ -e "$BAOTA_LOADER_PATH" ] || [ -L "$BAOTA_LOADER_PATH" ]; then
            BAOTA_LOADER_PRESENT=1
        fi
    done
    [ "$BAOTA_LOADER_PRESENT" = "1" ] || return 0

    if [ ! -x "$BAOTA_NGINX_BIN" ] || [ ! -r "$BAOTA_NGINX_CONF" ]; then
        echo "ERROR: cannot safely remove Arcway loaders from an incomplete BaoTa Nginx installation" >&2
        return 1
    fi
    NGINX_STATE_DIR=$(mktemp -d "$RUNTIME_DIR/arcway-nginx-uninstall.XXXXXX") || return 1
    chmod 0700 "$NGINX_STATE_DIR" || return 1
    backup_arcway_loader "$BAOTA_HTTP_LOADER" http || return 1
    backup_arcway_loader "$BAOTA_STREAM_LOADER" stream || return 1

    if ! validate_baota_nginx; then
        echo "ERROR: BaoTa Nginx configuration was invalid before Arcway loader cleanup" >&2
        return 1
    fi
    if baota_nginx_is_running; then
        BAOTA_NGINX_WAS_RUNNING=1
    fi

    if ! rm -f "$BAOTA_HTTP_LOADER" "$BAOTA_STREAM_LOADER"; then
        fail_baota_bridge_cleanup "could not remove the Arcway BaoTa Nginx loaders"
        return 1
    fi
    if ! validate_baota_nginx; then
        fail_baota_bridge_cleanup "BaoTa Nginx rejected its configuration after Arcway loader removal"
        return 1
    fi
    if [ "$BAOTA_NGINX_WAS_RUNNING" = "1" ] && ! reload_baota_nginx; then
        fail_baota_bridge_cleanup "BaoTa Nginx reload failed after Arcway loader removal"
        return 1
    fi

    # Keep the tiny loader backup until the entire Agent cleanup commits. A
    # later pre-commit failure can then restore Nginx before restarting Agent.
    BAOTA_BRIDGE_REMOVED=1
    return 0
}
# ARCWAY_BAOTA_BRIDGE_CLEANUP_END

# ARCWAY_LOCAL_RECOVERY_BEGIN
backup_local_recovery_path() {
    RECOVERY_PATH="$1"
    RECOVERY_NAME="$2"
    if [ ! -e "$RECOVERY_PATH" ] && [ ! -L "$RECOVERY_PATH" ]; then
        return 0
    fi
    if [ -d "$RECOVERY_PATH" ] && [ ! -L "$RECOVERY_PATH" ]; then
        echo "ERROR: expected an Arcway file but found a directory: $RECOVERY_PATH" >&2
        return 1
    fi
    cp -a "$RECOVERY_PATH" "$LOCAL_RECOVERY_DIR/$RECOVERY_NAME" || return 1
    : > "$LOCAL_RECOVERY_DIR/$RECOVERY_NAME.present" || return 1
}

restore_local_recovery_path() {
    RECOVERY_PATH="$1"
    RECOVERY_NAME="$2"
    [ -f "$LOCAL_RECOVERY_DIR/$RECOVERY_NAME.present" ] || return 0
    if [ -e "$RECOVERY_PATH" ] && [ ! -L "$RECOVERY_PATH" ] && [ -d "$RECOVERY_PATH" ]; then
        echo "ERROR: refusing to replace a directory at Arcway recovery path: $RECOVERY_PATH" >&2
        return 1
    fi
    rm -f "$RECOVERY_PATH" || return 1
    mkdir -p "$(dirname "$RECOVERY_PATH")" || return 1
    cp -a "$LOCAL_RECOVERY_DIR/$RECOVERY_NAME" "$RECOVERY_PATH" || return 1
}

for_each_local_recovery_path() {
    RECOVERY_ACTION="$1"
    "$RECOVERY_ACTION" /usr/local/bin/mmw-agent mmw-agent || return 1
    "$RECOVERY_ACTION" /usr/local/bin/.mmw-agent.new mmw-agent-new || return 1
    "$RECOVERY_ACTION" /usr/local/bin/arcway-expiry-guard expiry-guard || return 1
    "$RECOVERY_ACTION" /usr/local/bin/.arcway-expiry-guard.new expiry-guard-new || return 1
    "$RECOVERY_ACTION" /etc/mmw-agent/config.yaml agent-config || return 1
    "$RECOVERY_ACTION" /etc/arcway-expiry-guard.env expiry-guard-env || return 1
    "$RECOVERY_ACTION" /etc/arcway-port-firewall.env firewall-env || return 1
    "$RECOVERY_ACTION" /usr/local/sbin/arcway-agent-firewall firewall-helper || return 1
    "$RECOVERY_ACTION" /usr/local/sbin/arcway-nginx-bridge nginx-helper || return 1
    "$RECOVERY_ACTION" /etc/systemd/system/mmw-agent.service systemd-agent || return 1
    "$RECOVERY_ACTION" /etc/systemd/system/arcway-expiry-guard.service systemd-guard || return 1
    "$RECOVERY_ACTION" /etc/init.d/mmw-agent openrc-agent || return 1
    "$RECOVERY_ACTION" /etc/init.d/arcway-expiry-guard openrc-guard || return 1
    "$RECOVERY_ACTION" /usr/local/bin/mmw-agent-supervisor.sh supervisor-agent || return 1
    "$RECOVERY_ACTION" /usr/local/bin/arcway-expiry-guard-supervisor.sh supervisor-guard || return 1
    "$RECOVERY_ACTION" /etc/rc.local rc-local || return 1
}

stage_local_recovery() {
    RECOVERY_PARENT=/var/tmp
    [ -d "$RECOVERY_PARENT" ] && [ -w "$RECOVERY_PARENT" ] || RECOVERY_PARENT="$RUNTIME_DIR"
    LOCAL_RECOVERY_DIR=$(mktemp -d "$RECOVERY_PARENT/arcway-agent-uninstall-recovery.$CLEANUP_ID.XXXXXX") || return 1
    chmod 0700 "$LOCAL_RECOVERY_DIR" || return 1
    for_each_local_recovery_path backup_local_recovery_path
}

restart_recovered_agent() {
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || return 1
        if [ -f "$LOCAL_RECOVERY_DIR/systemd-agent.present" ]; then
            systemctl enable mmw-agent.service >/dev/null 2>&1 || return 1
            systemctl restart mmw-agent.service >/dev/null 2>&1 || return 1
        fi
        if [ -f "$LOCAL_RECOVERY_DIR/systemd-guard.present" ]; then
            systemctl enable arcway-expiry-guard.service >/dev/null 2>&1 || return 1
            systemctl restart arcway-expiry-guard.service >/dev/null 2>&1 || return 1
        fi
    elif command -v rc-service >/dev/null 2>&1; then
        if [ -f "$LOCAL_RECOVERY_DIR/openrc-agent.present" ]; then
            command -v rc-update >/dev/null 2>&1 && rc-update add mmw-agent default >/dev/null 2>&1 || true
            rc-service mmw-agent restart >/dev/null 2>&1 || return 1
        fi
        if [ -f "$LOCAL_RECOVERY_DIR/openrc-guard.present" ]; then
            command -v rc-update >/dev/null 2>&1 && rc-update add arcway-expiry-guard default >/dev/null 2>&1 || true
            rc-service arcway-expiry-guard restart >/dev/null 2>&1 || return 1
        fi
    elif [ -x /usr/local/bin/mmw-agent-supervisor.sh ]; then
        nohup /usr/local/bin/mmw-agent-supervisor.sh >/dev/null 2>&1 &
        if [ -x /usr/local/bin/arcway-expiry-guard-supervisor.sh ]; then
            nohup /usr/local/bin/arcway-expiry-guard-supervisor.sh >/dev/null 2>&1 &
        fi
    else
        return 1
    fi

    RECOVERY_WAIT=0
    while [ "$RECOVERY_WAIT" -lt 10 ]; do
        if pgrep -f '^/usr/local/bin/mmw-agent([[:space:]]|$)' >/dev/null 2>&1 || \
            pgrep -f '/usr/local/bin/mmw-agent-supervisor[.]sh' >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        RECOVERY_WAIT=$((RECOVERY_WAIT + 1))
    done
    return 1
}

restore_local_cleanup() {
    RESTORE_OK=1
    if [ -n "$LOCAL_RECOVERY_DIR" ] && [ -d "$LOCAL_RECOVERY_DIR" ]; then
        for_each_local_recovery_path restore_local_recovery_path || RESTORE_OK=0
    else
        RESTORE_OK=0
    fi
    if [ "$BAOTA_BRIDGE_REMOVED" = "1" ]; then
        restore_baota_bridge || RESTORE_OK=0
    fi
    if [ "$RESTORE_OK" = "1" ]; then
        restart_recovered_agent || RESTORE_OK=0
    fi
    if [ "$RESTORE_OK" = "1" ]; then
        BAOTA_BRIDGE_REMOVED=0
        LOCAL_CLEANUP_MUTATED=0
        log_cleanup "pre-commit cleanup failed; Agent runtime restored for retry"
    fi
    [ "$RESTORE_OK" = "1" ]
}
# ARCWAY_LOCAL_RECOVERY_END

if ! stage_local_recovery; then
    FINAL_ERROR="could not stage Agent recovery files"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi

LOCAL_CLEANUP_MUTATED=1

if ! cleanup_baota_bridge; then
    FINAL_ERROR="BaoTa Nginx bridge cleanup failed"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi

AGENT_PORT=""
GUARD_PORT=""
PANEL_IPS=""
if [ -r /etc/arcway-port-firewall.env ]; then
    AGENT_PORT=$(sed -n 's/^ARCWAY_AGENT_PORT=//p' /etc/arcway-port-firewall.env | head -n 1)
    GUARD_PORT=$(sed -n 's/^ARCWAY_GUARD_PORT=//p' /etc/arcway-port-firewall.env | head -n 1)
    PANEL_IPS=$(sed -n "s/^ARCWAY_PANEL_IPS='\(.*\)'$/\1/p" /etc/arcway-port-firewall.env | head -n 1)
fi

cleanup_rc_local() {
    [ -f /etc/rc.local ] || return 0
    RC_TEMP=$(mktemp "$RUNTIME_DIR/arcway-rc-local.XXXXXX") || return 1
    if ! awk '
        /arcway-agent-firewall|arcway-nginx-bridge|mmw-agent-supervisor[.]sh|arcway-expiry-guard-supervisor[.]sh/ { next }
        { print }
    ' /etc/rc.local > "$RC_TEMP"; then
        return 1
    fi
    cat "$RC_TEMP" > /etc/rc.local || return 1
    rm -f "$RC_TEMP"
    RC_TEMP=""
}

# Disable every boot path before stopping the process that received the request.
# This is a checked pre-commit operation: accepting a partial rc.local write
# and discovering it only after deleting Agent would strand the panel record.
if ! cleanup_rc_local; then
    FINAL_ERROR="could not remove Arcway lines from rc.local"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi

# The HTTP handler checks this before dispatch, but the detached runner starts
# later. Re-check immediately before stopping Agent so a concurrent WARP install
# cannot be discovered only after the executable has already been removed.
if [ -e /etc/mmw-agent/warp.json ] || [ -L /etc/mmw-agent/warp.json ]; then
    FINAL_ERROR="WARP appeared while Agent uninstall was being dispatched"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable arcway-expiry-guard.service mmw-agent.service >/dev/null 2>&1 || true
    systemctl stop arcway-expiry-guard.service >/dev/null 2>&1 || true
    systemctl stop mmw-agent.service >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null 2>&1; then
    command -v rc-update >/dev/null 2>&1 && rc-update del arcway-expiry-guard default >/dev/null 2>&1 || true
    command -v rc-update >/dev/null 2>&1 && rc-update del mmw-agent default >/dev/null 2>&1 || true
    rc-service arcway-expiry-guard stop >/dev/null 2>&1 || true
    rc-service mmw-agent stop >/dev/null 2>&1 || true
fi

# These exact installed paths are Arcway-owned. Killing them is safe after all
# boot supervisors have been disabled, and does not target Xray or Nginx.
stop_owned_process() {
    PROCESS_PATTERN="$1"
    pkill -f "$PROCESS_PATTERN" >/dev/null 2>&1 || true
    PROCESS_WAIT=0
    while [ "$PROCESS_WAIT" -lt 10 ]; do
        pgrep -f "$PROCESS_PATTERN" >/dev/null 2>&1 || return 0
        sleep 1
        PROCESS_WAIT=$((PROCESS_WAIT + 1))
    done
    pkill -9 -f "$PROCESS_PATTERN" >/dev/null 2>&1 || true
    sleep 1
    if pgrep -f "$PROCESS_PATTERN" >/dev/null 2>&1; then
        log_cleanup "could not stop Arcway process matching $PROCESS_PATTERN"
        return 1
    fi
}

PROCESS_STOP_FAILED=0
stop_owned_process '/usr/local/bin/arcway-expiry-guard-supervisor[.]sh' || PROCESS_STOP_FAILED=1
stop_owned_process '/usr/local/bin/mmw-agent-supervisor[.]sh' || PROCESS_STOP_FAILED=1
stop_owned_process '^/usr/local/bin/arcway-expiry-guard([[:space:]]|$)' || PROCESS_STOP_FAILED=1
stop_owned_process '^/usr/local/bin/mmw-agent([[:space:]]|$)' || PROCESS_STOP_FAILED=1
if [ "$PROCESS_STOP_FAILED" -ne 0 ]; then
    FINAL_ERROR="Arcway process did not stop"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi

cleanup_owned_filter_chain() {
    FILTER_TOOL="$1"
    FILTER_CHAIN="$2"
    command -v "$FILTER_TOOL" >/dev/null 2>&1 || return 0
    "$FILTER_TOOL" -w 5 -t filter -S "$FILTER_CHAIN" >/dev/null 2>&1 || return 0
    if "$FILTER_TOOL" -w 5 -t filter -S "$FILTER_CHAIN" | awk '
        $1 == "-A" && index($0, "--comment arcway-managed") == 0 { foreign=1 }
        END { exit foreign ? 0 : 1 }
    '; then
        log_cleanup "retained non-Arcway rules in $FILTER_TOOL $FILTER_CHAIN"
        return 0
    fi
    while "$FILTER_TOOL" -w 5 -t filter -C INPUT -m comment --comment arcway-managed -j "$FILTER_CHAIN" >/dev/null 2>&1; do
        "$FILTER_TOOL" -w 5 -t filter -D INPUT -m comment --comment arcway-managed -j "$FILTER_CHAIN" >/dev/null 2>&1 || break
    done
    while "$FILTER_TOOL" -w 5 -t filter -C INPUT -j "$FILTER_CHAIN" >/dev/null 2>&1; do
        "$FILTER_TOOL" -w 5 -t filter -D INPUT -j "$FILTER_CHAIN" >/dev/null 2>&1 || break
    done
    "$FILTER_TOOL" -w 5 -t filter -F "$FILTER_CHAIN" >/dev/null 2>&1 || true
    "$FILTER_TOOL" -w 5 -t filter -X "$FILTER_CHAIN" >/dev/null 2>&1 || true
}

cleanup_legacy_filter_chain() {
    FILTER_TOOL="$1"
    command -v "$FILTER_TOOL" >/dev/null 2>&1 || return 0
    "$FILTER_TOOL" -w 5 -t filter -S ARCWAY_PORTS >/dev/null 2>&1 || return 0
    while "$FILTER_TOOL" -w 5 -t filter -C INPUT -j ARCWAY_PORTS >/dev/null 2>&1; do
        "$FILTER_TOOL" -w 5 -t filter -D INPUT -j ARCWAY_PORTS >/dev/null 2>&1 || break
    done
    "$FILTER_TOOL" -w 5 -t filter -F ARCWAY_PORTS >/dev/null 2>&1 || true
    "$FILTER_TOOL" -w 5 -t filter -X ARCWAY_PORTS >/dev/null 2>&1 || true
}

if command -v nft >/dev/null 2>&1 && nft list table inet arcway >/dev/null 2>&1; then
    nft delete table inet arcway >/dev/null 2>&1 || log_cleanup "could not remove nft table inet arcway"
fi
for FILTER_TOOL in iptables ip6tables; do
    cleanup_owned_filter_chain "$FILTER_TOOL" ARCWAY_PANEL_IN
    cleanup_legacy_filter_chain "$FILTER_TOOL"
done

# Current installers tag UFW rules. Exact legacy tuples are removed only when
# the old root-owned environment file identifies both source and port.
if command -v ufw >/dev/null 2>&1; then
    UFW_RULE_NUMBERS=$(LC_ALL=C ufw status numbered 2>/dev/null | awk '
        /arcway-managed/ && match($0, /^\[[[:space:]]*[0-9]+\]/) {
            number=substr($0, RSTART, RLENGTH)
            gsub(/[^0-9]/, "", number)
            print number
        }
    ' | sort -rn -u)
    for UFW_RULE_NUMBER in $UFW_RULE_NUMBERS; do
        ufw --force delete "$UFW_RULE_NUMBER" >/dev/null 2>&1 || true
    done
    for PANEL_IP in $PANEL_IPS; do
        for MANAGEMENT_PORT in $AGENT_PORT $GUARD_PORT; do
            case "$MANAGEMENT_PORT" in ''|*[!0-9]*) continue ;; esac
            ufw --force delete allow proto tcp from "$PANEL_IP" to any port "$MANAGEMENT_PORT" >/dev/null 2>&1 || true
        done
    done
fi

verify_precommit_cleanup() {
    PRECOMMIT_VERIFY_FAILED=0
    for PROCESS_PATTERN in \
        '/usr/local/bin/arcway-expiry-guard-supervisor[.]sh' \
        '/usr/local/bin/mmw-agent-supervisor[.]sh' \
        '^/usr/local/bin/arcway-expiry-guard([[:space:]]|$)' \
        '^/usr/local/bin/mmw-agent([[:space:]]|$)'; do
        pgrep -f "$PROCESS_PATTERN" >/dev/null 2>&1 && PRECOMMIT_VERIFY_FAILED=1
    done

    if [ -d /run/systemd/system ]; then
        systemctl is-active --quiet mmw-agent.service >/dev/null 2>&1 && PRECOMMIT_VERIFY_FAILED=1
        systemctl is-active --quiet arcway-expiry-guard.service >/dev/null 2>&1 && PRECOMMIT_VERIFY_FAILED=1
        systemctl is-enabled --quiet mmw-agent.service >/dev/null 2>&1 && PRECOMMIT_VERIFY_FAILED=1
        systemctl is-enabled --quiet arcway-expiry-guard.service >/dev/null 2>&1 && PRECOMMIT_VERIFY_FAILED=1
    fi
    for BOOT_LINK in \
        /etc/systemd/system/*target.wants/mmw-agent.service \
        /etc/systemd/system/*target.wants/arcway-expiry-guard.service \
        /etc/runlevels/*/mmw-agent \
        /etc/runlevels/*/arcway-expiry-guard; do
        [ ! -e "$BOOT_LINK" ] && [ ! -L "$BOOT_LINK" ] || PRECOMMIT_VERIFY_FAILED=1
    done
    if [ -f /etc/rc.local ] && grep -Eq \
        'arcway-agent-firewall|arcway-nginx-bridge|mmw-agent-supervisor[.]sh|arcway-expiry-guard-supervisor[.]sh' \
        /etc/rc.local; then
        PRECOMMIT_VERIFY_FAILED=1
    fi

    if command -v nft >/dev/null 2>&1 && nft list table inet arcway >/dev/null 2>&1; then
        PRECOMMIT_VERIFY_FAILED=1
    fi
    for FILTER_TOOL in iptables ip6tables; do
        command -v "$FILTER_TOOL" >/dev/null 2>&1 || continue
        "$FILTER_TOOL" -w 5 -t filter -S ARCWAY_PANEL_IN 2>/dev/null | grep -q 'arcway-managed' && PRECOMMIT_VERIFY_FAILED=1
        "$FILTER_TOOL" -w 5 -t filter -C INPUT -j ARCWAY_PANEL_IN >/dev/null 2>&1 && PRECOMMIT_VERIFY_FAILED=1
        "$FILTER_TOOL" -w 5 -t filter -S ARCWAY_PORTS >/dev/null 2>&1 && PRECOMMIT_VERIFY_FAILED=1
        "$FILTER_TOOL" -w 5 -t filter -C INPUT -j ARCWAY_PORTS >/dev/null 2>&1 && PRECOMMIT_VERIFY_FAILED=1
    done
    if command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -q 'arcway-managed'; then
        PRECOMMIT_VERIFY_FAILED=1
    fi

    [ ! -e /etc/mmw-agent/warp.json ] && [ ! -L /etc/mmw-agent/warp.json ] || PRECOMMIT_VERIFY_FAILED=1
    [ ! -e /www/server/panel/vhost/nginx/zz_arcway_loader.conf ] && \
        [ ! -L /www/server/panel/vhost/nginx/zz_arcway_loader.conf ] || PRECOMMIT_VERIFY_FAILED=1
    [ ! -e /www/server/panel/vhost/nginx/tcp/zz_arcway_loader.conf ] && \
        [ ! -L /www/server/panel/vhost/nginx/tcp/zz_arcway_loader.conf ] || PRECOMMIT_VERIFY_FAILED=1
    [ "$PRECOMMIT_VERIFY_FAILED" -eq 0 ]
}

if ! verify_precommit_cleanup; then
    FINAL_ERROR="pre-commit Agent cleanup verification failed"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi

if ! rm -f \
    /usr/local/bin/mmw-agent \
    /usr/local/bin/.mmw-agent.new \
    /usr/local/bin/arcway-expiry-guard \
    /usr/local/bin/.arcway-expiry-guard.new \
    /etc/mmw-agent/config.yaml \
    /etc/arcway-expiry-guard.env \
    /etc/arcway-port-firewall.env \
    /usr/local/sbin/arcway-agent-firewall \
    /usr/local/sbin/arcway-nginx-bridge \
    /etc/systemd/system/mmw-agent.service \
    /etc/systemd/system/arcway-expiry-guard.service \
    /etc/init.d/mmw-agent \
    /etc/init.d/arcway-expiry-guard \
    /usr/local/bin/mmw-agent-supervisor.sh \
    /usr/local/bin/arcway-expiry-guard-supervisor.sh; then
    FINAL_ERROR="could not remove one or more Agent files"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi
if ! rm -f /etc/systemd/system/*target.wants/mmw-agent.service \
    /etc/systemd/system/*target.wants/arcway-expiry-guard.service \
    /etc/runlevels/*/mmw-agent /etc/runlevels/*/arcway-expiry-guard; then
    FINAL_ERROR="could not remove Agent boot links"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi
if ! rm -rf /var/lib/mmw-agent /var/lib/arcway-expiry-guard /var/log/mmw-agent; then
    FINAL_ERROR="could not remove Agent state directories"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi
rmdir /etc/mmw-agent >/dev/null 2>&1 || true
exec 8>&-
rm -f "$RUNTIME_DIR/arcway-agent-firewall.lock" "$RUNTIME_DIR/arcway-nginx-bridge.lock"
rm -rf "$RUNTIME_DIR"/arcway-agent-firewall.* "$RUNTIME_DIR"/arcway-nginx-bridge.*

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed mmw-agent.service arcway-expiry-guard.service >/dev/null 2>&1 || true
fi

verify_removed_path() {
    [ ! -e "$1" ] && [ ! -L "$1" ]
}

verify_cleanup() {
    VERIFY_FAILED=0
    for PROCESS_PATTERN in \
        '/usr/local/bin/arcway-expiry-guard-supervisor[.]sh' \
        '/usr/local/bin/mmw-agent-supervisor[.]sh' \
        '^/usr/local/bin/arcway-expiry-guard([[:space:]]|$)' \
        '^/usr/local/bin/mmw-agent([[:space:]]|$)'; do
        pgrep -f "$PROCESS_PATTERN" >/dev/null 2>&1 && VERIFY_FAILED=1
    done

    if [ -d /run/systemd/system ]; then
        systemctl is-active --quiet mmw-agent.service >/dev/null 2>&1 && VERIFY_FAILED=1
        systemctl is-active --quiet arcway-expiry-guard.service >/dev/null 2>&1 && VERIFY_FAILED=1
        systemctl is-enabled --quiet mmw-agent.service >/dev/null 2>&1 && VERIFY_FAILED=1
        systemctl is-enabled --quiet arcway-expiry-guard.service >/dev/null 2>&1 && VERIFY_FAILED=1
    fi
    for BOOT_LINK in \
        /etc/systemd/system/*target.wants/mmw-agent.service \
        /etc/systemd/system/*target.wants/arcway-expiry-guard.service \
        /etc/runlevels/*/mmw-agent \
        /etc/runlevels/*/arcway-expiry-guard; do
        verify_removed_path "$BOOT_LINK" || VERIFY_FAILED=1
    done
    if [ -f /etc/rc.local ] && grep -Eq \
        'arcway-agent-firewall|arcway-nginx-bridge|mmw-agent-supervisor[.]sh|arcway-expiry-guard-supervisor[.]sh' \
        /etc/rc.local; then
        VERIFY_FAILED=1
    fi

    if command -v nft >/dev/null 2>&1 && nft list table inet arcway >/dev/null 2>&1; then
        VERIFY_FAILED=1
    fi
    for FILTER_TOOL in iptables ip6tables; do
        command -v "$FILTER_TOOL" >/dev/null 2>&1 || continue
        "$FILTER_TOOL" -w 5 -t filter -S ARCWAY_PANEL_IN 2>/dev/null | grep -q 'arcway-managed' && VERIFY_FAILED=1
        "$FILTER_TOOL" -w 5 -t filter -C INPUT -j ARCWAY_PANEL_IN >/dev/null 2>&1 && VERIFY_FAILED=1
        "$FILTER_TOOL" -w 5 -t filter -S ARCWAY_PORTS >/dev/null 2>&1 && VERIFY_FAILED=1
        "$FILTER_TOOL" -w 5 -t filter -C INPUT -j ARCWAY_PORTS >/dev/null 2>&1 && VERIFY_FAILED=1
    done
    if command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -q 'arcway-managed'; then
        VERIFY_FAILED=1
    fi

    # Never delete WARP credentials here. A file appearing after dispatch means
    # a concurrent registration won the race, so completion must fail closed.
    verify_removed_path /etc/mmw-agent/warp.json || VERIFY_FAILED=1

    for OWNED_PATH in \
        /usr/local/bin/mmw-agent \
        /usr/local/bin/.mmw-agent.new \
        /usr/local/bin/arcway-expiry-guard \
        /usr/local/bin/.arcway-expiry-guard.new \
        /etc/mmw-agent/config.yaml \
        /etc/arcway-expiry-guard.env \
        /etc/arcway-port-firewall.env \
        /usr/local/sbin/arcway-agent-firewall \
        /usr/local/sbin/arcway-nginx-bridge \
        /etc/systemd/system/mmw-agent.service \
        /etc/systemd/system/arcway-expiry-guard.service \
        /etc/init.d/mmw-agent \
        /etc/init.d/arcway-expiry-guard \
        /usr/local/bin/mmw-agent-supervisor.sh \
        /usr/local/bin/arcway-expiry-guard-supervisor.sh \
        /www/server/panel/vhost/nginx/zz_arcway_loader.conf \
        /www/server/panel/vhost/nginx/tcp/zz_arcway_loader.conf \
        /var/lib/mmw-agent \
        /var/lib/arcway-expiry-guard \
        /var/log/mmw-agent; do
        verify_removed_path "$OWNED_PATH" || VERIFY_FAILED=1
    done
    for RUNTIME_PATH in "$RUNTIME_DIR"/arcway-agent-firewall.* "$RUNTIME_DIR"/arcway-nginx-bridge.*; do
        verify_removed_path "$RUNTIME_PATH" || VERIFY_FAILED=1
    done
    [ "$VERIFY_FAILED" -eq 0 ]
}

if ! verify_cleanup; then
    FINAL_ERROR="cleanup verification failed"
    log_cleanup "$FINAL_ERROR"
    exit 1
fi

LOCAL_CLEANUP_COMMITTED=1
FINAL_SUCCESS=true
FINAL_ERROR=""
log_cleanup "cleanup completed and verified"
exit 0
`

type agentUninstallLauncher interface {
	Launch(context.Context, string, string, string) error
}

type realAgentUninstallLauncher struct {
	systemdRuntimeDir string
	getEUID           func() int
	lookPath          func(string) (string, error)
	runSystemd        func(context.Context, string, ...string) ([]byte, error)
	startDetached     func(string, []string, *syscall.SysProcAttr) error
}

func (l realAgentUninstallLauncher) Launch(ctx context.Context, scriptPath, statePath, cleanupID string) error {
	systemdRuntimeDir := l.systemdRuntimeDir
	if systemdRuntimeDir == "" {
		systemdRuntimeDir = "/run/systemd/system"
	}
	getEUID := l.getEUID
	if getEUID == nil {
		getEUID = os.Geteuid
	}
	if uid := getEUID(); uid != 0 {
		return fmt.Errorf("Agent uninstall requires root privileges (effective uid %d)", uid)
	}
	lookPath := l.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	requireCommand := func(name string) (string, error) {
		path, err := lookPath(name)
		if err != nil {
			return "", fmt.Errorf("required cleanup command %s is unavailable: %w", name, err)
		}
		return path, nil
	}
	if _, err := requireCommand("/bin/sh"); err != nil {
		return err
	}
	for _, name := range []string{"awk", "cat", "chmod", "cp", "curl", "dirname", "flock", "grep", "head", "mkdir", "mktemp", "pgrep", "pkill", "readlink", "rm", "rmdir", "sed", "sleep", "sort", "stat", "tr"} {
		if _, err := requireCommand(name); err != nil {
			return err
		}
	}
	timeoutPath, err := requireCommand("timeout")
	if err != nil {
		return err
	}
	runnerArgs := []string{
		"-s", "TERM",
		"-k", agentUninstallRunnerKillAfter,
		agentUninstallRunnerTimeout,
		"/bin/sh",
		scriptPath,
		statePath,
	}
	runSystemd := l.runSystemd
	if runSystemd == nil {
		runSystemd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	startDetached := l.startDetached
	if startDetached == nil {
		startDetached = startDetachedAgentUninstall
	}

	if info, err := os.Stat(systemdRuntimeDir); err == nil && info.IsDir() {
		if _, err := requireCommand("systemctl"); err != nil {
			return err
		}
		systemdRun, err := requireCommand("systemd-run")
		if err != nil {
			return err
		}
		unit := "arcway-agent-uninstall-" + cleanupID
		systemdArgs := []string{
			"--property=Type=exec",
			"--unit=" + unit,
			timeoutPath,
		}
		systemdArgs = append(systemdArgs, runnerArgs...)
		output, err := runSystemd(ctx, systemdRun, systemdArgs...)
		if err != nil {
			message := strings.TrimSpace(string(output))
			if message != "" {
				return fmt.Errorf("start independent systemd uninstall unit: %w: %s", err, message)
			}
			return fmt.Errorf("start independent systemd uninstall unit: %w", err)
		}
		return nil
	}

	nohupPath, err := requireCommand("nohup")
	if err != nil {
		return err
	}
	return startDetached(nohupPath, append([]string{timeoutPath}, runnerArgs...), &syscall.SysProcAttr{Setsid: true})
}

func startDetachedAgentUninstall(name string, args []string, sysProcAttr *syscall.SysProcAttr) error {
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open null device: %w", err)
	}
	defer devNull.Close()

	cmd := exec.Command(name, args...)
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.SysProcAttr = sysProcAttr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start detached uninstall runner: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("release detached uninstall runner: %w", err)
	}
	return nil
}

func agentUninstallCleanupID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate cleanup id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func agentUninstallRunDirectory() string {
	if info, err := os.Stat("/run"); err == nil && info.IsDir() {
		return "/run"
	}
	return "/var/run"
}

func stageAgentUninstallScript(runDir, cleanupID string) (string, error) {
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return "", fmt.Errorf("prepare runtime directory: %w", err)
	}
	path := filepath.Join(runDir, "arcway-agent-uninstall-"+cleanupID+".sh")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return "", fmt.Errorf("create cleanup script: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.WriteString(agentUninstallV2CleanupScript); err != nil {
		return "", fmt.Errorf("write cleanup script: %w", err)
	}
	if err := file.Chmod(0700); err != nil {
		return "", fmt.Errorf("set cleanup script permissions: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync cleanup script: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close cleanup script: %w", err)
	}
	remove = false
	return path, nil
}

func stageAgentUninstallState(runDir, callbackURL, callbackToken, cleanupID string) (string, error) {
	path := filepath.Join(runDir, "arcway-agent-uninstall-"+cleanupID+".state")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("create cleanup state: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	state := strings.Join([]string{
		"ARCWAY_AGENT_UNINSTALL_V2_STATE",
		callbackURL,
		callbackToken,
		cleanupID,
		"",
	}, "\n")
	if _, err := file.WriteString(state); err != nil {
		return "", fmt.Errorf("write cleanup state: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		return "", fmt.Errorf("set cleanup state permissions: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync cleanup state: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close cleanup state: %w", err)
	}
	remove = false
	return path, nil
}

type agentUninstallV2Request struct {
	CallbackURL   string `json:"callback_url"`
	CallbackToken string `json:"callback_token"`
}

func validateAgentUninstallCallback(masterURL, callbackURL, callbackToken string) error {
	if masterURL == "" {
		return fmt.Errorf("Agent master URL is not configured")
	}
	master, err := url.Parse(masterURL)
	if err != nil || master.Host == "" || (master.Scheme != "http" && master.Scheme != "https") {
		return fmt.Errorf("Agent master URL is invalid")
	}
	callback, err := url.Parse(callbackURL)
	if err != nil || callback.Host == "" || callback.Opaque != "" {
		return fmt.Errorf("callback_url must be an absolute HTTP URL")
	}
	if callback.Scheme != "http" && callback.Scheme != "https" {
		return fmt.Errorf("callback_url must use http or https")
	}
	if callback.User != nil || callback.RawQuery != "" || callback.ForceQuery || callback.Fragment != "" {
		return fmt.Errorf("callback_url must not contain user info, query, or fragment")
	}
	if callback.Path != agentUninstallCallbackPath || callback.RawPath != "" {
		return fmt.Errorf("callback_url path must be %s", agentUninstallCallbackPath)
	}
	canonicalCallback := (&url.URL{
		Scheme: callback.Scheme,
		Host:   callback.Host,
		Path:   agentUninstallCallbackPath,
	}).String()
	if callbackURL != canonicalCallback {
		return fmt.Errorf("callback_url must use its canonical form")
	}
	if !strings.EqualFold(master.Scheme, callback.Scheme) ||
		!strings.EqualFold(master.Hostname(), callback.Hostname()) ||
		normalizedURLPort(master) != normalizedURLPort(callback) {
		return fmt.Errorf("callback_url must use the current master URL origin")
	}
	if !agentUninstallCallbackTokenPattern.MatchString(callbackToken) {
		return fmt.Errorf("callback_token must be 43-128 base64url characters")
	}
	return nil
}

func normalizedURLPort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return "443"
	}
	return "80"
}

func (h *ManageHandler) agentUninstallWarpStatePath() string {
	workDir := "."
	if h.configPath != "" {
		workDir = filepath.Dir(h.configPath)
	}
	return filepath.Join(workDir, "warp.json")
}

func (h *ManageHandler) supportsAgentUninstallV2() bool {
	return h.agentUninstallV2Supported != nil && h.agentUninstallV2Supported()
}

// HandleAgentUninstallV2 stages a fixed cleanup program and starts it outside
// the Agent service lifecycle. The response verifies dispatch, not completion.
func (h *ManageHandler) HandleAgentUninstallV2(w http.ResponseWriter, r *http.Request) {
	h.handleAgentUninstallV2(w, r, realAgentUninstallLauncher{}, agentUninstallRunDirectory())
}

func (h *ManageHandler) handleAgentUninstallV2(w http.ResponseWriter, r *http.Request, launcher agentUninstallLauncher, runDir string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	isInternalWSRPC := r.Header.Get("X-WS-RPC") == "1" && r.RemoteAddr == "ws-rpc"
	if h.configToken == "" && !isInternalWSRPC {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if !h.authenticate(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if !h.supportsAgentUninstallV2() {
		writeError(w, http.StatusNotImplemented, "Agent self-uninstall is not supported when Agent is PID 1 or runs inside an application container; remove it from the container host")
		return
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	var req agentUninstallV2Request
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid uninstall request: "+err.Error())
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "Uninstall request must contain one JSON object")
		return
	}
	if err := validateAgentUninstallCallback(h.currentMasterURL(), req.CallbackURL, req.CallbackToken); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := os.Lstat(h.agentUninstallWarpStatePath()); err == nil {
		writeError(w, http.StatusConflict, "WARP is still installed; uninstall WARP before removing the Agent")
		return
	} else if !os.IsNotExist(err) {
		writeError(w, http.StatusInternalServerError, "Inspect WARP state: "+err.Error())
		return
	}

	cleanupID, err := agentUninstallCleanupID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	scriptPath, err := stageAgentUninstallScript(runDir, cleanupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	statePath, err := stageAgentUninstallState(runDir, req.CallbackURL, req.CallbackToken, cleanupID)
	if err != nil {
		_ = os.Remove(scriptPath)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	launchCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := launcher.Launch(launchCtx, scriptPath, statePath, cleanupID); err != nil {
		_ = os.Remove(scriptPath)
		_ = os.Remove(statePath)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Printf("[Manage] Agent uninstall v2 runner started (cleanup_id=%s)", cleanupID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":           true,
		"dispatch_verified": true,
		"cleanup_id":        cleanupID,
	})
}
