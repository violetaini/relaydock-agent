package util

import (
	"os"
	"strings"
)

// IsDocker 探测当前是否在 Docker 容器内。
// 完全复用主控 miaomiaowuX internal/handler/update.go:isDocker 的 3 重检测逻辑。
//
// 用途:agent 在容器内不能调 systemctl(没 systemd)、不能跑 install-nginx.sh /
// install-release.sh(脚本依赖 systemd)。各处 isDocker 早返 + 走 binary 直接控制。
func IsDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if os.Getenv("DOCKER") == "1" {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil && strings.Contains(string(data), "docker") {
		return true
	}
	return false
}

// SupportsAgentUninstallV2 reports whether the Agent can safely hand cleanup
// to a process outside its own lifecycle. In Docker the Agent is PID 1, so
// stopping it terminates the container and kills the callback runner as well.
func SupportsAgentUninstallV2() bool {
	containerEnv := false
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		containerEnv = true
	}
	cgroup, _ := os.ReadFile("/proc/1/cgroup")
	return supportsAgentUninstallV2Environment(os.Getpid(), IsDocker(), containerEnv, string(cgroup))
}

func supportsAgentUninstallV2Environment(pid int, docker, containerEnv bool, cgroup string) bool {
	if pid == 1 || docker || containerEnv {
		return false
	}
	cgroup = strings.ToLower(cgroup)
	for _, marker := range []string{"docker", "containerd", "kubepods", "libpod", "podman"} {
		if strings.Contains(cgroup, marker) {
			return false
		}
	}
	return true
}
