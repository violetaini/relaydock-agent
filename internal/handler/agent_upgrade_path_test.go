package handler

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAgentUpgradeUsesRunningExecutablePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX filesystem semantics")
	}
	bash, err := exec.LookPath("bash")
	if err != nil && runtime.GOOS == "windows" {
		bash = "C:/Program Files/Git/bin/bash.exe"
		_, err = os.Stat(bash)
	}
	if err != nil {
		t.Skip("bash unavailable")
	}
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "signature-refused"}[fail], func(t *testing.T) {
			root := t.TempDir()
			binDir := filepath.Join(root, "custom install")
			mockDir := filepath.Join(root, "commands")
			os.Mkdir(binDir, 0755)
			os.Mkdir(mockDir, 0755)
			current := filepath.Join(binDir, "agent")
			original := "#!/usr/bin/env bash\n[ \"${VERIFY_FAIL:-0}\" != 1 ] && [ \"$1\" = __verify-update ]\n"
			os.WriteFile(current, []byte(original), 0755)
			curl := "#!/usr/bin/env bash\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=\"$2\"; shift 2;; http*) url=\"$1\"; shift;; *) shift;; esac; done\ncase \"$url\" in *.sig) printf signature >\"$out\";; *) printf new-binary >\"$out\";; esac\n"
			os.WriteFile(filepath.Join(mockDir, "curl"), []byte(curl), 0755)
			script := strings.ReplaceAll(agentUpgradeScript, "__AGENT_RELEASE_TAG__", "v0.4.12")
			cmd := exec.Command(bash, "-c", script)
			env := append(os.Environ(), "PATH="+filepath.ToSlash(mockDir)+string(os.PathListSeparator)+os.Getenv("PATH"), "RELAYDOCK_UPGRADE_SELF="+filepath.ToSlash(current), "TMPDIR="+filepath.ToSlash(root))
			if fail {
				env = append(env, "VERIFY_FAIL=1")
			}
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			data, _ := os.ReadFile(current)
			if fail {
				if err == nil || string(data) != original {
					t.Fatalf("signature rejection changed binary: %s", out)
				}
			} else if err != nil || string(data) != "new-binary" {
				t.Fatalf("upgrade failed: %v %s", err, out)
			}
			matches, _ := filepath.Glob(filepath.Join(binDir, ".relaydock-agent.new.*"))
			if len(matches) > 0 {
				t.Fatal("staging file leaked")
			}
			matches, _ = filepath.Glob(filepath.Join(root, "relaydock-upgrade.*"))
			if len(matches) > 0 {
				t.Fatal("download directory leaked")
			}
		})
	}
}
