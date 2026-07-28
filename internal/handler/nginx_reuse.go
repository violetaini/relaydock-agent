package handler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"mmw-agent/internal/constants"
)

const (
	arcwayReuseLoaderMarker = "# arcway: reuse-existing nginx loader v1"
	arcwayReuseConfigMarker = "# arcway: reuse-existing nginx config v1"
)

var (
	nginxReuseMu sync.Mutex

	findNginxForReuse = findNginxBinary
	runNginxForReuse  = func(binary string, args ...string) (string, error) {
		output, err := exec.Command(binary, args...).CombinedOutput()
		text := strings.TrimSpace(string(output))
		if err != nil {
			if text == "" {
				return "", fmt.Errorf("%s %s: %w", binary, strings.Join(args, " "), err)
			}
			return text, fmt.Errorf("%s %s: %s: %w", binary, strings.Join(args, " "), text, err)
		}
		return text, nil
	}
)

type nginxSetupSSLRequest struct {
	Domain       string `json:"domain"`
	NginxConfig  string `json:"nginx_config"`
	DomainConfig string `json:"domain_config"`
	NginxMode    string `json:"nginx_mode"`
}

type nginxReuseRuntime struct {
	Binary         string
	Prefix         string
	MainConfigPath string
}

type nginxReuseResult struct {
	ConfigPath     string
	LoaderPath     string
	IncludePattern string
	MainConfigPath string
}

type nginxIncludeCandidate struct {
	Pattern    string
	LoaderPath string
	Score      int
}

type nginxFileSnapshot struct {
	exists bool
	data   []byte
	mode   os.FileMode
}

func normalizeNginxMode(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", constants.NginxModeManaged:
		return constants.NginxModeManaged, nil
	case constants.NginxModeReuseExisting:
		return constants.NginxModeReuseExisting, nil
	default:
		return "", fmt.Errorf("nginx_mode must be %q or %q", constants.NginxModeManaged, constants.NginxModeReuseExisting)
	}
}

func setupNginxReuseExisting(domain, domainConfig string) (nginxReuseResult, error) {
	nginxReuseMu.Lock()
	defer nginxReuseMu.Unlock()

	runtime, err := discoverNginxReuseRuntime()
	if err != nil {
		return nginxReuseResult{}, err
	}
	if _, err := runNginxForReuse(runtime.Binary, "-t"); err != nil {
		return nginxReuseResult{}, fmt.Errorf("existing nginx configuration is already invalid; no files changed: %w", err)
	}
	baselineDump, err := runNginxForReuse(runtime.Binary, "-T")
	if err != nil {
		return nginxReuseResult{}, fmt.Errorf("inspect active nginx includes: %w", err)
	}

	candidates := nginxHTTPIncludeCandidates(baselineDump, runtime)
	if len(candidates) == 0 {
		return nginxReuseResult{}, fmt.Errorf("no active writable HTTP wildcard include was found in %s; add a conf.d/sites-enabled/servers include before using reuse_existing", runtime.MainConfigPath)
	}

	privateRoot := nginxReusePrivateRoot(runtime.MainConfigPath)
	serverDir := filepath.Join(privateRoot, "servers")
	domainPath := filepath.Join(serverDir, domain+".conf")
	createdPrivateRoot, err := ensureNginxReuseDirectory(privateRoot)
	if err != nil {
		return nginxReuseResult{}, err
	}
	createdServerDir, err := ensureNginxReuseDirectory(serverDir)
	if err != nil {
		if createdPrivateRoot {
			_ = os.Remove(privateRoot)
		}
		return nginxReuseResult{}, err
	}
	loaderContent := renderNginxReuseLoader(serverDir)
	domainContent := renderNginxReuseDomainConfig(domainConfig)
	var attemptErrors []string

	for _, candidate := range candidates {
		result, err := tryNginxReuseCandidate(runtime, candidate, domainPath, loaderContent, domainContent, createdPrivateRoot, createdServerDir)
		if err == nil {
			return result, nil
		}
		attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", candidate.Pattern, err))
	}
	if createdServerDir {
		_ = os.Remove(serverDir)
	}
	if createdPrivateRoot {
		_ = os.Remove(privateRoot)
	}

	return nginxReuseResult{}, fmt.Errorf("no compatible HTTP include accepted the Arcway configuration: %s", strings.Join(attemptErrors, "; "))
}

func nginxReusePrivateRoot(mainConfigPath string) string {
	return filepath.Join(filepath.Dir(mainConfigPath), "arcway.d")
}

func ensureNginxReuseDirectory(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0755); err != nil {
			return false, fmt.Errorf("create Arcway private nginx directory %s: %w", path, err)
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect Arcway private nginx directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("Arcway private nginx path must be a real directory: %s", path)
	}
	return false, nil
}

func discoverNginxReuseRuntime() (nginxReuseRuntime, error) {
	binary := findNginxForReuse()
	if binary == "" {
		return nginxReuseRuntime{}, fmt.Errorf("existing nginx binary not found; reuse_existing never installs nginx")
	}
	versionOutput, err := runNginxForReuse(binary, "-V")
	if err != nil {
		return nginxReuseRuntime{}, fmt.Errorf("inspect existing nginx build: %w", err)
	}
	prefix := nginxConfigureArgument(versionOutput, "prefix")
	confPath := nginxConfigureArgument(versionOutput, "conf-path")
	if confPath == "" {
		return nginxReuseRuntime{}, fmt.Errorf("existing nginx did not report --conf-path; refusing to guess its main configuration")
	}
	if !filepath.IsAbs(confPath) {
		if prefix == "" {
			return nginxReuseRuntime{}, fmt.Errorf("existing nginx uses relative --conf-path without --prefix; refusing to guess its main configuration")
		}
		confPath = filepath.Join(prefix, confPath)
	}
	confPath = filepath.Clean(confPath)
	if info, err := os.Stat(confPath); err != nil {
		return nginxReuseRuntime{}, fmt.Errorf("stat existing nginx main configuration %s: %w", confPath, err)
	} else if !info.Mode().IsRegular() {
		return nginxReuseRuntime{}, fmt.Errorf("existing nginx main configuration is not a regular file: %s", confPath)
	}
	if prefix == "" {
		prefix = filepath.Dir(confPath)
	} else if !filepath.IsAbs(prefix) {
		prefix, _ = filepath.Abs(prefix)
	}
	return nginxReuseRuntime{Binary: binary, Prefix: filepath.Clean(prefix), MainConfigPath: confPath}, nil
}

func nginxConfigureArgument(output, name string) string {
	pattern := regexp.MustCompile(`(?:^|\s)--` + regexp.QuoteMeta(name) + `=(?:"([^"]*)"|'([^']*)'|(\S+))`)
	match := pattern.FindStringSubmatch(output)
	if len(match) == 0 {
		return ""
	}
	for _, value := range match[1:] {
		if value != "" {
			return value
		}
	}
	return ""
}

func nginxHTTPIncludeCandidates(configDump string, runtime nginxReuseRuntime) []nginxIncludeCandidate {
	seen := make(map[string]struct{})
	var candidates []nginxIncludeCandidate
	for _, includeValue := range nginxHTTPIncludePatterns(configDump) {
		value := strings.TrimSpace(includeValue)
		if hash := strings.Index(value, "#"); hash >= 0 {
			value = strings.TrimSpace(value[:hash])
		}
		value = strings.Trim(value, `"'`)
		if value == "" || strings.Contains(value, "$)") || strings.ContainsAny(value, "\r\n") {
			continue
		}
		if !filepath.IsAbs(value) {
			value = filepath.Join(runtime.Prefix, value)
		}
		value = filepath.Clean(value)
		dir, glob := filepath.Dir(value), filepath.Base(value)
		if glob != "*" && glob != "*.conf" {
			continue
		}
		lowerDir := strings.ToLower(filepath.ToSlash(dir))
		if strings.Contains(lowerDir, "/arcway.d/") || strings.HasSuffix(lowerDir, "/arcway.d") ||
			strings.Contains(lowerDir, "module") || strings.Contains(lowerDir, "snippet") {
			continue
		}
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		loaderPath := filepath.Join(dir, "arcway-reuse.conf")
		if _, ok := seen[loaderPath]; ok {
			continue
		}
		seen[loaderPath] = struct{}{}
		if info, err := os.Lstat(loaderPath); err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			content, readErr := os.ReadFile(loaderPath)
			if readErr != nil || !strings.Contains(string(content), arcwayReuseLoaderMarker) {
				continue
			}
		}
		candidates = append(candidates, nginxIncludeCandidate{
			Pattern:    value,
			LoaderPath: loaderPath,
			Score:      nginxIncludeScore(dir, loaderPath),
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Score == candidates[j].Score {
			return candidates[i].LoaderPath < candidates[j].LoaderPath
		}
		return candidates[i].Score < candidates[j].Score
	})
	return candidates
}

// nginxHTTPIncludePatterns parses the rendered nginx configuration just far
// enough to distinguish includes in the http context from stream or top-level
// includes. nginx -T retains the original include directives, including those
// in nested files, so parsing the rendered output also proves the directory is
// part of the effective configuration.
func nginxHTTPIncludePatterns(configDump string) []string {
	var includes []string
	var statement strings.Builder
	var contexts []string
	inComment := false
	var quote rune

	flushStatement := func() string {
		value := strings.TrimSpace(statement.String())
		statement.Reset()
		return value
	}
	inHTTPContext := func() bool {
		for _, context := range contexts {
			if context == "http" {
				return true
			}
		}
		return false
	}

	for _, char := range configDump {
		if inComment {
			if char == '\n' {
				inComment = false
				statement.WriteRune(' ')
			}
			continue
		}
		if quote != 0 {
			statement.WriteRune(char)
			if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '#':
			inComment = true
		case '\'', '"':
			quote = char
			statement.WriteRune(char)
		case '{':
			fields := strings.Fields(flushStatement())
			if len(fields) > 0 {
				contexts = append(contexts, strings.ToLower(fields[0]))
			} else {
				contexts = append(contexts, "")
			}
		case '}':
			flushStatement()
			if len(contexts) > 0 {
				contexts = contexts[:len(contexts)-1]
			}
		case ';':
			fields := strings.Fields(flushStatement())
			if inHTTPContext() && len(fields) >= 2 && strings.EqualFold(fields[0], "include") {
				includes = append(includes, strings.Trim(fields[1], `"'`))
			}
		default:
			statement.WriteRune(char)
		}
	}
	return includes
}

func nginxIncludeScore(dir, loaderPath string) int {
	if content, err := os.ReadFile(loaderPath); err == nil && strings.Contains(string(content), arcwayReuseLoaderMarker) {
		return 0
	}
	switch strings.ToLower(filepath.Base(dir)) {
	case "conf.d":
		return 10
	case "sites-enabled":
		return 20
	case "servers", "vhosts", "vhost.d", "http.d":
		return 30
	default:
		return 100
	}
}

func renderNginxReuseLoader(serverDir string) string {
	return fmt.Sprintf(`%s
# This file is owned by Arcway. The main nginx.conf is never modified.
map $http_upgrade $arcway_reuse_connection_upgrade {
    default upgrade;
    ""      close;
}

include %s/*.conf;
`, arcwayReuseLoaderMarker, filepath.ToSlash(serverDir))
}

func renderNginxReuseDomainConfig(domainConfig string) string {
	config := strings.ReplaceAll(domainConfig, "$arcway_connection_upgrade", "$arcway_reuse_connection_upgrade")
	return arcwayReuseConfigMarker + "\n" + config
}

func tryNginxReuseCandidate(runtime nginxReuseRuntime, candidate nginxIncludeCandidate, domainPath, loaderContent, domainContent string, createdPrivateRoot, createdServerDir bool) (nginxReuseResult, error) {
	loaderSnapshot, err := captureNginxFile(candidate.LoaderPath, arcwayReuseLoaderMarker)
	if err != nil {
		return nginxReuseResult{}, err
	}
	domainSnapshot, err := captureNginxFile(domainPath, arcwayReuseConfigMarker)
	if err != nil {
		return nginxReuseResult{}, err
	}
	rollback := func() error {
		var errs []string
		if err := restoreNginxFile(candidate.LoaderPath, loaderSnapshot); err != nil {
			errs = append(errs, "loader: "+err.Error())
		}
		if err := restoreNginxFile(domainPath, domainSnapshot); err != nil {
			errs = append(errs, "domain: "+err.Error())
		}
		if createdServerDir {
			_ = os.Remove(filepath.Dir(domainPath))
		}
		if createdPrivateRoot {
			_ = os.Remove(filepath.Dir(filepath.Dir(domainPath)))
		}
		if len(errs) > 0 {
			return fmt.Errorf("%s", strings.Join(errs, "; "))
		}
		return nil
	}

	if err := atomicWriteNginxFile(candidate.LoaderPath, []byte(loaderContent), 0644); err != nil {
		_ = rollback()
		return nginxReuseResult{}, fmt.Errorf("write Arcway loader: %w", err)
	}
	if err := atomicWriteNginxFile(domainPath, []byte(domainContent), 0644); err != nil {
		rollbackErr := rollback()
		return nginxReuseResult{}, withNginxRollbackError(fmt.Errorf("write Arcway domain config: %w", err), rollbackErr)
	}
	if _, err := runNginxForReuse(runtime.Binary, "-t"); err != nil {
		rollbackErr := rollback()
		return nginxReuseResult{}, withNginxRollbackError(fmt.Errorf("nginx -t rejected Arcway configuration: %w", err), rollbackErr)
	}
	if _, err := runNginxForReuse(runtime.Binary, "-s", "reload"); err != nil {
		rollbackErr := rollback()
		if rollbackErr == nil {
			if _, testErr := runNginxForReuse(runtime.Binary, "-t"); testErr != nil {
				rollbackErr = fmt.Errorf("restored configuration failed nginx -t: %w", testErr)
			} else if _, reloadErr := runNginxForReuse(runtime.Binary, "-s", "reload"); reloadErr != nil {
				rollbackErr = fmt.Errorf("restored configuration reload failed: %w", reloadErr)
			}
		}
		return nginxReuseResult{}, withNginxRollbackError(fmt.Errorf("reload existing nginx: %w", err), rollbackErr)
	}

	// The reload has now accepted this exact configuration. Inspect the rendered
	// configuration afterwards so a successful syntax check cannot be mistaken
	// for an effective include.
	dump, err := runNginxForReuse(runtime.Binary, "-T")
	if err != nil || !strings.Contains(dump, arcwayReuseLoaderMarker) || !strings.Contains(dump, arcwayReuseConfigMarker) {
		rollbackErr := rollback()
		if rollbackErr == nil {
			if _, testErr := runNginxForReuse(runtime.Binary, "-t"); testErr != nil {
				rollbackErr = fmt.Errorf("restored configuration failed nginx -t: %w", testErr)
			} else if _, reloadErr := runNginxForReuse(runtime.Binary, "-s", "reload"); reloadErr != nil {
				rollbackErr = fmt.Errorf("restored configuration reload failed: %w", reloadErr)
			}
		}
		if err != nil {
			return nginxReuseResult{}, withNginxRollbackError(fmt.Errorf("verify active Arcway include: %w", err), rollbackErr)
		}
		return nginxReuseResult{}, withNginxRollbackError(fmt.Errorf("nginx reloaded but did not load Arcway through %s", candidate.Pattern), rollbackErr)
	}

	return nginxReuseResult{
		ConfigPath:     domainPath,
		LoaderPath:     candidate.LoaderPath,
		IncludePattern: candidate.Pattern,
		MainConfigPath: runtime.MainConfigPath,
	}, nil
}

func captureNginxFile(path, ownershipMarker string) (nginxFileSnapshot, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nginxFileSnapshot{}, nil
	}
	if err != nil {
		return nginxFileSnapshot{}, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nginxFileSnapshot{}, fmt.Errorf("refusing to replace non-regular configuration: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nginxFileSnapshot{}, fmt.Errorf("read %s: %w", path, err)
	}
	if !strings.Contains(string(data), ownershipMarker) {
		return nginxFileSnapshot{}, fmt.Errorf("refusing to replace configuration not owned by Arcway: %s", path)
	}
	return nginxFileSnapshot{exists: true, data: data, mode: info.Mode().Perm()}, nil
}

func restoreNginxFile(path string, snapshot nginxFileSnapshot) error {
	if !snapshot.exists {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove new file %s: %w", path, err)
		}
		return nil
	}
	return atomicWriteNginxFile(path, snapshot.data, snapshot.mode)
}

func atomicWriteNginxFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".arcway-nginx-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func withNginxRollbackError(operationErr, rollbackErr error) error {
	if rollbackErr == nil {
		return fmt.Errorf("%w; Arcway files restored", operationErr)
	}
	return fmt.Errorf("%w; rollback failed: %v", operationErr, rollbackErr)
}
