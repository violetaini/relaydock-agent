package linespeed

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Implementation       = "Ookla Speedtest CLI"
	Version              = "1.2.0"
	ResultImplementation = Implementation + " " + Version

	managedFilename        = "speedtest"
	consentFilename        = ".ookla-speedtest-consent"
	homeDirectory          = "home"
	temporaryBinaryPrefix  = ".speedtest-"
	temporaryConsentPrefix = ".ookla-speedtest-consent-"

	officialDownloadBase = "https://install.speedtest.net/app/cli/"
	maxArchiveBytes      = int64(16 << 20)
	maxArchiveExpanded   = int64(64 << 20)
	maxBinaryBytes       = int64(8 << 20)
	maxConsentBytes      = int64(512)
	maxCommandOutput     = int64(1 << 20)
	defaultRunTimeout    = 3 * time.Minute
	defaultInstallTTL    = 4 * time.Minute
	versionCheckTimeout  = 15 * time.Second
	managedBinaryFDPath  = "/proc/self/fd/3"
)

var (
	ErrBusy               = errors.New("line speed test operation already in progress")
	ErrNotInstalled       = errors.New("Ookla Speedtest CLI is not installed")
	ErrNotManaged         = errors.New("Ookla Speedtest CLI is not managed by the agent")
	ErrLicenseNotAccepted = errors.New("the Ookla Speedtest CLI license and privacy notice must be accepted before installation")
	ErrOutputLimit        = errors.New("Ookla Speedtest CLI output exceeded the size limit")
	ErrUnsupported        = errors.New("managed Ookla Speedtest CLI is unsupported on this platform")
)

type artifact struct {
	arch       string
	url        string
	archiveSHA string
	binarySHA  string
}

var officialArtifacts = map[string]artifact{
	"amd64": {
		arch:       "x86_64",
		url:        officialDownloadBase + "ookla-speedtest-1.2.0-linux-x86_64.tgz",
		archiveSHA: "5690596c54ff9bed63fa3732f818a05dbc2db19ad36ed68f21ca5f64d5cfeeb7",
		binarySHA:  "31f1124c5ab8acdae6b9fe1741e704df420f9f2e7d429679fabe62075453c051",
	},
	"arm64": {
		arch:       "aarch64",
		url:        officialDownloadBase + "ookla-speedtest-1.2.0-linux-aarch64.tgz",
		archiveSHA: "3953d231da3783e2bf8904b6dd72767c5c6e533e163d3742fd0437affa431bd3",
		binarySHA:  "d99fa13293f658b53eaa79fe81f4b210db39fdfc1e9698f33da3f234a6008df7",
	},
	"386": {
		arch:       "i386",
		url:        officialDownloadBase + "ookla-speedtest-1.2.0-linux-i386.tgz",
		archiveSHA: "9ff7e18dbae7ee0e03c66108445a2fb6ceea6c86f66482e1392f55881b772fe8",
		binarySHA:  "8c600519568eddf31849fbbe9c65b1987dd6f81d69d9b443d4e4afdb3f4864b0",
	},
	"armhf": {
		arch:       "armhf",
		url:        officialDownloadBase + "ookla-speedtest-1.2.0-linux-armhf.tgz",
		archiveSHA: "e45fcdebbd8a185553535533dd032d6b10bc8c64eee4139b1147b9c09835d08d",
		binarySHA:  "66ad57568664e6f8580e14ad67316a57038fd22b30548bef98531df4ebcc8956",
	},
	"armel": {
		arch:       "armel",
		url:        officialDownloadBase + "ookla-speedtest-1.2.0-linux-armel.tgz",
		archiveSHA: "629a455a2879224bd0dbd4b36d8c721dda540717937e4660b4d2c966029466bf",
		binarySHA:  "d103b5372da7720413f5263e0b557b6d477669785da2b6d7393d00e9708daf2b",
	},
}

type Status struct {
	Supported       bool   `json:"supported"`
	Installed       bool   `json:"installed"`
	Managed         bool   `json:"managed"`
	Owned           bool   `json:"owned"`
	Implementation  string `json:"implementation"`
	Version         string `json:"version,omitempty"`
	PythonReady     bool   `json:"python_ready"` // Legacy field: native Ookla CLI has no Python dependency.
	LicenseAccepted bool   `json:"license_accepted"`
	Running         bool   `json:"running"`
}

type Result struct {
	PingMS            float64   `json:"ping_ms"`
	DownloadMbps      float64   `json:"download_mbps"`
	UploadMbps        float64   `json:"upload_mbps"`
	JitterMS          *float64  `json:"jitter_ms,omitempty"`
	PacketLossPercent *float64  `json:"packet_loss_percent,omitempty"`
	ISP               string    `json:"isp"`
	EgressIP          string    `json:"egress_ip"`
	TestServer        string    `json:"test_server"`
	ServerLocation    string    `json:"server_location"`
	ResultURL         string    `json:"result_url,omitempty"`
	Implementation    string    `json:"implementation"`
	CreatedAt         time.Time `json:"created_at"`
}

type commandFactory func(context.Context, string, ...string) *exec.Cmd

type Service struct {
	managedDir      string
	managedPath     string
	consentPath     string
	homeDir         string
	httpClient      *http.Client
	command         commandFactory
	ipv4BindAddress func() string

	goos             string
	goarch           string
	armVariant       func() string
	artifactOverride *artifact

	operationMu    sync.Mutex
	running        atomic.Bool
	runTimeout     time.Duration
	installTimeout time.Duration
	versionTimeout time.Duration
}

func New(configDir string) *Service {
	if strings.TrimSpace(configDir) == "" {
		configDir = "."
	}
	managedDir := filepath.Join(configDir, "tools", "ookla-speedtest")
	return &Service{
		managedDir:      managedDir,
		managedPath:     filepath.Join(managedDir, managedFilename),
		consentPath:     filepath.Join(managedDir, consentFilename),
		homeDir:         filepath.Join(managedDir, homeDirectory),
		httpClient:      &http.Client{Timeout: 90 * time.Second},
		command:         exec.CommandContext,
		ipv4BindAddress: preferredIPv4BindAddress,
		goos:            runtime.GOOS,
		goarch:          runtime.GOARCH,
		armVariant:      detectARMVariant,
		runTimeout:      defaultRunTimeout,
		installTimeout:  defaultInstallTTL,
		versionTimeout:  versionCheckTimeout,
	}
}

func (s *Service) Status(context.Context) Status {
	status := Status{
		Implementation: Implementation,
		Running:        s != nil && s.running.Load(),
	}
	if s == nil {
		return status
	}
	if _, err := s.resolveArtifact(); err != nil {
		return status
	}
	status.Supported = true
	status.Managed = true
	// Retained for older masters. The native official CLI has no Python dependency.
	status.PythonReady = false
	if file, err := s.openVerifiedOfficialBinary(); err == nil {
		status.Installed = true
		status.Owned = true
		status.Version = Version
		status.LicenseAccepted = s.consentMatchesOpenBinary(file) == nil
		_ = file.Close()
	}
	return status
}

// Install downloads the official Ookla archive only after the caller explicitly
// accepts the license and privacy notice. The consent marker also pins the exact
// extracted binary digest used by future runs.
func (s *Service) Install(ctx context.Context, acceptLicense bool) (Status, error) {
	if _, err := s.resolveArtifact(); err != nil {
		return s.Status(ctx), err
	}
	if !acceptLicense {
		return s.Status(ctx), ErrLicenseNotAccepted
	}
	if !s.operationMu.TryLock() {
		return s.Status(ctx), ErrBusy
	}
	defer s.operationMu.Unlock()

	installCtx, cancel := context.WithTimeout(ctx, s.installTimeout)
	defer cancel()
	if current := s.Status(installCtx); current.Installed && current.LicenseAccepted {
		return current, nil
	}
	if err := s.ensureManagedDirectories(); err != nil {
		return s.Status(installCtx), err
	}
	if err := s.cleanupStaleTemporaryFiles(); err != nil {
		return s.Status(installCtx), err
	}
	// A crash after the atomic binary rename but before writing the consent marker
	// leaves a locally managed binary in place. Explicit consent may complete that
	// installation after the binary reports the expected official version via FD.
	if current := s.Status(installCtx); current.Installed && !current.LicenseAccepted {
		if file, err := s.openVerifiedOfficialBinary(); err == nil {
			verifyErr := s.verifyBinaryVersion(installCtx, file)
			digest, digestErr := digestOpenFile(file, maxBinaryBytes)
			_ = file.Close()
			if verifyErr == nil && digestErr == nil {
				if err := s.writeConsentMarker(digest); err != nil {
					return s.Status(installCtx), err
				}
				if status := s.Status(installCtx); status.Installed && status.LicenseAccepted {
					return status, nil
				}
			}
		}
	}
	art, err := s.resolveArtifact()
	if err != nil {
		return s.Status(installCtx), err
	}
	archive, err := s.downloadArchive(installCtx, art)
	if err != nil {
		return s.Status(installCtx), err
	}
	binary, err := unpackOfficialArchive(archive)
	if err != nil {
		return s.Status(installCtx), err
	}
	if err := s.installBinary(installCtx, binary, art); err != nil {
		return s.Status(installCtx), err
	}
	status := s.Status(installCtx)
	if !status.Installed || !status.Owned || !status.LicenseAccepted {
		return status, errors.New("managed Ookla Speedtest CLI failed its post-install check")
	}
	return status, nil
}

func (s *Service) Remove(ctx context.Context) (Status, error) {
	if _, err := s.resolveArtifact(); err != nil {
		return s.Status(ctx), err
	}
	if !s.operationMu.TryLock() {
		return s.Status(ctx), ErrBusy
	}
	defer s.operationMu.Unlock()
	if err := s.cleanupStaleTemporaryFiles(); err != nil {
		return s.Status(ctx), err
	}

	binaryExists, binaryTrusted := s.managedPathState()
	markerExists, markerTrusted := s.consentPathState()
	homeExists, homeTrusted := s.managedHomeState()
	if !binaryExists && !markerExists && !homeExists {
		return s.Status(ctx), nil
	}
	if (binaryExists && !binaryTrusted) || (markerExists && !markerTrusted) || (homeExists && !homeTrusted) {
		return s.Status(ctx), ErrNotManaged
	}
	if binaryExists {
		var file *os.File
		var err error
		if markerExists {
			file, err = s.openVerifiedManagedBinary()
		} else {
			file, err = s.openVerifiedOfficialBinary()
		}
		if err != nil {
			return s.Status(ctx), ErrNotManaged
		}
		_ = file.Close()
		if err := os.Remove(s.managedPath); err != nil && !os.IsNotExist(err) {
			return s.Status(ctx), fmt.Errorf("remove managed Ookla Speedtest CLI: %w", err)
		}
	}
	// A valid marker without a binary can result from an interrupted prior uninstall.
	// It is safe to remove and prevents a stale consent record from being reused.
	if markerExists {
		if err := os.Remove(s.consentPath); err != nil && !os.IsNotExist(err) {
			return s.Status(ctx), fmt.Errorf("remove Ookla consent marker: %w", err)
		}
	}
	if homeExists {
		if err := os.RemoveAll(s.homeDir); err != nil {
			return s.Status(ctx), fmt.Errorf("remove managed Ookla runtime directory: %w", err)
		}
	}
	return s.Status(ctx), nil
}

func (s *Service) Run(ctx context.Context) (Result, error) {
	if _, err := s.resolveArtifact(); err != nil {
		return Result{}, err
	}
	if !s.operationMu.TryLock() {
		return Result{}, ErrBusy
	}
	defer s.operationMu.Unlock()

	s.running.Store(true)
	defer s.running.Store(false)

	runCtx, cancel := context.WithTimeout(ctx, s.runTimeout)
	defer cancel()
	file, err := s.openVerifiedManagedBinary()
	if err != nil {
		return Result{}, err
	}
	defer file.Close()
	env, err := s.managedEnvironment()
	if err != nil {
		return Result{}, err
	}
	args := []string{
		"--accept-license",
		"--accept-gdpr",
		"--progress=no",
		"--format=json",
	}
	stdout, detail, err := s.runOfficialCLI(runCtx, file, env, args)
	if runCtx.Err() != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return Result{}, fmt.Errorf("Ookla Speedtest CLI timed out after %s: %w", s.runTimeout, runCtx.Err())
		}
		return Result{}, fmt.Errorf("Ookla Speedtest CLI canceled: %w", runCtx.Err())
	}
	if err != nil && isConnectTimeout(detail) && s.ipv4BindAddress != nil {
		if bindAddress := s.ipv4BindAddress(); bindAddress != "" {
			retryArgs := append(append([]string(nil), args...), "--ip", bindAddress)
			retryStdout, retryDetail, retryErr := s.runOfficialCLI(runCtx, file, env, retryArgs)
			if runCtx.Err() != nil {
				if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
					return Result{}, fmt.Errorf("Ookla Speedtest CLI timed out after %s: %w", s.runTimeout, runCtx.Err())
				}
				return Result{}, fmt.Errorf("Ookla Speedtest CLI canceled: %w", runCtx.Err())
			}
			if retryErr == nil {
				stdout = retryStdout
				err = nil
			} else {
				return Result{}, fmt.Errorf("Ookla Speedtest CLI failed after IPv4 fallback (%s): %s", bindAddress, commandFailureDetail(retryDetail, retryErr))
			}
		}
	}
	if err != nil {
		return Result{}, fmt.Errorf("Ookla Speedtest CLI failed: %s", commandFailureDetail(detail, err))
	}
	result, err := parseResult(stdout)
	if err != nil {
		return Result{}, err
	}
	result.Implementation = ResultImplementation
	result.CreatedAt = time.Now().UTC()
	return result, nil
}

func (s *Service) runOfficialCLI(ctx context.Context, file *os.File, env, args []string) ([]byte, string, error) {
	stdout := newCappedBuffer(maxCommandOutput)
	stderr := newCappedBuffer(maxCommandOutput)
	cmd := s.command(ctx, managedBinaryFDPath, args...)
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if stdout.Truncated() || stderr.Truncated() {
		return nil, "", ErrOutputLimit
	}
	return stdout.Bytes(), strings.TrimSpace(stderr.String()), err
}

func commandFailureDetail(detail string, err error) string {
	if detail = truncateDetail(strings.TrimSpace(detail), 4096); detail != "" {
		return detail
	}
	return err.Error()
}

func isConnectTimeout(detail string) bool {
	return strings.Contains(strings.ToLower(detail), "timeout occurred in connect")
}

// preferredIPv4BindAddress obtains the source address selected by the kernel's
// IPv4 routing table. UDP connect selects a route locally and sends no packet.
func preferredIPv4BindAddress() string {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})
	if err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && usableIPv4(addr.IP) {
			return addr.IP.To4().String()
		}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if usableIPv4(ip) {
				return ip.To4().String()
			}
		}
	}
	return ""
}

func usableIPv4(ip net.IP) bool {
	ip = ip.To4()
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast()
}

func (s *Service) resolveArtifact() (artifact, error) {
	if s == nil || s.goos != "linux" {
		return artifact{}, ErrUnsupported
	}
	if s.artifactOverride != nil {
		return *s.artifactOverride, nil
	}
	arch := strings.ToLower(strings.TrimSpace(s.goarch))
	switch arch {
	case "amd64", "x86_64":
		return officialArtifacts["amd64"], nil
	case "arm64", "aarch64":
		return officialArtifacts["arm64"], nil
	case "386", "i386":
		return officialArtifacts["386"], nil
	case "armhf", "armel":
		return officialArtifacts[arch], nil
	case "arm":
		variant := ""
		if s.armVariant != nil {
			variant = s.armVariant()
		}
		if art, ok := officialArtifacts[variant]; ok {
			return art, nil
		}
	}
	return artifact{}, fmt.Errorf("%w: linux/%s", ErrUnsupported, arch)
}

// Go's GOARCH=arm does not encode whether the userspace ABI is armhf or armel.
// The dynamic loader is a stronger signal than CPU features; if it is ambiguous,
// refuse to install rather than guessing a binary that cannot run.
func detectARMVariant() string {
	hardFloatLoaders := []string{
		"/lib/ld-linux-armhf.so.3",
		"/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3",
		"/usr/arm-linux-gnueabihf/lib/ld-linux-armhf.so.3",
	}
	softFloatLoaders := []string{
		"/lib/ld-linux.so.3",
		"/lib/arm-linux-gnueabi/ld-linux.so.3",
		"/usr/arm-linux-gnueabi/lib/ld-linux.so.3",
	}
	hardFloat := anyPathExists(hardFloatLoaders)
	softFloat := anyPathExists(softFloatLoaders)
	switch {
	case hardFloat && !softFloat:
		return "armhf"
	case softFloat && !hardFloat:
		return "armel"
	default:
		return ""
	}
}

func anyPathExists(paths []string) bool {
	for _, candidate := range paths {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

func (s *Service) ensureManagedDirectories() error {
	if err := os.MkdirAll(s.managedDir, 0o755); err != nil {
		return fmt.Errorf("create Ookla Speedtest CLI directory: %w", err)
	}
	if !trustedManagedDirectory(s.managedDir) {
		return errors.New("Ookla Speedtest CLI directory must be owned by the agent user and not group/world writable")
	}
	if err := os.MkdirAll(s.homeDir, 0o700); err != nil {
		return fmt.Errorf("create Ookla Speedtest CLI runtime directory: %w", err)
	}
	if !trustedRuntimeDirectory(s.homeDir) {
		return errors.New("Ookla Speedtest CLI runtime directory must be private, owned by the agent user, and not group/world writable")
	}
	return nil
}

func trustedRuntimeDirectory(dir string) bool {
	if !trustedManagedDirectory(dir) {
		return false
	}
	info, err := os.Lstat(dir)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0
}

func (s *Service) managedEnvironment() ([]string, error) {
	if err := s.ensureManagedDirectories(); err != nil {
		return nil, err
	}
	// Keep every XDG location inside the panel-owned private home. This also
	// prevents a future CLI release from writing to a user's system profile.
	// PATH is fixed rather than inherited because the official CLI may invoke
	// system helpers internally.
	env := []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"TZ=UTC",
		"HOME=" + s.homeDir,
		"XDG_CONFIG_HOME=" + s.homeDir,
		"XDG_DATA_HOME=" + s.homeDir,
		"XDG_CACHE_HOME=" + s.homeDir,
		"XDG_STATE_HOME=" + s.homeDir,
	}
	return env, nil
}

func (s *Service) downloadArchive(ctx context.Context, art artifact) ([]byte, error) {
	if strings.TrimSpace(art.url) == "" || len(art.archiveSHA) != sha256.Size*2 || len(art.binarySHA) != sha256.Size*2 {
		return nil, errors.New("invalid official Ookla artifact configuration")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, art.url, nil)
	if err != nil {
		return nil, fmt.Errorf("create Ookla Speedtest CLI download request: %w", err)
	}
	req.Header.Set("User-Agent", "arcway-line-speedtest/1.0")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download Ookla Speedtest CLI: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Ookla Speedtest CLI download returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxArchiveBytes {
		return nil, fmt.Errorf("Ookla Speedtest CLI archive exceeds %d bytes", maxArchiveBytes)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArchiveBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Ookla Speedtest CLI archive: %w", err)
	}
	if int64(len(data)) > maxArchiveBytes {
		return nil, fmt.Errorf("Ookla Speedtest CLI archive exceeds %d bytes", maxArchiveBytes)
	}
	digest := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), art.archiveSHA) {
		return nil, errors.New("Ookla Speedtest CLI SHA-256 verification failed")
	}
	return data, nil
}

// unpackOfficialArchive never extracts the archive to disk. It accepts safe
// documentation entries, but copies only the exact regular speedtest entry.
func unpackOfficialArchive(archive []byte) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open Ookla Speedtest CLI archive: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(io.LimitReader(gzipReader, maxArchiveExpanded+1))
	var binary []byte
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read Ookla Speedtest CLI archive: %w", err)
		}
		name, err := safeArchiveName(header.Name)
		if err != nil {
			return nil, err
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxArchiveExpanded {
				return nil, errors.New("Ookla Speedtest CLI archive contains an oversized file")
			}
			if name != managedFilename {
				if _, err := io.Copy(io.Discard, tarReader); err != nil {
					return nil, fmt.Errorf("skip Ookla Speedtest CLI archive entry: %w", err)
				}
				continue
			}
			if binary != nil {
				return nil, errors.New("Ookla Speedtest CLI archive contains duplicate speedtest binaries")
			}
			if header.Size == 0 || header.Size > maxBinaryBytes {
				return nil, errors.New("Ookla Speedtest CLI binary has an invalid size")
			}
			binary, err = io.ReadAll(io.LimitReader(tarReader, maxBinaryBytes+1))
			if err != nil {
				return nil, fmt.Errorf("read Ookla Speedtest CLI binary: %w", err)
			}
			if int64(len(binary)) != header.Size || int64(len(binary)) > maxBinaryBytes {
				return nil, errors.New("Ookla Speedtest CLI binary has an invalid size")
			}
		case tar.TypeDir:
			// Directories are never created; their safe names were still validated.
		default:
			// Links and special files are deliberately rejected instead of relying on
			// archive/tar's extraction behavior.
			return nil, fmt.Errorf("Ookla Speedtest CLI archive contains unsupported entry %q", header.Name)
		}
	}
	if len(binary) == 0 {
		return nil, errors.New("Ookla Speedtest CLI archive does not contain speedtest")
	}
	return binary, nil
}

func safeArchiveName(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) || strings.Contains(name, "\\") || path.IsAbs(name) {
		return "", fmt.Errorf("unsafe Ookla Speedtest CLI archive path %q", name)
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("unsafe Ookla Speedtest CLI archive path %q", name)
	}
	return clean, nil
}

func (s *Service) installBinary(ctx context.Context, binary []byte, art artifact) error {
	binaryDigest := sha256.Sum256(binary)
	if !strings.EqualFold(hex.EncodeToString(binaryDigest[:]), art.binarySHA) {
		return errors.New("Ookla Speedtest CLI binary SHA-256 verification failed")
	}
	tmp, err := os.CreateTemp(s.managedDir, temporaryBinaryPrefix+"*")
	if err != nil {
		return fmt.Errorf("create Ookla Speedtest CLI temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	installed := false
	defer func() {
		_ = tmp.Close()
		if !installed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(binary); err != nil {
		return fmt.Errorf("write Ookla Speedtest CLI binary: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync Ookla Speedtest CLI binary: %w", err)
	}
	// CreateTemp starts at 0600. Do not make a partially written file executable;
	// the final mode is only needed after its content has been fully persisted.
	if err := tmp.Chmod(0o700); err != nil {
		return fmt.Errorf("set Ookla Speedtest CLI permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync Ookla Speedtest CLI permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close Ookla Speedtest CLI temporary binary: %w", err)
	}
	verifyFile, err := s.openTrustedFile(tmpPath, maxBinaryBytes, true)
	if err != nil {
		return fmt.Errorf("open Ookla Speedtest CLI temporary binary for verification: %w", err)
	}
	writtenDigest, digestErr := digestOpenFile(verifyFile, maxBinaryBytes)
	if digestErr != nil || !strings.EqualFold(writtenDigest, art.binarySHA) {
		_ = verifyFile.Close()
		return errors.New("Ookla Speedtest CLI binary SHA-256 verification failed")
	}
	verifyErr := s.verifyBinaryVersion(ctx, verifyFile)
	_ = verifyFile.Close()
	if verifyErr != nil {
		return verifyErr
	}
	if err := os.Rename(tmpPath, s.managedPath); err != nil {
		return fmt.Errorf("install Ookla Speedtest CLI binary: %w", err)
	}
	if err := s.writeConsentMarker(hex.EncodeToString(binaryDigest[:])); err != nil {
		return err
	}
	installed = true
	return nil
}

func (s *Service) verifyBinaryVersion(ctx context.Context, file *os.File) error {
	if file == nil {
		return errors.New("Ookla Speedtest CLI temporary file is unavailable")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	env, err := s.managedEnvironment()
	if err != nil {
		return err
	}
	versionCtx, cancel := context.WithTimeout(ctx, s.versionTimeout)
	defer cancel()
	stdout := newCappedBuffer(64 << 10)
	stderr := newCappedBuffer(64 << 10)
	cmd := s.command(versionCtx, managedBinaryFDPath, "--version")
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if versionCtx.Err() != nil {
			return versionCtx.Err()
		}
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return fmt.Errorf("verify Ookla Speedtest CLI version: %s", truncateDetail(detail, 4096))
	}
	if stdout.Truncated() || stderr.Truncated() {
		return ErrOutputLimit
	}
	output := stdout.String() + "\n" + stderr.String()
	if !strings.Contains(output, "Speedtest by Ookla "+Version) {
		return fmt.Errorf("downloaded Ookla Speedtest CLI did not report version %s", Version)
	}
	return nil
}

func (s *Service) writeConsentMarker(binaryDigest string) error {
	if len(binaryDigest) != sha256.Size*2 {
		return errors.New("invalid Ookla Speedtest CLI binary digest")
	}
	marker := consentMarker(binaryDigest)
	tmp, err := os.CreateTemp(s.managedDir, temporaryConsentPrefix+"*")
	if err != nil {
		return fmt.Errorf("create Ookla consent marker: %w", err)
	}
	tmpPath := tmp.Name()
	written := false
	defer func() {
		_ = tmp.Close()
		if !written {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("set Ookla consent marker permissions: %w", err)
	}
	if _, err := io.WriteString(tmp, marker); err != nil {
		return fmt.Errorf("write Ookla consent marker: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync Ookla consent marker: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close Ookla consent marker: %w", err)
	}
	if err := os.Rename(tmpPath, s.consentPath); err != nil {
		return fmt.Errorf("install Ookla consent marker: %w", err)
	}
	written = true
	return nil
}

func consentMarker(binaryDigest string) string {
	return "version=" + Version + "\nsha256=" + strings.ToLower(binaryDigest) + "\naccept_license=true\naccept_gdpr=true\n"
}

func (s *Service) openVerifiedManagedBinary() (*os.File, error) {
	file, err := s.openVerifiedOfficialBinary()
	if err != nil {
		return nil, err
	}
	if err := s.consentMatchesOpenBinary(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// openVerifiedOfficialBinary validates the fixed extracted-binary digest in
// addition to filesystem ownership/mode checks. A consent marker is deliberately
// not part of this check so Status can expose an installed CLI awaiting consent.
func (s *Service) openVerifiedOfficialBinary() (*os.File, error) {
	art, err := s.resolveArtifact()
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(s.managedPath); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotInstalled
		}
		return nil, err
	}
	file, err := s.openTrustedFile(s.managedPath, maxBinaryBytes, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotInstalled, err)
	}
	digest, err := digestOpenFile(file, maxBinaryBytes)
	if err != nil || !strings.EqualFold(digest, art.binarySHA) {
		_ = file.Close()
		return nil, fmt.Errorf("%w: binary digest mismatch", ErrNotInstalled)
	}
	return file, nil
}

func (s *Service) consentMatchesOpenBinary(file *os.File) error {
	digest, err := s.readConsentDigest()
	if err != nil {
		return err
	}
	actualDigest, err := digestOpenFile(file, maxBinaryBytes)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actualDigest, digest) {
		return errors.New("Ookla Speedtest CLI binary digest mismatch")
	}
	return nil
}

func (s *Service) readConsentDigest() (string, error) {
	file, err := s.openTrustedFile(s.consentPath, maxConsentBytes, false)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrLicenseNotAccepted
		}
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConsentBytes+1))
	if err != nil || int64(len(data)) > maxConsentBytes {
		return "", errors.New("invalid Ookla consent marker")
	}
	const prefix = "version=" + Version + "\nsha256="
	const suffix = "\naccept_license=true\naccept_gdpr=true\n"
	text := string(data)
	if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, suffix) {
		return "", errors.New("invalid Ookla consent marker")
	}
	digest := strings.TrimSuffix(strings.TrimPrefix(text, prefix), suffix)
	if len(digest) != sha256.Size*2 {
		return "", errors.New("invalid Ookla consent marker")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", errors.New("invalid Ookla consent marker")
	}
	return strings.ToLower(digest), nil
}

func (s *Service) openTrustedFile(filePath string, maxSize int64, executable bool) (*os.File, error) {
	if !trustedManagedDirectory(s.managedDir) {
		return nil, errors.New("untrusted Ookla Speedtest CLI directory")
	}
	info, err := os.Lstat(filePath)
	if err != nil {
		return nil, err
	}
	if !trustedFileInfo(info, maxSize, executable) {
		return nil, errors.New("untrusted Ookla Speedtest CLI file")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !trustedFileInfo(openedInfo, maxSize, executable) {
		_ = file.Close()
		return nil, errors.New("Ookla Speedtest CLI file changed while opening")
	}
	return file, nil
}

func trustedFileInfo(info os.FileInfo, maxSize int64, executable bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > maxSize || !ownedByEffectiveUser(info) {
		return false
	}
	return !executable || info.Mode().Perm()&0o111 != 0
}

func digestOpenFile(file *os.File, maxSize int64) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxSize+1))
	if err != nil || written == 0 || written > maxSize {
		return "", errors.New("read Ookla Speedtest CLI binary for verification")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *Service) managedPathState() (exists, trusted bool) {
	if _, err := os.Lstat(s.managedPath); err != nil {
		if os.IsNotExist(err) {
			return false, false
		}
		return true, false
	}
	file, err := s.openVerifiedOfficialBinary()
	if err == nil {
		_ = file.Close()
		return true, true
	}
	return true, false
}

func (s *Service) consentPathState() (exists, trusted bool) {
	if _, err := os.Lstat(s.consentPath); err != nil {
		if os.IsNotExist(err) {
			return false, false
		}
		return true, false
	}
	file, err := s.openTrustedFile(s.consentPath, maxConsentBytes, false)
	if err == nil {
		_ = file.Close()
		if _, markerErr := s.readConsentDigest(); markerErr == nil {
			return true, true
		}
		return true, false
	}
	return true, false
}

func (s *Service) managedHomeState() (exists, trusted bool) {
	if _, err := os.Lstat(s.homeDir); err != nil {
		if os.IsNotExist(err) {
			return false, false
		}
		return true, false
	}
	return true, trustedRuntimeDirectory(s.homeDir)
}

// cleanupStaleTemporaryFiles removes only agent-created atomic-write remnants.
// It validates every candidate before deleting any of them, so an unexpected
// entry cannot turn an uninstall into a partial cleanup of unknown files.
func (s *Service) cleanupStaleTemporaryFiles() error {
	if _, err := os.Lstat(s.managedDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect Ookla Speedtest CLI directory: %w", err)
	}
	if !trustedManagedDirectory(s.managedDir) {
		return fmt.Errorf("%w: untrusted Ookla Speedtest CLI directory", ErrNotManaged)
	}
	entries, err := os.ReadDir(s.managedDir)
	if err != nil {
		return fmt.Errorf("read Ookla Speedtest CLI directory: %w", err)
	}
	paths := make([]string, 0)
	for _, entry := range entries {
		maxSize, ok := managedTemporaryMaxSize(entry.Name())
		if !ok {
			continue
		}
		filePath := filepath.Join(s.managedDir, entry.Name())
		info, err := os.Lstat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("inspect Ookla Speedtest CLI temporary file: %w", err)
		}
		if !trustedTemporaryEntryInfo(info, maxSize) {
			return fmt.Errorf("%w: untrusted Ookla Speedtest CLI temporary file", ErrNotManaged)
		}
		paths = append(paths, filePath)
	}
	for _, filePath := range paths {
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale Ookla Speedtest CLI temporary file: %w", err)
		}
	}
	return nil
}

func managedTemporaryMaxSize(name string) (int64, bool) {
	switch {
	case strings.HasPrefix(name, temporaryBinaryPrefix):
		return maxBinaryBytes, true
	case strings.HasPrefix(name, temporaryConsentPrefix):
		return maxConsentBytes, true
	default:
		return 0, false
	}
}

func trustedTemporaryEntryInfo(info os.FileInfo, maxSize int64) bool {
	if info == nil || !ownedByEffectiveUser(info) {
		return false
	}
	// os.Remove unlinks a symlink itself and never follows its target. Directories
	// remain rejected so cleanup cannot recurse or remove managed subtrees.
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0 && info.Size() >= 0 && info.Size() <= maxSize
}

type rawOoklaResult struct {
	Type string `json:"type"`
	Ping struct {
		Latency *float64 `json:"latency"`
		Jitter  *float64 `json:"jitter"`
	} `json:"ping"`
	Download struct {
		Bandwidth *float64 `json:"bandwidth"`
	} `json:"download"`
	Upload struct {
		Bandwidth *float64 `json:"bandwidth"`
	} `json:"upload"`
	PacketLoss *float64 `json:"packetLoss"`
	ISP        string   `json:"isp"`
	Interface  struct {
		ExternalIP string `json:"externalIp"`
	} `json:"interface"`
	Server struct {
		Name     string `json:"name"`
		Location string `json:"location"`
		Country  string `json:"country"`
		Host     string `json:"host"`
	} `json:"server"`
	Result struct {
		URL string `json:"url"`
	} `json:"result"`
}

// Ookla can emit a license notice and JSON log lines before the final result.
// Only a line with type=result is a measurement payload.
func parseResult(data []byte) (Result, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), int(maxCommandOutput))
	var raw *rawOoklaResult
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil || envelope.Type != "result" {
			continue
		}
		candidate := new(rawOoklaResult)
		if err := json.Unmarshal([]byte(line), candidate); err != nil {
			return Result{}, fmt.Errorf("parse Ookla Speedtest CLI result JSON: %w", err)
		}
		raw = candidate
	}
	if err := scanner.Err(); err != nil {
		return Result{}, fmt.Errorf("read Ookla Speedtest CLI output: %w", err)
	}
	if raw == nil {
		return Result{}, errors.New("Ookla Speedtest CLI output did not contain a result")
	}
	if raw.Ping.Latency == nil || raw.Download.Bandwidth == nil || raw.Upload.Bandwidth == nil {
		return Result{}, errors.New("Ookla Speedtest CLI JSON is missing measurements")
	}
	if !finiteNonNegative(*raw.Ping.Latency) || !finiteNonNegative(*raw.Download.Bandwidth) || !finiteNonNegative(*raw.Upload.Bandwidth) {
		return Result{}, errors.New("Ookla Speedtest CLI returned invalid measurements")
	}
	if raw.Ping.Jitter != nil && !finiteNonNegative(*raw.Ping.Jitter) {
		return Result{}, errors.New("Ookla Speedtest CLI returned invalid jitter")
	}
	if raw.PacketLoss != nil && !finiteNonNegative(*raw.PacketLoss) {
		return Result{}, errors.New("Ookla Speedtest CLI returned invalid packet loss")
	}
	testServer := strings.TrimSpace(raw.Server.Name)
	if testServer == "" {
		testServer = strings.TrimSpace(raw.Server.Host)
	}
	location := strings.TrimSpace(raw.Server.Location)
	if location == "" {
		location = strings.Trim(strings.Join([]string{strings.TrimSpace(raw.Server.Name), strings.TrimSpace(raw.Server.Country)}, ", "), ", ")
	}
	return Result{
		PingMS:            *raw.Ping.Latency,
		DownloadMbps:      *raw.Download.Bandwidth * 8 / 1_000_000,
		UploadMbps:        *raw.Upload.Bandwidth * 8 / 1_000_000,
		JitterMS:          raw.Ping.Jitter,
		PacketLossPercent: raw.PacketLoss,
		ISP:               strings.TrimSpace(raw.ISP),
		EgressIP:          strings.TrimSpace(raw.Interface.ExternalIP),
		TestServer:        testServer,
		ServerLocation:    location,
		ResultURL:         strings.TrimSpace(raw.Result.URL),
	}, nil
}

func finiteNonNegative(value float64) bool {
	return value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func truncateDetail(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	return value[:maxBytes] + "..."
}

type cappedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func newCappedBuffer(limit int64) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(p)
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.truncated = true
		return written, nil
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buf.Write(p)
	return written, nil
}

func (b *cappedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func (b *cappedBuffer) String() string {
	return string(b.Bytes())
}

func (b *cappedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}
