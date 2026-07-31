package handler

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/violetaini/relaydock-agent/internal/util"
)

type certFileState struct {
	path   string
	data   []byte
	mode   os.FileMode
	exists bool
}

type certFilePair struct {
	cert certFileState
	key  certFileState
}

type certFileDeployment struct {
	before certFilePair
	after  certFilePair
	ops    certFileOps
}

type certFileOps struct {
	createTemp func(string, string) (*os.File, error)
	rename     func(string, string) error
	remove     func(string) error
}

func defaultCertFileOps() certFileOps {
	return certFileOps{
		createTemp: os.CreateTemp,
		rename:     os.Rename,
		remove:     os.Remove,
	}
}

func (ops certFileOps) withDefaults() certFileOps {
	defaults := defaultCertFileOps()
	if ops.createTemp == nil {
		ops.createTemp = defaults.createTemp
	}
	if ops.rename == nil {
		ops.rename = defaults.rename
	}
	if ops.remove == nil {
		ops.remove = defaults.remove
	}
	return ops
}

func deployCertFiles(certPEM, keyPEM, certPath, keyPath string) (*certFileDeployment, error) {
	return deployCertFilesWithOps(certPEM, keyPEM, certPath, keyPath, defaultCertFileOps())
}

func deployCertFilesWithOps(certPEM, keyPEM, certPath, keyPath string, ops certFileOps) (*certFileDeployment, error) {
	// Certificate paths are administrator-configurable. Restrict their contents
	// to real PEM material and reject sensitive destinations before creating any
	// directory or temporary file.
	if err := util.ValidateCertKeyPEM(certPEM, keyPEM); err != nil {
		return nil, err
	}
	if err := util.CertPathSafe(certPath); err != nil {
		return nil, fmt.Errorf("cert path: %w", err)
	}
	if err := util.CertPathSafe(keyPath); err != nil {
		return nil, fmt.Errorf("key path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}

	resolvedCertPath, err := resolveCertDeployPath(certPath)
	if err != nil {
		return nil, fmt.Errorf("resolve cert path: %w", err)
	}
	resolvedKeyPath, err := resolveCertDeployPath(keyPath)
	if err != nil {
		return nil, fmt.Errorf("resolve key path: %w", err)
	}
	if resolvedCertPath == resolvedKeyPath {
		return nil, fmt.Errorf("certificate and private key paths resolve to the same file")
	}

	beforeCert, err := captureCertFileState(resolvedCertPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot cert: %w", err)
	}
	beforeKey, err := captureCertFileState(resolvedKeyPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot key: %w", err)
	}

	deployment := &certFileDeployment{
		before: certFilePair{cert: beforeCert, key: beforeKey},
		after: certFilePair{
			cert: certFileState{path: resolvedCertPath, data: []byte(certPEM), mode: 0o644, exists: true},
			key:  certFileState{path: resolvedKeyPath, data: []byte(keyPEM), mode: 0o600, exists: true},
		},
		ops: ops.withDefaults(),
	}
	if err := replaceCertFilePair(deployment.after, deployment.before, deployment.ops); err != nil {
		return nil, err
	}
	return deployment, nil
}

// Rollback restores the exact pre-deployment contents and permission bits. The
// replacement uses the same pair transaction as deployment, so a failure while
// restoring the key re-applies the new certificate instead of leaving a mixed
// old/new pair.
func (deployment *certFileDeployment) Rollback() error {
	if deployment == nil {
		return fmt.Errorf("certificate deployment is unavailable")
	}
	return replaceCertFilePair(deployment.before, deployment.after, deployment.ops)
}

func resolveCertDeployPath(path string) (string, error) {
	clean := filepath.Clean(path)
	resolvedDir, err := filepath.EvalSymlinks(filepath.Dir(clean))
	if err != nil {
		return "", err
	}
	resolved := filepath.Join(resolvedDir, filepath.Base(clean))
	if info, statErr := os.Lstat(clean); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err = filepath.EvalSymlinks(clean)
			if err != nil {
				return "", err
			}
		}
	} else if !os.IsNotExist(statErr) {
		return "", statErr
	}
	if err := util.CertPathSafe(resolved); err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func captureCertFileState(path string) (certFileState, error) {
	state := certFileState{path: path}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() {
		return state, fmt.Errorf("target is not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	state.data = data
	state.mode = info.Mode().Perm()
	state.exists = true
	return state, nil
}

// replaceCertFilePair stages both desired files before replacing either one.
// POSIX has no two-path rename primitive, so if the second rename fails the
// first path is atomically restored from a pre-staged fallback copy.
func replaceCertFilePair(desired, fallback certFilePair, ops certFileOps) error {
	ops = ops.withDefaults()
	desiredCertTemp, err := stageCertFileState(desired.cert, ops)
	if err != nil {
		return fmt.Errorf("stage cert: %w", err)
	}
	defer removeStagedCertFile(&desiredCertTemp, ops)

	desiredKeyTemp, err := stageCertFileState(desired.key, ops)
	if err != nil {
		return fmt.Errorf("stage key: %w", err)
	}
	defer removeStagedCertFile(&desiredKeyTemp, ops)

	// Only the first path needs a fallback staged ahead of time: if applying
	// the second path fails, that second path is still in its fallback state.
	fallbackCertTemp, err := stageCertFileState(fallback.cert, ops)
	if err != nil {
		return fmt.Errorf("stage cert rollback: %w", err)
	}
	defer removeStagedCertFile(&fallbackCertTemp, ops)

	if err := applyCertFileState(desired.cert, &desiredCertTemp, ops); err != nil {
		return fmt.Errorf("replace cert: %w", err)
	}
	if err := applyCertFileState(desired.key, &desiredKeyTemp, ops); err != nil {
		restoreErr := applyCertFileState(fallback.cert, &fallbackCertTemp, ops)
		if restoreErr != nil {
			return errors.Join(
				fmt.Errorf("replace key: %w", err),
				fmt.Errorf("restore cert after key replacement failure: %w", restoreErr),
			)
		}
		return fmt.Errorf("replace key: %w", err)
	}
	return nil
}

func stageCertFileState(state certFileState, ops certFileOps) (string, error) {
	if !state.exists {
		return "", nil
	}
	file, err := ops.createTemp(filepath.Dir(state.path), ".arcway-cert-"+filepath.Base(state.path)+"-*")
	if err != nil {
		return "", err
	}
	tempPath := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = file.Close()
			_ = ops.remove(tempPath)
		}
	}()
	if err := file.Chmod(state.mode.Perm()); err != nil {
		return "", err
	}
	written, err := file.Write(state.data)
	if err != nil {
		return "", err
	}
	if written != len(state.data) {
		return "", io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	cleanup = false
	return tempPath, nil
}

func applyCertFileState(state certFileState, stagedPath *string, ops certFileOps) error {
	if state.exists {
		if stagedPath == nil || *stagedPath == "" {
			return fmt.Errorf("staged file is unavailable for %s", state.path)
		}
		if err := ops.rename(*stagedPath, state.path); err != nil {
			return err
		}
		*stagedPath = ""
		return nil
	}
	if err := ops.remove(state.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func removeStagedCertFile(path *string, ops certFileOps) {
	if path != nil && *path != "" {
		_ = ops.remove(*path)
		*path = ""
	}
}

func rollbackCertDeploymentAfterReloadFailure(deployment *certFileDeployment, reloadErr error, recovery ...func() error) error {
	issues := []error{reloadErr}
	if rollbackErr := deployment.Rollback(); rollbackErr != nil {
		issues = append(issues, fmt.Errorf("restore previous certificate pair: %w", rollbackErr))
		return errors.Join(issues...)
	}
	for _, recoverService := range recovery {
		if recoverService == nil {
			continue
		}
		if recoveryErr := recoverService(); recoveryErr != nil {
			issues = append(issues, recoveryErr)
		}
	}
	return errors.Join(issues...)
}
