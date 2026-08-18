package capture

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func validateResultPath(captureDir, resultPath string) (string, error) {
	if captureDir == "" {
		return "", errors.New("capture directory is required")
	}
	if resultPath == "-" {
		return resultPath, nil
	}
	absResult, err := filepath.Abs(resultPath)
	if err != nil {
		return "", fmt.Errorf("resolving result path: %w", err)
	}
	resolvedCapture, err := resolveProspectivePath(captureDir)
	if err != nil {
		return "", fmt.Errorf("resolving capture directory: %w", err)
	}
	resolvedResult, err := resolveProspectivePath(resultPath)
	if err != nil {
		return "", fmt.Errorf("resolving result path: %w", err)
	}
	inside, err := pathWithin(resolvedCapture, resolvedResult)
	if err != nil {
		return "", err
	}
	if inside {
		return "", errors.New("result path must be outside the capture directory")
	}
	return filepath.Clean(absResult), nil
}

func validateProviderRootPath(captureDir, providerRoot string) error {
	resolvedCapture, err := resolveProspectivePath(captureDir)
	if err != nil {
		return fmt.Errorf("resolving capture directory: %w", err)
	}
	resolvedRoot, err := resolveProspectivePath(providerRoot)
	if err != nil {
		return fmt.Errorf("resolving provider root: %w", err)
	}
	inside, err := pathWithin(resolvedCapture, resolvedRoot)
	if err != nil {
		return err
	}
	if inside {
		return errors.New("provider root must be outside the capture directory")
	}
	return nil
}

func writeCaptureResult(
	state *captureState,
	resultPath string,
	stdout ioWriter,
	data []byte,
) error {
	validated, err := validateResultPath(state.dir, resultPath)
	if err != nil {
		return err
	}
	return writeResult(validated, stdout, data)
}

func resolveProspectivePath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := absPath
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for _, part := range slices.Backward(suffix) {
				resolved = filepath.Join(resolved, part)
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Clean(absPath), nil
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func pathWithin(parent, candidate string) (bool, error) {
	relative, err := filepath.Rel(parent, candidate)
	if err != nil {
		return false, fmt.Errorf("comparing paths: %w", err)
	}
	return relative == "." || relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator)), nil
}
