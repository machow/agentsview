package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.kenn.io/agentsview/internal/pathutil"
)

const maxCaptureConfigBytes = 2 << 20

// CaptureConfig is the intentionally narrow configuration surface used by
// one-shot automation. It contains no archive, server, transport, credential,
// daemon, or runtime-record settings.
type CaptureConfig struct {
	CustomModelPricing map[string]CustomModelRate
}

// LoadCapture reads only custom pricing from the normal read-only config
// location. It does not construct a Config or resolve any archive backend.
func LoadCapture() (CaptureConfig, error) {
	dataDir := dataDirFromEnv()
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return CaptureConfig{}, fmt.Errorf("determining home directory: %w", err)
		}
		dataDir = filepath.Join(home, ".agentsview")
	}
	dataDir, err := pathutil.ExpandHome(dataDir)
	if err != nil {
		return CaptureConfig{}, fmt.Errorf("locating capture pricing config: %w", err)
	}
	path := filepath.Join(dataDir, "config.toml")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return CaptureConfig{}, nil
	}
	if err != nil {
		return CaptureConfig{}, fmt.Errorf("opening capture pricing config: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return CaptureConfig{}, fmt.Errorf("checking capture pricing config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxCaptureConfigBytes {
		return CaptureConfig{}, errors.New("capture pricing config is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCaptureConfigBytes+1))
	if err != nil {
		return CaptureConfig{}, fmt.Errorf("reading capture pricing config: %w", err)
	}
	if len(data) > maxCaptureConfigBytes {
		return CaptureConfig{}, errors.New("capture pricing config exceeds byte limit")
	}
	customModelPricing, err := decodeCustomModelPricing(string(data))
	if err != nil {
		return CaptureConfig{}, err
	}
	return CaptureConfig{CustomModelPricing: customModelPricing}, nil
}
