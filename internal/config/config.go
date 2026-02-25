// Package config provides constants, configuration management, and path helpers for mlsgit.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

const (
	// DeltaSeparator separates blocks in a ciphertext delta chain.
	DeltaSeparator = "\n---MLSGIT-DELTA---\n"

	// DefaultCompactionThreshold is the number of deltas before compaction.
	DefaultCompactionThreshold = 50

	// MLSCiphersuiteID is MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
	MLSCiphersuiteID = 0x0001

	// Version is the mlsgit version string.
	Version = "0.1.0"
)

// FindGitRoot walks up from start (or cwd) until a .git directory is found.
func FindGitRoot(start string) (string, error) {
	if start == "" {
		var err error
		start, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("cannot get working directory: %w", err)
		}
	}
	p, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		info, err := os.Stat(filepath.Join(p, ".git"))
		if err == nil && info.IsDir() {
			return p, nil
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", fmt.Errorf("not inside a git repository")
		}
		p = parent
	}
}

// MLSGitConfig holds runtime configuration from .mlsgit/config.toml.
type MLSGitConfig struct {
	Version              string `toml:"version"`
	CipherSuite          int    `toml:"cipher_suite"`
	CompactionThreshold  int    `toml:"compaction_threshold"`
}

// DefaultConfig returns a config with default values.
func DefaultConfig() MLSGitConfig {
	return MLSGitConfig{
		Version:             Version,
		CipherSuite:         MLSCiphersuiteID,
		CompactionThreshold: DefaultCompactionThreshold,
	}
}

// tomlConfig is the TOML wrapper for serialization.
type tomlConfig struct {
	MLSGit MLSGitConfig `toml:"mlsgit"`
}

// ToTOML serializes the config to TOML format matching the Python output.
func (c MLSGitConfig) ToTOML() string {
	return fmt.Sprintf("[mlsgit]\nversion = %q\ncipher_suite = %d\ncompaction_threshold = %d\n",
		c.Version, c.CipherSuite, c.CompactionThreshold)
}

// ConfigFromTOML parses a config from TOML text.
func ConfigFromTOML(text string) (MLSGitConfig, error) {
	var wrapper tomlConfig
	if _, err := toml.Decode(text, &wrapper); err != nil {
		return MLSGitConfig{}, fmt.Errorf("parsing config TOML: %w", err)
	}
	cfg := DefaultConfig()
	m := wrapper.MLSGit
	if m.Version != "" {
		cfg.Version = m.Version
	}
	if m.CipherSuite != 0 {
		cfg.CipherSuite = m.CipherSuite
	}
	if m.CompactionThreshold != 0 {
		cfg.CompactionThreshold = m.CompactionThreshold
	}
	return cfg, nil
}
