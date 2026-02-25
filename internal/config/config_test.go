package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindGitRoot(t *testing.T) {
	// Create a temp dir with a .git directory
	tmp := t.TempDir()
	gitDir := filepath.Join(tmp, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a subdirectory
	sub := filepath.Join(tmp, "a", "b", "c")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	root, err := FindGitRoot(sub)
	if err != nil {
		t.Fatalf("FindGitRoot(%q) error: %v", sub, err)
	}
	if root != tmp {
		t.Errorf("FindGitRoot(%q) = %q, want %q", sub, root, tmp)
	}
}

func TestFindGitRootNotFound(t *testing.T) {
	tmp := t.TempDir()
	_, err := FindGitRoot(tmp)
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
}

func TestMLSGitConfigRoundtrip(t *testing.T) {
	cfg := DefaultConfig()
	text := cfg.ToTOML()

	parsed, err := ConfigFromTOML(text)
	if err != nil {
		t.Fatalf("ConfigFromTOML error: %v", err)
	}

	if parsed.Version != cfg.Version {
		t.Errorf("Version = %q, want %q", parsed.Version, cfg.Version)
	}
	if parsed.CipherSuite != cfg.CipherSuite {
		t.Errorf("CipherSuite = %d, want %d", parsed.CipherSuite, cfg.CipherSuite)
	}
	if parsed.CompactionThreshold != cfg.CompactionThreshold {
		t.Errorf("CompactionThreshold = %d, want %d", parsed.CompactionThreshold, cfg.CompactionThreshold)
	}
}

func TestMLSGitConfigToTOMLFormat(t *testing.T) {
	cfg := DefaultConfig()
	text := cfg.ToTOML()

	// Must match Python output format
	expected := "[mlsgit]\nversion = \"0.1.0\"\ncipher_suite = 1\ncompaction_threshold = 50\n"
	if text != expected {
		t.Errorf("ToTOML():\n got: %q\nwant: %q", text, expected)
	}
}

func TestConfigFromTOMLPythonOutput(t *testing.T) {
	// Parse what Python generates
	pythonTOML := `[mlsgit]
version = "0.1.0"
cipher_suite = 1
compaction_threshold = 50
`
	cfg, err := ConfigFromTOML(pythonTOML)
	if err != nil {
		t.Fatalf("ConfigFromTOML error: %v", err)
	}
	if cfg.Version != "0.1.0" {
		t.Errorf("Version = %q, want %q", cfg.Version, "0.1.0")
	}
	if cfg.CipherSuite != 1 {
		t.Errorf("CipherSuite = %d, want %d", cfg.CipherSuite, 1)
	}
	if cfg.CompactionThreshold != 50 {
		t.Errorf("CompactionThreshold = %d, want %d", cfg.CompactionThreshold, 50)
	}
}
