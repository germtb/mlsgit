// Package storage provides filesystem I/O for .mlsgit/ and .git/mlsgit/.
package storage

import (
	"os"
	"path/filepath"
)

// MLSGitPaths contains all well-known paths derived from the git root.
type MLSGitPaths struct {
	Root string
}

// -- committed (.mlsgit/) --

func (p MLSGitPaths) MLSGitDir() string          { return filepath.Join(p.Root, ".mlsgit") }
func (p MLSGitPaths) ConfigTOML() string          { return filepath.Join(p.MLSGitDir(), "config.toml") }
func (p MLSGitPaths) EpochTOML() string           { return filepath.Join(p.MLSGitDir(), "epoch.toml") }
func (p MLSGitPaths) MembersDir() string          { return filepath.Join(p.MLSGitDir(), "members") }
func (p MLSGitPaths) PendingDir() string          { return filepath.Join(p.MLSGitDir(), "pending") }
func (p MLSGitPaths) GroupDir() string            { return filepath.Join(p.MLSGitDir(), "group") }
func (p MLSGitPaths) GroupState() string          { return filepath.Join(p.GroupDir(), "state.b64") }
func (p MLSGitPaths) WelcomeDir() string          { return filepath.Join(p.GroupDir(), "welcome") }
func (p MLSGitPaths) EpochKeys() string           { return filepath.Join(p.MLSGitDir(), "epoch_keys.b64") }
func (p MLSGitPaths) MerkleTOML() string          { return filepath.Join(p.MLSGitDir(), "merkle.toml") }
func (p MLSGitPaths) MLSGitGitattributes() string { return filepath.Join(p.MLSGitDir(), ".gitattributes") }

// -- local (.git/mlsgit/) --

func (p MLSGitPaths) LocalDir() string     { return filepath.Join(p.Root, ".git", "mlsgit") }
func (p MLSGitPaths) PrivateKey() string   { return filepath.Join(p.LocalDir(), "private_key.pem") }
func (p MLSGitPaths) MLSState() string     { return filepath.Join(p.LocalDir(), "mls_state.bin") }
func (p MLSGitPaths) IdentityTOML() string { return filepath.Join(p.LocalDir(), "identity.toml") }
func (p MLSGitPaths) CacheDir() string     { return filepath.Join(p.LocalDir(), "cache") }

// -- repo-level files --

func (p MLSGitPaths) RootGitattributes() string { return filepath.Join(p.Root, ".gitattributes") }
func (p MLSGitPaths) Gitignore() string          { return filepath.Join(p.Root, ".gitignore") }

// -- helpers --

func (p MLSGitPaths) CachePlain(filePath string) string {
	return filepath.Join(p.CacheDir(), filePath+".plain")
}

func (p MLSGitPaths) CacheCT(filePath string) string {
	return filepath.Join(p.CacheDir(), filePath+".ct")
}

func (p MLSGitPaths) MemberTOML(memberID string) string {
	return filepath.Join(p.MembersDir(), memberID+".toml")
}

func (p MLSGitPaths) MemberKeypackage(memberID string) string {
	return filepath.Join(p.MembersDir(), memberID+".keypackage.b64")
}

func (p MLSGitPaths) PendingRequest(memberID string) string {
	return filepath.Join(p.PendingDir(), memberID+".request.toml")
}

func (p MLSGitPaths) WelcomeFile(memberID string) string {
	return filepath.Join(p.WelcomeDir(), memberID+".welcome.b64")
}

// EnsureDirs creates all required directories (idempotent).
func (p MLSGitPaths) EnsureDirs() error {
	dirs := []string{
		p.MLSGitDir(),
		p.MembersDir(),
		p.PendingDir(),
		p.GroupDir(),
		p.WelcomeDir(),
		p.LocalDir(),
		p.CacheDir(),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}
