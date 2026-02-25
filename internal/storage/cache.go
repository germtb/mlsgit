package storage

import (
	"os"
	"path/filepath"
)

// FilterCache manages the plaintext/ciphertext cache under .git/mlsgit/cache/.
type FilterCache struct {
	paths MLSGitPaths
}

// NewFilterCache creates a new FilterCache.
func NewFilterCache(paths MLSGitPaths) *FilterCache {
	return &FilterCache{paths: paths}
}

func ensureParent(p string) error {
	return os.MkdirAll(filepath.Dir(p), 0o755)
}

// GetPlaintext returns cached plaintext for filePath, or nil if not cached.
func (c *FilterCache) GetPlaintext(filePath string) []byte {
	p := c.paths.CachePlain(filePath)
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return data
}

// GetCiphertext returns cached ciphertext for filePath, or empty string if not cached.
func (c *FilterCache) GetCiphertext(filePath string) (string, bool) {
	p := c.paths.CacheCT(filePath)
	data, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return string(data), true
}

// Put stores both plaintext and ciphertext in the cache.
func (c *FilterCache) Put(filePath string, plaintext []byte, ciphertext string) error {
	plainP := c.paths.CachePlain(filePath)
	ctP := c.paths.CacheCT(filePath)

	if err := ensureParent(plainP); err != nil {
		return err
	}
	if err := ensureParent(ctP); err != nil {
		return err
	}
	if err := os.WriteFile(plainP, plaintext, 0o644); err != nil {
		return err
	}
	return os.WriteFile(ctP, []byte(ciphertext), 0o644)
}

// InvalidateAll removes all cached entries.
func (c *FilterCache) InvalidateAll() error {
	cacheDir := c.paths.CacheDir()
	if err := os.RemoveAll(cacheDir); err != nil {
		return err
	}
	return os.MkdirAll(cacheDir, 0o755)
}
