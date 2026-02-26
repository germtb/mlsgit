package test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/germtb/mlsgit/internal/config"
	"github.com/germtb/mlsgit/internal/crypto"
	"github.com/germtb/mlsgit/internal/delta"
	"github.com/germtb/mlsgit/internal/mls"
	"github.com/germtb/mlsgit/internal/storage"
)

var mlsgitBinary string

func TestMain(m *testing.M) {
	// Build the mlsgit binary
	tmp, err := os.MkdirTemp("", "mlsgit-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	mlsgitBinary = filepath.Join(tmp, "mlsgit")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", mlsgitBinary, "./cmd/mlsgit")
	cmd.Dir = findProjectRoot()
	cmd.Env = append(os.Environ(), "GOMODCACHE=/tmp/gomod", "GOPATH=/tmp/gopath")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %s\n%s\n", err, out)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func findProjectRoot() string {
	// Walk up from this test file to find go.mod
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

// --- Test helpers ---

// testEnv caches the environment for a single test to avoid creating
// a new HOME temp dir on every git/mlsgit invocation.
var testEnvCache = map[string][]string{}

func makeEnv(t *testing.T) []string {
	t.Helper()
	key := t.Name()
	if env, ok := testEnvCache[key]; ok {
		return env
	}
	// Create a single HOME dir for this test's lifetime
	tmpHome, err := os.MkdirTemp("", "mlsgit-home-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpHome) })

	env := []string{
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=t@t",
		"HOME=" + tmpHome,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GOMODCACHE=/tmp/gomod",
		"GOPATH=/tmp/gopath",
	}
	dir := filepath.Dir(mlsgitBinary)
	origPath := os.Getenv("PATH")
	env = append(env, "PATH="+dir+":"+origPath)
	testEnvCache[key] = env
	return env
}

func git(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	cmd.Env = makeEnv(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func gitNoCheck(t *testing.T, repo string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	cmd.Env = makeEnv(t)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mlsgitCmd(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command(mlsgitBinary, args...)
	cmd.Dir = repo
	cmd.Env = makeEnv(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mlsgit %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func initMLSGitRepo(t *testing.T, name string) string {
	t.Helper()
	repo := t.TempDir()
	git(t, repo, "init")
	git(t, repo, "config", "user.email", "test@test.com")
	git(t, repo, "config", "user.name", "Test User")

	mlsgitCmd(t, repo, "init", "--name", name)

	// Commit metadata
	git(t, repo, "add", ".mlsgit/", ".gitattributes", ".gitignore")
	git(t, repo, "commit", "-m", "init mlsgit")
	return repo
}

func writeFile(t *testing.T, repo, path, content string) {
	t.Helper()
	full := filepath.Join(repo, path)
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, repo, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo, path))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func gitBlob(t *testing.T, repo, ref, path string) string {
	t.Helper()
	return git(t, repo, "show", ref+":"+path)
}

func addFakeMember(t *testing.T, repo, memberName string) string {
	t.Helper()
	paths := storage.MLSGitPaths{Root: repo}

	// Generate keys and create pending request
	mlsKeys, _ := mls.GenerateMLSKeys()
	_, sigPub, _ := crypto.GenerateKeypair()
	pubPEM, _ := crypto.PublicKeyToPEM(sigPub)

	memberID := memberName + "-test-id"
	kp := mls.BuildKeyPackage([]byte(memberName), mlsKeys)
	kpBytes, _ := json.Marshal(kp)
	kpB64 := crypto.B64Encode(kpBytes, false)

	storage.WritePendingRequest(paths, memberID, memberName, pubPEM, kpB64)

	// Approve via CLI
	mlsgitCmd(t, repo, "add", memberID)
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "add member: "+memberName)
	return memberID
}

// --- Tests ---

func TestAddCommitCheckoutRoundtrip(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	secret := "This is top-secret data.\nDo not share.\n"
	writeFile(t, repo, "secret.txt", secret)

	git(t, repo, "add", "secret.txt")
	git(t, repo, "commit", "-m", "add secret")

	// Blob should be ciphertext
	blob := gitBlob(t, repo, "HEAD", "secret.txt")
	if blob == secret {
		t.Fatal("git blob should be ciphertext, not plaintext")
	}

	// Delete and checkout should decrypt
	os.Remove(filepath.Join(repo, "secret.txt"))
	git(t, repo, "checkout", "--", "secret.txt")

	got := readFile(t, repo, "secret.txt")
	if got != secret {
		t.Errorf("after checkout: %q, want %q", got, secret)
	}
}

func TestMultipleFiles(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	files := map[string]string{
		"readme.txt":       "This is the readme.\n",
		"src/main.py":      "print('hello')\n",
		"data/config.json": `{"key": "value"}` + "\n",
	}

	for path, content := range files {
		writeFile(t, repo, path, content)
	}
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "add files")

	for path, content := range files {
		blob := gitBlob(t, repo, "HEAD", path)
		if blob == content {
			t.Errorf("%s: blob should be ciphertext", path)
		}
	}

	// Delete all and checkout
	for path := range files {
		os.Remove(filepath.Join(repo, path))
	}
	git(t, repo, "checkout", "--", ".")

	for path, content := range files {
		got := readFile(t, repo, path)
		if got != content {
			t.Errorf("%s: got %q, want %q", path, got, content)
		}
	}
}

func TestEditCreatesDelta(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	writeFile(t, repo, "evolving.txt", "version 1\n")
	git(t, repo, "add", "evolving.txt")
	git(t, repo, "commit", "-m", "v1")

	blob1 := gitBlob(t, repo, "HEAD", "evolving.txt")
	if delta.CountDeltas(blob1) != 0 {
		t.Errorf("v1 should have 0 deltas, got %d", delta.CountDeltas(blob1))
	}

	writeFile(t, repo, "evolving.txt", "version 2\n")
	git(t, repo, "add", "evolving.txt")
	git(t, repo, "commit", "-m", "v2")

	blob2 := gitBlob(t, repo, "HEAD", "evolving.txt")
	if delta.CountDeltas(blob2) != 1 {
		t.Errorf("v2 should have 1 delta, got %d", delta.CountDeltas(blob2))
	}
}

func TestNoSpuriousDiffs(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	writeFile(t, repo, "stable.txt", "content\n")
	git(t, repo, "add", "stable.txt")
	git(t, repo, "commit", "-m", "add stable")

	// Re-add same content
	git(t, repo, "add", "stable.txt")
	status := git(t, repo, "status", "--porcelain")
	if strings.TrimSpace(status) != "" {
		t.Errorf("expected clean status, got: %q", status)
	}
}

func TestMLSGitDirNotEncrypted(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	// .mlsgit/config.toml should be readable plaintext in the blob
	blob := gitBlob(t, repo, "HEAD", ".mlsgit/config.toml")
	if !strings.Contains(blob, "version") {
		t.Error("config.toml blob should be plaintext")
	}
}

func TestUnicodeContent(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	content := "Hello \u4e16\u754c\nEmoji: \U0001F600\n"
	writeFile(t, repo, "unicode.txt", content)
	git(t, repo, "add", "unicode.txt")
	git(t, repo, "commit", "-m", "unicode")

	os.Remove(filepath.Join(repo, "unicode.txt"))
	git(t, repo, "checkout", "--", "unicode.txt")

	got := readFile(t, repo, "unicode.txt")
	if got != content {
		t.Errorf("unicode: got %q, want %q", got, content)
	}
}

func TestLargeFile(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	content := strings.Repeat("A", 100000) + "\n"
	writeFile(t, repo, "large.txt", content)
	git(t, repo, "add", "large.txt")
	git(t, repo, "commit", "-m", "large file")

	os.Remove(filepath.Join(repo, "large.txt"))
	git(t, repo, "checkout", "--", "large.txt")

	got := readFile(t, repo, "large.txt")
	if got != content {
		t.Error("large file content mismatch")
	}
}

func TestMultipleSequentialEdits(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	for i := 1; i <= 9; i++ {
		content := fmt.Sprintf("version %d\n", i)
		writeFile(t, repo, "evolving.txt", content)
		git(t, repo, "add", "evolving.txt")
		git(t, repo, "commit", "-m", fmt.Sprintf("v%d", i))
	}

	// Current version should be correct
	got := readFile(t, repo, "evolving.txt")
	if got != "version 9\n" {
		t.Errorf("current version: %q, want %q", got, "version 9\n")
	}
}

func TestBranchAndMerge(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	writeFile(t, repo, "main.txt", "main content\n")
	git(t, repo, "add", "main.txt")
	git(t, repo, "commit", "-m", "main file")

	// Create branch
	git(t, repo, "checkout", "-b", "feature")
	writeFile(t, repo, "feature.txt", "feature content\n")
	git(t, repo, "add", "feature.txt")
	git(t, repo, "commit", "-m", "feature file")

	// Switch back to main
	git(t, repo, "checkout", "master")
	if _, err := os.Stat(filepath.Join(repo, "feature.txt")); err == nil {
		t.Error("feature.txt should not exist on master")
	}

	// Merge
	git(t, repo, "merge", "feature")
	got := readFile(t, repo, "feature.txt")
	if got != "feature content\n" {
		t.Errorf("after merge: %q, want %q", got, "feature content\n")
	}
}

func TestEpochKeyPreservation(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	// Create file at epoch 0
	writeFile(t, repo, "epoch0.txt", "created at epoch 0\n")
	git(t, repo, "add", "epoch0.txt")
	git(t, repo, "commit", "-m", "epoch 0 file")

	// Add a fake member (advances epoch)
	addFakeMember(t, repo, "bob")

	// File should still be decryptable
	os.Remove(filepath.Join(repo, "epoch0.txt"))
	git(t, repo, "checkout", "--", "epoch0.txt")

	got := readFile(t, repo, "epoch0.txt")
	if got != "created at epoch 0\n" {
		t.Errorf("epoch 0 file: %q, want %q", got, "created at epoch 0\n")
	}
}

func TestEmptyFile(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	writeFile(t, repo, "empty.txt", "")
	git(t, repo, "add", "empty.txt")
	git(t, repo, "commit", "-m", "empty file")

	os.Remove(filepath.Join(repo, "empty.txt"))
	git(t, repo, "checkout", "--", "empty.txt")

	got := readFile(t, repo, "empty.txt")
	if got != "" {
		t.Errorf("empty file: %q, want empty", got)
	}
}

func TestOnlyNewlines(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	content := "\n\n\n"
	writeFile(t, repo, "newlines.txt", content)
	git(t, repo, "add", "newlines.txt")
	git(t, repo, "commit", "-m", "newlines")

	os.Remove(filepath.Join(repo, "newlines.txt"))
	git(t, repo, "checkout", "--", "newlines.txt")

	got := readFile(t, repo, "newlines.txt")
	if got != content {
		t.Errorf("newlines: %q, want %q", got, content)
	}
}

func TestSeparatorInContent(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	// Content containing the delta separator
	content := "before" + config.DeltaSeparator + "after\n"
	writeFile(t, repo, "separator.txt", content)
	git(t, repo, "add", "separator.txt")
	git(t, repo, "commit", "-m", "separator")

	os.Remove(filepath.Join(repo, "separator.txt"))
	git(t, repo, "checkout", "--", "separator.txt")

	got := readFile(t, repo, "separator.txt")
	if got != content {
		t.Errorf("separator: %q, want %q", got, content)
	}
}

func TestStashAndPop(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	writeFile(t, repo, "file.txt", "committed\n")
	git(t, repo, "add", "file.txt")
	git(t, repo, "commit", "-m", "initial")

	// Make a change and stash
	writeFile(t, repo, "file.txt", "modified\n")
	git(t, repo, "stash")

	got := readFile(t, repo, "file.txt")
	if got != "committed\n" {
		t.Errorf("after stash: %q, want %q", got, "committed\n")
	}

	// Pop stash
	git(t, repo, "stash", "pop")
	got = readFile(t, repo, "file.txt")
	if got != "modified\n" {
		t.Errorf("after pop: %q, want %q", got, "modified\n")
	}
}

func TestResetHard(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	writeFile(t, repo, "file.txt", "original\n")
	git(t, repo, "add", "file.txt")
	git(t, repo, "commit", "-m", "original")

	writeFile(t, repo, "file.txt", "changed\n")
	git(t, repo, "add", "file.txt")
	git(t, repo, "commit", "-m", "changed")

	git(t, repo, "reset", "--hard", "HEAD~1")
	got := readFile(t, repo, "file.txt")
	if got != "original\n" {
		t.Errorf("after reset: %q, want %q", got, "original\n")
	}
}

func TestFileRemoveRecreate(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	writeFile(t, repo, "file.txt", "original\n")
	git(t, repo, "add", "file.txt")
	git(t, repo, "commit", "-m", "add file")

	// Remove
	git(t, repo, "rm", "file.txt")
	git(t, repo, "commit", "-m", "remove file")

	// Recreate
	writeFile(t, repo, "file.txt", "recreated\n")
	git(t, repo, "add", "file.txt")
	git(t, repo, "commit", "-m", "recreate file")

	got := readFile(t, repo, "file.txt")
	if got != "recreated\n" {
		t.Errorf("recreated: %q, want %q", got, "recreated\n")
	}
}

func TestCacheWipeReAdd(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	writeFile(t, repo, "file.txt", "cached content\n")
	git(t, repo, "add", "file.txt")
	git(t, repo, "commit", "-m", "add file")

	// Wipe cache
	paths := storage.MLSGitPaths{Root: repo}
	cache := storage.NewFilterCache(paths)
	cache.InvalidateAll()

	// Re-add same content (should still work, just creates a new base block)
	writeFile(t, repo, "file.txt", "cached content\n")
	git(t, repo, "add", "file.txt")
	git(t, repo, "commit", "-m", "re-add after cache wipe")

	os.Remove(filepath.Join(repo, "file.txt"))
	git(t, repo, "checkout", "--", "file.txt")

	got := readFile(t, repo, "file.txt")
	if got != "cached content\n" {
		t.Errorf("after cache wipe: %q, want %q", got, "cached content\n")
	}
}

func TestNestedPaths(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	writeFile(t, repo, "a/b/c/deep.txt", "deeply nested\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "nested file")

	os.Remove(filepath.Join(repo, "a/b/c/deep.txt"))
	git(t, repo, "checkout", "--", ".")

	got := readFile(t, repo, "a/b/c/deep.txt")
	if got != "deeply nested\n" {
		t.Errorf("nested: %q, want %q", got, "deeply nested\n")
	}
}

func TestLsMembers(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")
	out := mlsgitCmd(t, repo, "ls")
	if !strings.Contains(out, "alice") {
		t.Errorf("ls should show alice: %s", out)
	}
}

func TestReviewNoPending(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")
	out := mlsgitCmd(t, repo, "review")
	if !strings.Contains(out, "No pending") {
		t.Errorf("review should show no pending: %s", out)
	}
}
