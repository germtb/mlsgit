package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/germtb/mlsgit/internal/storage"
)

// --- Multi-user test helpers ---

func mlsgitCmdExpectError(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command(mlsgitBinary, args...)
	cmd.Dir = repo
	cmd.Env = makeEnv(t)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("mlsgit %s expected to fail but succeeded:\n%s", strings.Join(args, " "), out)
	}
	return string(out)
}

func createBareRepo(t *testing.T) string {
	t.Helper()
	bare := filepath.Join(t.TempDir(), "bare.git")
	cmd := exec.Command("git", "init", "--bare", bare)
	cmd.Env = makeEnv(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git init --bare failed: %v\n%s", err, out)
	}
	return bare
}

func gitClone(t *testing.T, src, dst string) {
	t.Helper()
	cmd := exec.Command("git", "clone", src, dst)
	cmd.Env = makeEnv(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone %s -> %s failed: %v\n%s", src, dst, err, out)
	}
}

func getMemberID(t *testing.T, repo string) string {
	t.Helper()
	paths := storage.MLSGitPaths{Root: repo}
	id, _, err := storage.ReadIdentity(paths)
	if err != nil {
		t.Fatalf("read identity from %s: %v", repo, err)
	}
	return id
}

// setupTwoUsers creates a full two-user setup:
//  1. Creates a bare repo (remote)
//  2. Alice: git init + mlsgit init + creates aliceFiles + pushes
//  3. Bob: clones, runs mlsgit join, pushes pending request
//  4. Alice: pulls, runs mlsgit add, pushes
//  5. Bob: pulls, runs mlsgit join (processes welcome, decrypts files)
//
// Returns (bare, aliceRepo, bobRepo, aliceID, bobID).
func setupTwoUsers(t *testing.T, aliceFiles map[string]string) (bare, aliceRepo, bobRepo, aliceID, bobID string) {
	t.Helper()

	bare = createBareRepo(t)

	// Alice: init repo + mlsgit init
	aliceRepo = t.TempDir()
	git(t, aliceRepo, "init")
	git(t, aliceRepo, "config", "user.email", "alice@test.com")
	git(t, aliceRepo, "config", "user.name", "Alice")
	git(t, aliceRepo, "config", "pull.rebase", "false")

	mlsgitCmd(t, aliceRepo, "init", "--name", "alice")
	git(t, aliceRepo, "add", ".")
	git(t, aliceRepo, "commit", "-m", "init mlsgit")

	// Create Alice's files (encrypted at epoch 0)
	if len(aliceFiles) > 0 {
		for path, content := range aliceFiles {
			writeFile(t, aliceRepo, path, content)
		}
		git(t, aliceRepo, "add", ".")
		git(t, aliceRepo, "commit", "-m", "add files")
	}

	git(t, aliceRepo, "remote", "add", "origin", bare)
	git(t, aliceRepo, "push", "-u", "origin", "master")

	// Bob: clone
	bobRepo = filepath.Join(t.TempDir(), "bob")
	gitClone(t, bare, bobRepo)
	git(t, bobRepo, "config", "user.email", "bob@test.com")
	git(t, bobRepo, "config", "user.name", "Bob")
	git(t, bobRepo, "config", "pull.rebase", "false")

	// Bob: mlsgit join (creates pending request + installs filter)
	mlsgitCmd(t, bobRepo, "join", "--name", "bob")
	git(t, bobRepo, "add", ".mlsgit/pending/")
	git(t, bobRepo, "commit", "-m", "request to join: bob")
	git(t, bobRepo, "push")

	// Alice: pull + approve Bob
	git(t, aliceRepo, "pull", "--no-edit")
	bobID = getMemberID(t, bobRepo)
	mlsgitCmd(t, aliceRepo, "add", bobID)
	git(t, aliceRepo, "add", ".")
	git(t, aliceRepo, "commit", "-m", "add bob")
	git(t, aliceRepo, "push")

	// Bob: pull + process welcome (decrypts working tree)
	git(t, bobRepo, "pull", "--no-edit")
	mlsgitCmd(t, bobRepo, "join")

	aliceID = getMemberID(t, aliceRepo)
	return
}

// ========================================================================
// Happy path tests
// ========================================================================

func TestTwoUserJoinAndEncryptDecrypt(t *testing.T) {
	_, aliceRepo, bobRepo, _, _ := setupTwoUsers(t, nil)

	// Alice creates a file (encrypted at current epoch)
	writeFile(t, aliceRepo, "secret.txt", "alice's secret\n")
	git(t, aliceRepo, "add", "secret.txt")
	git(t, aliceRepo, "commit", "-m", "add secret")
	git(t, aliceRepo, "push")

	// Bob pulls and reads — smudge filter should decrypt
	git(t, bobRepo, "pull", "--no-edit")
	got := readFile(t, bobRepo, "secret.txt")
	if got != "alice's secret\n" {
		t.Errorf("bob reads alice's file: %q, want %q", got, "alice's secret\n")
	}

	// Bob creates a file
	writeFile(t, bobRepo, "bob.txt", "bob's data\n")
	git(t, bobRepo, "add", "bob.txt")
	git(t, bobRepo, "commit", "-m", "add bob file")
	git(t, bobRepo, "push")

	// Alice pulls and reads
	git(t, aliceRepo, "pull", "--no-edit")
	got = readFile(t, aliceRepo, "bob.txt")
	if got != "bob's data\n" {
		t.Errorf("alice reads bob's file: %q, want %q", got, "bob's data\n")
	}

	// Verify blobs are ciphertext (not plaintext)
	blob := gitBlob(t, aliceRepo, "HEAD", "secret.txt")
	if blob == "alice's secret\n" {
		t.Error("secret.txt blob should be ciphertext")
	}
	blob = gitBlob(t, bobRepo, "HEAD", "bob.txt")
	if blob == "bob's data\n" {
		t.Error("bob.txt blob should be ciphertext")
	}
}

func TestNewMemberReadsExistingFiles(t *testing.T) {
	files := map[string]string{
		"readme.txt":  "project readme\n",
		"src/main.go": "package main\n",
		"data.json":   `{"key": "value"}` + "\n",
	}
	_, _, bobRepo, _, _ := setupTwoUsers(t, files)

	// Bob should be able to read all of Alice's pre-existing files
	for path, want := range files {
		got := readFile(t, bobRepo, path)
		if got != want {
			t.Errorf("%s: bob got %q, want %q", path, got, want)
		}
	}
}

func TestThreeUserWorkflow(t *testing.T) {
	bare, aliceRepo, bobRepo, _, _ := setupTwoUsers(t, map[string]string{
		"shared.txt": "shared content\n",
	})

	// Charlie clones
	charlieRepo := filepath.Join(t.TempDir(), "charlie")
	gitClone(t, bare, charlieRepo)
	git(t, charlieRepo, "config", "user.email", "charlie@test.com")
	git(t, charlieRepo, "config", "user.name", "Charlie")
	git(t, charlieRepo, "config", "pull.rebase", "false")

	// Charlie joins
	mlsgitCmd(t, charlieRepo, "join", "--name", "charlie")
	git(t, charlieRepo, "add", ".mlsgit/pending/")
	git(t, charlieRepo, "commit", "-m", "request to join: charlie")
	git(t, charlieRepo, "push")

	// Alice pulls and adds Charlie
	git(t, aliceRepo, "pull", "--no-edit")
	charlieID := getMemberID(t, charlieRepo)
	mlsgitCmd(t, aliceRepo, "add", charlieID)
	git(t, aliceRepo, "add", ".")
	git(t, aliceRepo, "commit", "-m", "add charlie")
	git(t, aliceRepo, "push")

	// Charlie pulls and processes welcome
	git(t, charlieRepo, "pull", "--no-edit")
	mlsgitCmd(t, charlieRepo, "join")

	// Charlie should be able to read the shared file (encrypted at epoch 0)
	got := readFile(t, charlieRepo, "shared.txt")
	if got != "shared content\n" {
		t.Errorf("charlie reads shared.txt: %q, want %q", got, "shared content\n")
	}

	// Bob pulls to sync with the latest state (epoch 2)
	git(t, bobRepo, "pull", "--no-edit")

	// Bob should still be able to read the shared file
	got = readFile(t, bobRepo, "shared.txt")
	if got != "shared content\n" {
		t.Errorf("bob reads shared.txt after charlie joined: %q, want %q", got, "shared content\n")
	}

	// Verify ls shows 3 members
	out := mlsgitCmd(t, aliceRepo, "ls")
	if !strings.Contains(out, "alice") || !strings.Contains(out, "bob") || !strings.Contains(out, "charlie") {
		t.Errorf("ls should show all 3 members:\n%s", out)
	}
}

func TestMemberRemoval(t *testing.T) {
	_, aliceRepo, _, _, bobID := setupTwoUsers(t, nil)

	// Record epoch before removal
	outBefore := mlsgitCmd(t, aliceRepo, "ls")

	// Alice removes Bob
	mlsgitCmd(t, aliceRepo, "remove", bobID)
	git(t, aliceRepo, "add", ".")
	git(t, aliceRepo, "commit", "-m", "remove bob")

	// Bob should no longer appear in ls
	outAfter := mlsgitCmd(t, aliceRepo, "ls")
	if strings.Contains(outAfter, "bob") {
		t.Errorf("ls should not show bob after removal:\nbefore: %s\nafter: %s", outBefore, outAfter)
	}
	if !strings.Contains(outAfter, "alice") {
		t.Error("ls should still show alice after removal")
	}

	// Alice can still encrypt/decrypt
	writeFile(t, aliceRepo, "post-removal.txt", "after bob left\n")
	git(t, aliceRepo, "add", "post-removal.txt")
	git(t, aliceRepo, "commit", "-m", "add post-removal file")

	os.Remove(filepath.Join(aliceRepo, "post-removal.txt"))
	git(t, aliceRepo, "checkout", "--", "post-removal.txt")
	got := readFile(t, aliceRepo, "post-removal.txt")
	if got != "after bob left\n" {
		t.Errorf("post-removal file: %q, want %q", got, "after bob left\n")
	}
}

func TestSealAndVerify(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	// Create some encrypted files
	writeFile(t, repo, "secret.txt", "secret data\n")
	writeFile(t, repo, "src/code.go", "package main\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "add files")

	// Seal: compute Merkle root and sign
	sealOut := mlsgitCmd(t, repo, "seal")
	if !strings.Contains(sealOut, "Merkle root:") {
		t.Errorf("seal output should contain Merkle root:\n%s", sealOut)
	}
	if !strings.Contains(sealOut, "Signed by:") {
		t.Errorf("seal output should contain Signed by:\n%s", sealOut)
	}

	// Verify: check root and signature
	verifyOut := mlsgitCmd(t, repo, "verify")
	if !strings.Contains(verifyOut, "OK") {
		t.Errorf("verify should pass:\n%s", verifyOut)
	}
}

func TestMultiUserLs(t *testing.T) {
	_, aliceRepo, _, _, _ := setupTwoUsers(t, nil)

	out := mlsgitCmd(t, aliceRepo, "ls")
	if !strings.Contains(out, "alice") {
		t.Errorf("ls should show alice:\n%s", out)
	}
	if !strings.Contains(out, "bob") {
		t.Errorf("ls should show bob:\n%s", out)
	}
}

func TestMultiUserReview(t *testing.T) {
	bare := createBareRepo(t)

	// Alice: init and push
	aliceRepo := t.TempDir()
	git(t, aliceRepo, "init")
	git(t, aliceRepo, "config", "user.email", "alice@test.com")
	git(t, aliceRepo, "config", "user.name", "Alice")
	git(t, aliceRepo, "config", "pull.rebase", "false")
	mlsgitCmd(t, aliceRepo, "init", "--name", "alice")
	git(t, aliceRepo, "add", ".")
	git(t, aliceRepo, "commit", "-m", "init mlsgit")
	git(t, aliceRepo, "remote", "add", "origin", bare)
	git(t, aliceRepo, "push", "-u", "origin", "master")

	// Bob: clone and join
	bobRepo := filepath.Join(t.TempDir(), "bob")
	gitClone(t, bare, bobRepo)
	git(t, bobRepo, "config", "user.email", "bob@test.com")
	git(t, bobRepo, "config", "user.name", "Bob")
	mlsgitCmd(t, bobRepo, "join", "--name", "bob")
	git(t, bobRepo, "add", ".mlsgit/pending/")
	git(t, bobRepo, "commit", "-m", "request to join: bob")
	git(t, bobRepo, "push")

	// Alice: pull and review
	git(t, aliceRepo, "pull", "--no-edit")
	out := mlsgitCmd(t, aliceRepo, "review")
	if !strings.Contains(out, "bob") {
		t.Errorf("review should show bob's pending request:\n%s", out)
	}
}

func TestBothUsersEditSameFile(t *testing.T) {
	_, aliceRepo, bobRepo, _, _ := setupTwoUsers(t, map[string]string{
		"shared.txt": "original content\n",
	})

	// Alice edits the file
	writeFile(t, aliceRepo, "shared.txt", "alice edited\n")
	git(t, aliceRepo, "add", "shared.txt")
	git(t, aliceRepo, "commit", "-m", "alice edits shared")
	git(t, aliceRepo, "push")

	// Bob pulls and reads
	git(t, bobRepo, "pull", "--no-edit")
	got := readFile(t, bobRepo, "shared.txt")
	if got != "alice edited\n" {
		t.Errorf("bob reads after alice edit: %q, want %q", got, "alice edited\n")
	}

	// Bob edits the same file
	writeFile(t, bobRepo, "shared.txt", "bob edited\n")
	git(t, bobRepo, "add", "shared.txt")
	git(t, bobRepo, "commit", "-m", "bob edits shared")
	git(t, bobRepo, "push")

	// Alice pulls and reads
	git(t, aliceRepo, "pull", "--no-edit")
	got = readFile(t, aliceRepo, "shared.txt")
	if got != "bob edited\n" {
		t.Errorf("alice reads after bob edit: %q, want %q", got, "bob edited\n")
	}
}

func TestCrossEpochDecryption(t *testing.T) {
	_, aliceRepo, bobRepo, _, _ := setupTwoUsers(t, nil)

	// Alice creates a file at current epoch (1, after Bob was added)
	writeFile(t, aliceRepo, "epoch1.txt", "created at epoch 1\n")
	git(t, aliceRepo, "add", "epoch1.txt")
	git(t, aliceRepo, "commit", "-m", "file at epoch 1")
	git(t, aliceRepo, "push")

	// Add a fake member to advance epoch to 2
	addFakeMember(t, aliceRepo, "charlie")
	git(t, aliceRepo, "push")

	// Alice creates a file at epoch 2
	writeFile(t, aliceRepo, "epoch2.txt", "created at epoch 2\n")
	git(t, aliceRepo, "add", "epoch2.txt")
	git(t, aliceRepo, "commit", "-m", "file at epoch 2")
	git(t, aliceRepo, "push")

	// Bob pulls everything (syncs to epoch 2)
	git(t, bobRepo, "pull", "--no-edit")

	// Bob should be able to read both files
	got := readFile(t, bobRepo, "epoch1.txt")
	if got != "created at epoch 1\n" {
		t.Errorf("epoch1.txt: %q, want %q", got, "created at epoch 1\n")
	}
	got = readFile(t, bobRepo, "epoch2.txt")
	if got != "created at epoch 2\n" {
		t.Errorf("epoch2.txt: %q, want %q", got, "created at epoch 2\n")
	}
}

// ========================================================================
// Unhappy path tests
// ========================================================================

func TestJoinNonMLSGitRepoFails(t *testing.T) {
	repo := t.TempDir()
	git(t, repo, "init")
	git(t, repo, "config", "user.email", "test@test.com")
	git(t, repo, "config", "user.name", "Test")

	out := mlsgitCmdExpectError(t, repo, "join", "--name", "alice")
	if !strings.Contains(out, "not mlsgit-enabled") && !strings.Contains(out, ".mlsgit") {
		t.Errorf("join should fail on non-mlsgit repo, got:\n%s", out)
	}
}

func TestAddNonExistentMemberFails(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	out := mlsgitCmdExpectError(t, repo, "add", "nonexistent-member-id")
	if !strings.Contains(out, "no pending request") {
		t.Errorf("add should fail for nonexistent member, got:\n%s", out)
	}
}

func TestRemoveSelfFails(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")
	aliceID := getMemberID(t, repo)

	out := mlsgitCmdExpectError(t, repo, "remove", aliceID)
	if !strings.Contains(out, "cannot remove yourself") {
		t.Errorf("remove self should fail, got:\n%s", out)
	}
}

func TestRemoveNonExistentMemberFails(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	out := mlsgitCmdExpectError(t, repo, "remove", "nonexistent-member-id")
	if !strings.Contains(out, "not found") {
		t.Errorf("remove nonexistent should fail, got:\n%s", out)
	}
}

func TestVerifyWithoutSealFails(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	writeFile(t, repo, "file.txt", "data\n")
	git(t, repo, "add", "file.txt")
	git(t, repo, "commit", "-m", "add file")

	out := mlsgitCmdExpectError(t, repo, "verify")
	if !strings.Contains(out, "merkle.toml") && !strings.Contains(out, "seal") {
		t.Errorf("verify without seal should fail, got:\n%s", out)
	}
}

func TestInitAlreadyInitializedFails(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	out := mlsgitCmdExpectError(t, repo, "init", "--name", "alice")
	if !strings.Contains(out, "already") {
		t.Errorf("double init should fail, got:\n%s", out)
	}
}

func TestJoinAlreadyMemberMessage(t *testing.T) {
	repo := initMLSGitRepo(t, "alice")

	// join when already a member should succeed but print a message
	out := mlsgitCmd(t, repo, "join")
	if !strings.Contains(out, "already a member") {
		t.Errorf("join as existing member should say already joined, got:\n%s", out)
	}
}
