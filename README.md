# mlsgit

A working prototype of ["End-to-End Encrypted Git Services"](https://eprint.iacr.org/2025/1208) (IACR 2025/1208). The paper describes a protocol for encrypting git repos so the server never sees plaintext; this implements it.

It works as a git clean/smudge filter. `git add` encrypts, `git checkout` decrypts. Your working tree is plaintext, git objects are ciphertext. Members form an MLS group — adding or removing someone rotates the encryption key. Edits are encrypted at the delta level so git history stays meaningful.

This is a prototype, not production software.

## Install

```
make build    # binary at bin/mlsgit
```

## Usage

```bash
# start an encrypted repo
git init myproject && cd myproject
mlsgit init --name alice
git add . && git commit -m "init mlsgit"

# files are now encrypted automatically
echo "secret" > notes.txt
git add notes.txt && git commit -m "add notes"
```

Adding a collaborator:

```bash
# bob clones and requests to join
git clone <url> && cd repo
mlsgit join --name bob
git add .mlsgit/pending/ && git commit && git push

# alice approves
git pull
mlsgit add <bob-id>
git add . && git commit && git push

# bob completes the join
git pull && mlsgit join
```

Other commands: `mlsgit remove <id>`, `mlsgit ls`, `mlsgit review`, `mlsgit seal`, `mlsgit verify`.

## Testing

```bash
make test-all
```

## References

- [End-to-End Encrypted Git Services](https://eprint.iacr.org/2025/1208)
- [RFC 9420: Messaging Layer Security](https://www.rfc-editor.org/rfc/rfc9420)
