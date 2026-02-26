# MLSGit Protocol: Security Argument

## Summary

MLSGit encrypts git repositories using an MLS-inspired protocol for group key lifecycle and per-file AEAD for content. Each epoch secret derives per-file keys via HKDF. File updates are stored as signed encrypted deltas chained by hashes; repository state is summarized by a signed Merkle root.

## Threat Model

The adversary controls the git server and storage: it can read, reorder, modify, inject, or delete objects. It may corrupt up to `t < n` members and learn their private keys and epoch secrets. Endpoints are trusted (no side-channel protection), and metadata is visible.

## Cryptographic Primitives

- **Ed25519** (EUF-CMA): signing deltas, Merkle roots, and key packages.
- **X25519**: Diffie-Hellman key agreement for DH-based epoch rekeying on member removal.
- **HKDF-SHA-256** (PRF): epoch secret derivation, per-file key derivation, encapsulation key derivation.
- **AES-256-GCM** (IND-CPA / INT-CTXT): file encryption, epoch archive encryption, update secret encapsulation.
- **SHA-256**: collision-resistant hashing for Merkle trees and hash chains.

## Epoch Advancement

Two mechanisms are used depending on the operation:

### Deterministic advance (member add)

When a member is added, the epoch advances via:
```
new_epoch_secret = HKDF(old_epoch_secret, salt=epoch_be64, info="mlsgit-epoch-advance")
```
The new member receives the epoch secret directly in a Welcome message. All existing members derive the same new secret from the old one. This is deterministic: anyone with the old secret can compute the new one.

### DH-based advance (member removal)

When a member is removed, the epoch advances via X25519 DH encapsulation:

1. The remover generates a fresh `update_secret` (32 random bytes) and an ephemeral X25519 keypair `(eph_priv, eph_pub)`.
2. For each remaining active member `i`: `shared_i = X25519(eph_priv, member_i.InitPub)`, then `enc_key_i = HKDF(shared_i, salt=epoch_be64, info="mlsgit-encap")`, and the update secret is encrypted as `AES-GCM(enc_key_i, update_secret)`.
3. The new epoch secret mixes in the update secret: `new_epoch_secret = HKDF(old_epoch_secret || update_secret, salt=epoch_be64, info="mlsgit-epoch-advance")`.
4. The ephemeral public key and per-member ciphertexts are stored in the committed group state as `UpdateEncaps`.

Remaining members decrypt their entry via `shared = X25519(own_init_priv, eph_pub)` and derive the same new epoch secret.

## Security Argument

**Confidentiality.** File keys are derived as `file_key = HKDF(epoch_secret, salt=file_path, info="mlsgit-file-key"||epoch_be64)`. If `epoch_secret` is unknown, HKDF outputs are pseudorandom; thus AES-256-GCM encryption is IND-CPA secure. Across `q` encryptions, the adversary's advantage is bounded by `Adv^{PRF}_{HKDF} + q * Adv^{IND-CPA}_{AES-GCM}`.

**Integrity and authenticity.** Each delta record is signed (Ed25519) and chained with `prev_hash = H(previous_ciphertext)`. Forging a delta without an honest signature reduces to Ed25519 EUF-CMA; breaking the chain reduces to SHA-256 collision resistance. The repository manifest signs a Merkle root over file hashes; any file set substitution implies a hash collision or signature forgery.

**Forward secrecy (post-removal).** When a member is removed, the new epoch secret depends on `update_secret`, a value encrypted under X25519 DH shared secrets that the removed member cannot compute (their entry is excluded from the encapsulation). Specifically:

- The removed member knows `old_epoch_secret` and the epoch number (both of which are public to group members).
- The removed member does NOT have an `UpdateEncap` entry for their leaf index.
- To compute `new_epoch_secret`, the removed member would need `update_secret`.
- To obtain `update_secret`, they would need to compute `X25519(eph_priv, any_remaining_member.InitPub)` or break AES-GCM.
- The ephemeral private key `eph_priv` is never stored or transmitted.
- Therefore, forward secrecy after removal reduces to the CDH assumption on Curve25519 and the INT-CTXT property of AES-256-GCM.

## Limitations

- **No post-compromise security for add operations.** Add-based epoch transitions are deterministic. If an epoch secret leaks, all subsequent add-based transitions are computable until the next removal (which re-establishes security via DH).
- **No backward secrecy.** New members receive the epoch key archive and can decrypt history.
- **Static X25519 keys.** Members' init keys are generated once and not rotated. A periodic key-update mechanism (analogous to MLS Update proposals) would strengthen PCS.
- **No DoS prevention.** A compromised member can disrupt the group.
- **Metadata leakage.** File paths, sizes, timestamps, and member identities are visible.
- **Trust in out-of-band identity verification** for adding members.

## References

- RFC 9420: Messaging Layer Security (MLS).
- Bellare (2006) on HMAC/HKDF PRF.
- Bernstein et al. (2012) on Ed25519.
- Bernstein (2006) on Curve25519.
