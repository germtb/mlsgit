# MLSGit Protocol: One-Page Security Argument

## Summary

MLSGit encrypts git repositories using MLS for group key lifecycle and per-file AEAD for content. Each epoch secret exported from MLS derives per-file keys via HKDF. File updates are stored as signed encrypted deltas chained by hashes; repository state is summarized by a signed Merkle root.

## Threat Model

The adversary controls the git server and storage: it can read, reorder, modify, inject, or delete objects. It may corrupt up to `t < n` members and learn their private keys and epoch secrets. Endpoints are trusted (no side-channel protection), and metadata is visible.

## Assumptions

- **MLS PCS:** after removal, the new epoch secret is independent of the removed member's prior state (RFC 9420).
- **HKDF PRF:** HKDF-SHA-256 outputs are pseudorandom given an unpredictable secret.
- **AES-GCM IND-CPA / INT-CTXT:** AES-256-GCM provides confidentiality and ciphertext integrity.
- **Ed25519 EUF-CMA** and **SHA-256 collision resistance**.

## Security Argument (Composition)

**Confidentiality.** File keys are derived as `file_key = HKDF(epoch_secret, file_path || epoch)`. If `epoch_secret` is unknown, HKDF outputs are pseudorandom; thus AES-256-GCM encryption is IND-CPA secure. Across `q` encryptions, the adversary's advantage is bounded by `Adv^{PRF}_{HKDF} + q * Adv^{IND-CPA}_{AES-GCM}`.

**Integrity and authenticity.** Each delta record is signed (Ed25519) and chained with `prev_hash = H(previous_ciphertext)`. Forging a delta without an honest signature reduces to Ed25519 EUF-CMA; breaking the chain reduces to SHA-256 collision resistance. The repository manifest signs a Merkle root over file hashes; any file set substitution implies a hash collision or signature forgery.

**Forward secrecy (post-removal).** When a member is removed, MLS advances the epoch and derives a fresh epoch secret via TreeKEM. By MLS PCS, the removed member's prior state is independent of the new epoch secret. File keys derived from the new secret are therefore unavailable to the removed member. The epoch archive is re-encrypted under the new secret.

## Limitations

No backward secrecy (new members can decrypt history), no DoS prevention, metadata leakage (paths, sizes, timestamps), text-centric deltas for binary files, and trust in out-of-band identity verification for adding members.

## References

- RFC 9420: Messaging Layer Security (MLS).
- Bellare (2006) on HMAC/HKDF PRF.
- Bernstein et al. (2012) on Ed25519.
