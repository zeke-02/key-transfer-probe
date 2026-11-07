# Key transfer probe

Throwaway test for Fount Mail's vault design
(`fount/docs/features/fount-fleet/keyserver-without-aws-access.md`). Can two Tinfoil enclaves
verify each other and pass a key nobody else can read? Delete everything afterwards.

The key is random, made on request, and worthless. No Fount secret or account is involved.

## How a transfer works

Whichever enclave holds the key is the holder. The other is the requester.

1. The requester calls `POST /transfer/begin` on the holder and gets a one-use nonce.
2. The requester gets a document for that nonce from `/tinfoil/attestation.sock` and sends it to
   `POST /transfer/finish`, with a nonce of its own.
3. The holder verifies the document against `PEER_PIN` and reads the requester's attested
   `transfer` key from it.
4. The holder seals the key with X25519 between both attested keys, and sends the box with its
   own document for the requester's nonce.
5. The requester verifies that document too, then opens the box.

`/prove` returns an HMAC of a challenge under the key, so two enclaves can show they match
without revealing it. `verify.VerifyV3` does no network I/O, so the only egress this needs is
reaching the peer.

## What runs where

`go test -race ./...` covers the protocol with a fake attester, including altered ciphertext,
which the live run can't reach. Only a live run proves the attestation parts.

| Instance | Release | Role |
|---|---|---|
| `kt-a`, `kt-b` | `zeke-02/key-transfer-probe@v0.0.1`, later `v0.0.3` to `v0.0.5` | The pair |
| `kt-unapproved` | `zeke-02/key-transfer-probe@v0.0.2` | Correct repo, wrong release |
| `kt-copy` | `zeke-02/key-transfer-probe-copy@v0.0.1` | Same code and tag, wrong repo |

## Versions

Checked 2026-11-07. Recheck before running:

| Component | Version | Note |
|---|---|---|
| Tinfoil CLI | 0.19.20 | Run `tinfoil update --check` |
| CVM image | 0.14.17 | Latest stable. `0.15.x` tags are release candidates |
| `tinfoil-go` | `v0.17.0-rc.8` | A release candidate. Stable `v0.15.10` has no `verify.Verifier` |
| `measure-image-action` | v0.14.1 | Latest |

## Running it

Check first that V3 attestation is enabled for the Tinfoil org.

1. Create the public repo `zeke-02/key-transfer-probe` and push this code.
2. Run **Build Image** with `v0.0.1`, and make the GHCR package public.
3. Replace `PLACEHOLDER_DIGEST` in `tinfoil-config.yml` with the digest and commit.
4. Run **Tinfoil Release** with `v0.0.1`.
5. Change `PROBE_LABEL` to `unapproved`, commit, and run **Tinfoil Release** with `v0.0.2`.
   Changing the label makes its measurement differ. Keep `PEER_PIN` at `v0.0.1`.
6. Copy the `v0.0.1` commit to the public repo `zeke-02/key-transfer-probe-copy`, with its
   config unchanged, and run **Tinfoil Release** there with `v0.0.1`.
7. Create the instances:

   ```bash
   tinfoil container create kt-a --repo zeke-02/key-transfer-probe --tag v0.0.1
   tinfoil container create kt-b --repo zeke-02/key-transfer-probe --tag v0.0.1
   tinfoil container create kt-unapproved --repo zeke-02/key-transfer-probe --tag v0.0.2
   tinfoil container create kt-copy --repo zeke-02/key-transfer-probe-copy --tag v0.0.1
   tinfoil container list
   ```

   A release that has never been latest has no witness, so its enclave answers 503
   (`attestation_unavailable`) to fresh attestation. If that happens, run
   `gh release edit v0.0.1 -R zeke-02/key-transfer-probe --latest`. It recovered in about 45
   seconds, and `v0.0.2` kept working.

8. Run the checks, using the instance domains. They need `curl`, `jq`, and `openssl`:

   ```bash
   ./check.sh transfer $A $B
   ./check.sh replay $A $B
   ./check.sh refuse $A $UNAPPROVED
   ./check.sh refuse $A $COPY
   curl -s https://$A/status | jq .
   curl -s https://$UNAPPROVED/status | jq .
   tinfoil container stop kt-a
   tinfoil container deploy kt-a
   ./check.sh restore $A $B
   ```

9. Save the `/status` output, then delete all four instances, both repos, and the GHCR package.

## What passing means

| Check | Pass |
|---|---|
| `transfer` | Mutual attestation works, and both enclaves prove the same key |
| `replay` | Mismatched and reused documents are refused, and the laptop only sees a sealed box |
| `refuse`, `kt-unapproved` | A proper release that isn't pinned gets nothing |
| `refuse`, `kt-copy` | The same code in another repo gets nothing |
| `restore` | A fully redeployed enclave has a new attested key and gets the original key back |

Also record `last_peer` from `/status`. It shows what Tinfoil signs for a deployed release: the
config name and approval time, if the enclave uses V3 config collateral. The public delay
depends on that.

If `transfer` fails, the error names the stage. `begin` or a network error points at egress or
the shim, and a failure at `verify` shows what the document lacks.

## Result

All checks passed on 2026-11-07, on CVM 0.14.17 on `iridium-1`. A transfer took 132ms with a
78 KB document. Each enclave reported code collateral, so `last_peer` had no config approval
time. The copy had the same measurement as `v0.0.1`, and was refused on the signing
certificate's repo.

## Upgrade test

`v0.0.3` and `v0.0.4` pin the repo without a tag, because an old enclave can't name a release
that doesn't exist yet. On 2026-11-07:

1. `kt-a` and `kt-b` moved to `v0.0.3`, and `kt-b` pulled a new key from `kt-a`.
2. `tinfoil container update kt-a --tag v0.0.4 --hold=true` started a candidate at
   `https://kt-a...:4443`, which pulled the key from the old version still serving production.
3. After `tinfoil container promote kt-a`, production kept the key in memory.
4. `kt-b` upgraded the same way, pulling from the new `kt-a`. Both proofs matched.

The repo pin also let `kt-a` seal the key to `kt-unapproved` on `v0.0.2`. That enclave only
refused it because its own pin was stricter. A real vault should also require a tag at or above
its own.

## Minimum tag

`v0.0.5` adds that check. A holder reads its own tag from its own attestation, then refuses to
seal the key to any peer with a lower tag, or with no valid version tag. If it can't read its own
tag, it refuses everyone. Only the holder checks, because an upgrade pulls from an older release.

On 2026-11-07, both enclaves upgraded from `v0.0.4` to `v0.0.5` with hold and promote. The `kt-a`
candidate pulled from `v0.0.4`, and the `kt-b` candidate pulled from the new `kt-a`. Then:

```bash
./check.sh refuse $A $UNAPPROVED   # refused at minimum tag: v0.0.2 is older than v0.0.5
./check.sh refuse $A $COPY         # still refused at verify, on the signing repo
```

`release_floor` in `/status` shows the tag in force, once the first transfer has read it.

## What this doesn't cover

- Handing over after witnesses have aged.
- Losing both enclaves, or recovery shares.
- Whether a second instance of an approved release is safe. The pin names a release, not an
  instance.
