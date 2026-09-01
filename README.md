# Visiblaze secret scan

Finds credentials committed to your repository. **When you use this action, detection runs on your
runner and your source never reaches Visiblaze.**

That is a property of *this path*, and it is worth being precise about: Visiblaze also offers a
platform-side secret scan, which fetches a repository tarball and scans it in our infrastructure.
If you want the guarantee above, run this action and do not enable the platform-side scan for the
repository — the two are alternatives, not layers.

```yaml
permissions:
  contents: read
  id-token: write        # required — the scanner mints its own short-lived token

steps:
  - uses: actions/checkout@v4
  - uses: Visiblaze/visiblaze-secret-scan@<commit-sha>
    with:
      tenant: your-tenant-id
      api-url: https://<your-visiblaze-endpoint>/v1/code/secrets
```

## What leaves your runner

| Sent | Not sent |
|---|---|
| Rule id (e.g. `aws-secret-access-key`) | The credential |
| Severity | The file |
| File path and line number | The repository |
| A **redacted** fragment of the matching line | Anything from outside the scan path |

Masking is a property of the **line**, not of one finding: every secret detected anywhere on a
line is masked in every finding that reports that line. Two credentials on one line — an `.env`
file, a `docker-compose` argument, a shell `export` — cannot leak each other. The value is masked
before it is placed in any structure that is later serialised, logged or transmitted, not filtered
out afterwards.

We think this is the right default for credentials specifically. Central scanning means copying the
repository into our infrastructure, and for credentials the artefact being copied **is** the key —
so the same design that is merely a trade-off for static analysis is a poor one here. That is why
this path exists and why we would rather you used it.

**The limit, stated plainly.** What is masked is what the rules *detect*. A credential no rule
matches, sitting on the same line as one that does, would travel inside that fragment — a detection
gap, but with the same effect on you. So the fragment is also **bounded** to a short window around
the match rather than the whole line. If you find a credential type we do not detect, that is a bug
worth reporting.

You can check this claim without trusting us: `--dry-run` prints the exact envelope and uploads
nothing.

```yaml
  - uses: Visiblaze/visiblaze-secret-scan@<commit-sha>
    with:
      tenant: your-tenant-id
      api-url: https://<your-visiblaze-endpoint>/v1/code/secrets
      dry-run: 'true'
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `tenant` | *required* | Your Visiblaze tenant id. |
| `api-url` | *required* | The credential ingest endpoint. Must be https and on the allowlist in `pins.env`. |
| `repo-key` | from context | `<provider>#<external_id>`. |
| `path` | `.` | Directory to scan. Must resolve inside the checkout. |
| `scope` | whole repo | Comma-separated paths this run covers. |
| `fail-on` | never | `critical`\|`high`\|`medium`\|`low`. Fails the step at or above this severity. |
| `fail-on-error` | `false` | Whether **our** failure fails **your** build. See below. |
| `dry-run` | `false` | Scan, print the envelope, upload nothing. |

## Two kinds of failure, kept separate

- **`fail-on`** is your result. Credentials at or above the bar exit **2**, and that happens
  regardless of `fail-on-error`.
- **`fail-on-error`** is our result. If the scan cannot run — our endpoint is down, the download
  fails — the default is to warn and pass. A credential scanner that breaks your pipeline because
  of an outage on our side has made your day worse and your repository no safer.

## What we execute on your runner

One binary, ours, from a release pinned by **digest** in
[`pins.env`](pins.env) — so the action SHA you pin determines the bytes that run. A re-tagged
release or a replaced artefact changes the digest and the job **fails**, without executing
anything.

Note *fails*, not warns. Integrity failures ignore `fail-on-error` entirely: a tampered artefact,
an unverifiable pin, an `api-url` we do not permit, or a scan path outside your checkout all exit
non-zero however you configure the action. `fail-on-error` governs only **our** availability — a
download timeout or an ingest outage — because that is our problem and should not break your
build. A substituted binary is not our availability problem.

There is no third-party scanner, so there is no second download and no signature chain to verify.
Credential detection is regular expressions over text; implementing it ourselves means one artefact
to trust instead of three.

## Permissions

`id-token: write` is required. The scanner mints a short-lived GitHub OIDC token whose audience is
bound to the credential ingest route — so nothing is stored in your repository secrets, there is
nothing to rotate, and a token minted here cannot be replayed against another Visiblaze endpoint.

## When it finds something

Rotate the credential at its issuer **first**. Deleting the line does not revoke it, and anyone who
has cloned the repository — or can read its history — already has the value. Purging history is the
second step, not the first.
