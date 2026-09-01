# Security policy

## Why this repository warrants a policy of its own

This action reads **your entire source tree** on your own runner, beside your credentials, looking
for credentials. The thing it searches for is the thing that must never escape, which makes one
property matter more than anything else here — and it is something you should be able to check
rather than take on trust:

- **The credential value never leaves your runner.** Detection runs locally. What is transmitted is
  rule id, severity, file path, line number and a **redacted, length-bounded** fragment of the
  matching line. Not the secret, not the file, not the repository. The value is masked before it is
  placed in any structure that is later serialised, logged or transmitted — it is not filtered out
  afterwards.

  Masking is a property of the LINE, not of a single finding. Every secret detected anywhere on a
  line is masked in every finding that reports it, so two credentials sharing a line cannot leak
  each other. The known limit: this masks what the rules DETECT, so a credential type we have no
  rule for could travel inside a fragment. That is why the fragment is bounded to a window around
  the match rather than the whole line — and why a missing rule is a security-relevant report, not
  just a feature request.

Two more that follow from it:

- **A failed scan is never reported as a clean one.** A run that could not complete reports itself
  as failed, and a failed run is never allowed to mark anything as resolved. "No findings" and "we
  could not look" must never render the same way.
- **Nothing executes before it is verified.** The one binary this action runs is checked against a
  digest committed in `pins.env` — in the same commit you pinned — before it is made executable. A
  re-tagged release or a replaced artefact FAILS the job instead of running, and does so regardless
  of `fail-on-error`: integrity is not an availability setting.

A defect in any of those is the most serious thing that can go wrong here, and we would rather hear
about it from you than from a customer.

## Verifying the first property yourself

You do not have to believe us. Run it with `dry-run: 'true'` and the action prints the exact
envelope it would send and uploads nothing:

```yaml
- uses: Visiblaze/visiblaze-secret-scan@<commit-sha>
  with:
    tenant: your-tenant-id
    api-url: https://<your-visiblaze-endpoint>/v1/code/secrets
    dry-run: 'true'
```

Read the `symbol` field of each finding. If you ever see an unredacted credential there, that is a
vulnerability in this action and we want to know today.

## Reporting a vulnerability

Please report privately, not in a public issue.

Use **[GitHub private vulnerability reporting](https://github.com/Visiblaze/visiblaze-secret-scan/security/advisories/new)**
on this repository. If that is unavailable to you, email **security@visiblaze.com**.

Please include the action SHA you pinned, the scanner version from the job log, and — if the report
is about redaction — the SHAPE of the value that leaked rather than the value itself. Do not send us
a live credential; rotate it first.

## What is in scope

- Anything that causes a credential value, file content, or source text to be transmitted.
- Anything that causes an unverified or unpinned binary to execute.
- Anything that causes a failed or partial scan to be reported as complete.
- Anything that lets findings be sent to an origin not listed in `pins.env`.
- Anything that lets the scan path escape the checkout.

## What is not

- Findings you disagree with. A false positive is a detection-quality bug; open a normal issue.
- The absence of a rule for a credential type. Also a normal issue, and a welcome one.
