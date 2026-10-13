# Security Policy

Apate is a cyberdeception tool: it is deployed **inside** the environment it protects, it handles
integration credentials, and it produces intelligence about real adversaries. A vulnerability here
is not only a software problem — it can expose an operation in progress.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting:

**<https://github.com/Base4Security/Apate-Cyberdeception/security/advisories/new>**

**Do not open a public issue** for a security problem. An issue is visible from the moment it is
created, and for a tool that runs inside someone's network that turns a report into a warning to
the adversary.

It helps to include, as far as you have it:

- The affected version (`/about` shows it, together with the exact revision) and how you deployed it.
  If the problem is in a dependency, `/about/sbom.json` (requires a session) gives the full
  inventory of installed versions in CycloneDX format.
- What the problem allows an attacker to do, not only what is wrong. An unclassified route in the
  allowlist of `apate/web/access.py` and a leak of integration credentials are not the same thing.
- Steps to reproduce, or the code fragment where you found it.
- Whether you are already able to exploit it in your own environment: that changes the urgency.

## What to expect

This is a project with a small team. The following are targets, not an SLA:

| | |
|---|---|
| Acknowledgement | Within **5 business days** |
| First assessment (whether it applies, and its severity) | Within **15 business days** |
| Disclosure | Coordinated with the reporter, after a fix exists |

If you get no response, follow up through the same private channel.

## Scope

**In scope** is this repository's own code: `src/apate/` — the operation model, the rules engine,
the deception capabilities, telemetry, reporting, the web interface, identity and access control,
auditing, and secret encryption — and its dependencies as declared in [`NOTICE`](NOTICE).

**Handled separately** is the vendored code under `src/DOLOST/`, `src/BUDA/`, and
`playground-stack/`. These are copies of other BASE4 Security projects (see [`NOTICE`](NOTICE));
report them through the same channel and the fix is coordinated with the upstream project.

**Out of scope**, to save you time:

- **The lab's example credentials.** `playground-stack/frontend/config/` contains files that *look*
  like leaked secrets — `aws-credentials.json`, an `environment.env` that says "CRITICAL: This file
  contains production secrets" — and they look like that **on purpose**: they are the lures the
  deception exercise exposes for an attacker to find. The AWS key is `AKIAIOSFODNN7EXAMPLE`, the
  example key from AWS's own documentation, and grants access to nothing. GitHub secret scanning
  will flag them; they are not a finding.
- **An installation without `APATE_SOURCE_URL`.** `/about` explicitly states that the installation
  did not report where its source is. That is the correct response to an incomplete configuration.
- **`/about/sbom.json` requiring a session.** This is deliberate: the license notice required by
  AGPLv3 is public, but the inventory of installed versions is a map of the attack surface, and this
  tool runs inside the network it protects.
- **A single process with a single worker.** The supported installation is `--workers 1`
  (see [`docs/instalacion-produccion.md`](docs/instalacion-produccion.md), in Spanish); live
  notifications breaking with more workers is a declared architectural limitation, not a security
  defect.

## Supported versions

| Version | Status |
|---|---|
| `0.1.x` | Release candidate. Fixes go to the `main` branch. |

There is no backport policy yet.

## Limitations the project already declares

- **The audit hash chain detects an isolated edit or deletion, but not a writer who rebuilds every
  later hash.** Closing that gap requires signing with an external key or an external append-only
  log.
- **Secret encryption protects copies, backups, and shared JSON files, not against someone with
  access to the host**, because that person can also read the local key. External key custody
  (Vault/KMS) is what closes that gap.

If you find a way to go **beyond** those limitations — for example, altering the audit trail
without write access to the host — that is a finding, and a good one.
