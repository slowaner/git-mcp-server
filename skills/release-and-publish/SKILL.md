---
name: release-and-publish
description: >
  Prepare an immutable bundle from an explicitly reviewed commit and annotated
  version tag, then publish that exact bundle to npm and the MCP Registry only
  with explicit publication authority. Stops on drift, failed checks or missing
  destination receipts. Never fixes, commits, retags or pushes after review.
metadata:
  author: cyanheads
  version: '1.1.0'
  type: workflow
---

## Authority and supported profile

Preparing a bundle does not authorize publication. Require an explicit user
request naming the intended registries/namespaces before running `--publish`.
The operator must control those namespaces and configure authentication separately.
Do not retrieve credentials from Keychain, put tokens in arguments, provision
accounts, change provider settings or infer authority from available credentials.

The automated release profile supports Linux x64 and macOS arm64 with the exact
vendor Bun 1.4.3 and Gitleaks 8.30.1 archives. Publishing also requires the exact
MCP publisher 1.8.7 archive. Read [toolchain pins](../../scripts/security/toolchain-pins.ts)
for platform-specific URLs and SHA-256 values. No `latest`, global install or
binary fallback. The running Bun must match the selected vendor archive bytes.
Unsupported platforms or mismatched Homebrew/custom builds fail closed. Tool
availability does not establish native security qualification: final release
acceptance requires the unchanged arbitrary-byte filename oracle and complete
suite on the supported Linux runner, including production UTF-8 failure/terminal
request behavior. A supported-local profile with this case not run cannot grant
release readiness.

Use an operator-controlled checkout and private output directory. The release
runner does not sandbox arbitrary source code, native signing tools or the host.
Fork PR security jobs receive read-only permissions and no publishing credentials.

## Preparation before review and tag

All metadata synchronization and auto-fixing belongs in development, before the
final source commit, independent review and annotated tag:

```bash
bun scripts/validate-mcp-publish-schema.ts --sync-only
bun run devcheck
```

Metadata synchronization refuses a tagged HEAD and never commits. Preserve normal
commit hooks and exact staged-tree secret scanning. Review the changed source,
package/lock files, manifests and compatibility notes, then finish the source
commit and independent review using the project's normal process. The annotated
`v<version>` tag must point to that exact reviewed commit. Creating/pushing a tag
is a separate authorized action; this skill never creates or moves refs.

If review, source, metadata or lock inputs change, repeat affected gates and obtain
a current review/tag. Never patch a release from inside the publish phase.

## Read-only gate and immutable bundle

Download the exact archives from the pinned primary vendor URLs and verify their
SHA-256 values before selecting them. Invoke the release runner with the verified
vendor Bun binary:

```bash
bun scripts/release.ts \
  --commit <full-reviewed-commit> --tag v<version> \
  --output <absolute-private-directory-outside-checkout> \
  --bun-archive <matching-platform-bun.zip> \
  --gitleaks-archive <matching-platform-gitleaks.tar.gz>
```

Default mode prepares only; it performs no registry upload. It requires a clean
checkout, matching annotated tag/object, exact package/lock/toolchain inputs and
matching MCP metadata. It validates the vendored, digest-pinned MCP schema offline,
installs the frozen lock without lifecycle scripts, runs read-only devcheck and
tests, rebuilds and packs with lifecycle scripts disabled. A required native
fixture tool missing from the supported profile is an incomplete gate, not a pass.

The High/Critical all-lock audit policy is preserved. Structured lower-severity
findings remain visible. Network/tool/permission/empty/malformed/partial/skipped
audit results block. Optional `bun scripts/security-audit.ts --strict` blocks every
severity; a threshold pass never means all vulnerabilities are absent.

The bundle contains `source.tar`, exact `package.json`, `bun.lock`, `server.json`,
a separately hashed canonical `registry-manifest.json`, `package.tgz`,
`build.json`, `sbom.json`, `checks.json` and `provenance.json`.
The registry payload omits only the legacy npm-only `mcpName` field; the original
source manifest remains in the bundle with its own hash. The lock inventory covers
all supported npm tuples, including development/build copies; it is not a runtime
reachability finding. Packed files must match the checked build or reviewed source.
The bundle receives its own archive-aware secret scan.

Source export attributes (`export-ignore` or `export-subst`), submodules and
control characters in source paths are unsupported and block preparation. The
source archive must preserve the reviewed tree without export transformations.

Save the printed `provenance.json` SHA-256 separately. Keep bundle bytes unchanged.
No fixer, auto-commit, `--no-verify`, push or tag mutation is allowed after the
source gate. Any failed command or source/tag/metadata/build drift stops the flow.

## Explicit publication of the same bundle

After separately authorized publication, reuse the existing output directory and
its recorded manifest digest:

```bash
bun scripts/release.ts --publish \
  --commit <same-reviewed-commit> --tag v<same-version> \
  --output <same-private-bundle-directory> \
  --bundle-sha256 <recorded-provenance-json-sha256> \
  --bun-archive <same-platform-bun.zip> \
  --gitleaks-archive <same-platform-gitleaks.tar.gz> \
  --publisher-archive <matching-platform-mcp-publisher.tar.gz>
```

The runner refreshes read-only gates, verifies the exact existing bundle and
revalidates source/tag and artifact hashes before each destination. npm receives
the prebuilt tarball; the MCP publisher receives the bundle's registry manifest.
Credentials must already be configured by the operator; the runner performs no
automatic login or secret lookup.

A successful upload command is not a verified receipt. npm metadata must match the
exact name/version and its downloaded tarball SHA-256 must match the bundle. MCP
verification uses the exact version endpoint and compares canonical server content.
Each verified receipt is saved under the output directory's `.receipts` sibling
before starting the next destination.

## Failure and partial publication

Stop on the first failure. Never interpret duplicate-version text as proof of a
previous success. Do not retry automatically, rebuild after one registry succeeds,
or silently resume only the other destination. Preserve the bundle, its digest and
saved receipts; report each destination as verified, failed or uncertain.

A partial publication or existing version needs a separately reviewed recovery
decision based on actual remote identities/bytes. No merge, force push, tag move,
release creation or provider approval follows from a local check or receipt.

## CI evidence

CI and Security workflows run on PRs including stacked targets and on main/security
branch pushes. Reviewed action SHAs and platform-specific archive digests pin Bun,
Gitleaks and CodeQL inputs. Frozen installation skips lifecycle scripts; any needed
native generation requires an explicit reviewed step. Full current-tree secret
scanning and actual outgoing commit metadata scans have no fixture exception.
Scanner rules are the complete official 8.30.1 source, vendored without changes;
SHA-256, byte count and Git blob are checked before explicit configuration.
The history-only gate supports full descendant closures of its reviewed immutable
anchor, including first-parent merge diff presentation without restricting
traversal. It requires exactly both independently assessed immutable occurrences,
each once, as `accepted-history-fixtures`, count2. Missing, duplicate, extra,
malformed or zero findings and incomplete/altered scope block. This status is
distinct from zero findings; other histories require a separate policy decision.

CI configuration, generated SBOMs and helper tests alone do not prove workflow
execution, native-platform coverage, independent review or registry publication.
Record actual job/head/tool evidence and any incomplete/blocked gates.
