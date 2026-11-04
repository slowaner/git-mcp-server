# Git integrity and safety semantics

Git execution and repository access still require the configured execution
profile, canonical repository roots and verified principal grants. The trusted
native profile preserves operator Git configuration, hooks and signing agents;
it is not an operating-system sandbox.

## Privacy

Logs, interactions, trace exports and metric exports use an allowlisted schema.
Raw tool arguments, token claims, credential URLs, exception messages/stacks
and session identifiers are excluded. Process-local keyed correlations retain
request, session, tenant, principal and repository associations without exporting
their original values. Event and limiter cardinality are bounded. Object payload
sizes are reported as unknown instead of serializing the whole payload for
measurement. Private log files require the documented private directory profile.

## Push destinations and destructive actions

Force, force-with-lease and deletion require the existing caller confirmation
assertion for every destination, including feature branches and qualified refs.
The server resolves effective remote/default configuration to explicit branch
or tag destinations and sends concrete refspecs. Configured forced or deletion
refspecs receive the same checks. Matching/wildcard/mirror pushes, implicit
followed tags, ambiguous upstreams and more than 256 destinations fail closed;
select concrete supported destinations instead.

Hard, merge and keep reset require confirmation on every branch and detached
HEAD. An explicitly empty reset path selection is rejected. Clean's force or
dry-run choice, forced checkout/worktree removal, and stash drop/clear modes
remain explicit caller requests under write authority. These flags and modes
are caller assertions. They are not independent human consent: the host must
enforce user authorization, least privilege and approvals for destructive or
publication actions.

## Signing and verification

`GIT_SIGN_COMMITS=true` requires a signature on commit/tag creation. Creation
runs once; neither a signing failure nor a hook failure retries unsigned.
After a failure, inspect repository state before another creation request:
hooks or object creation may already have had side effects.

`GIT_SIGN_COMMITS=false` delegates to operator-trusted native Git policy from
the first attempt. It does not disable signing or override native-required
signatures. The legacy `signingWarning` field remains optional for compatibility
but current creation does not populate it.

`signed` reports stored signature presence, not validity or trust. Tag
verification pins the immutable tag object, obtains the format from its validated
stored signature armor, and requires ordinary numeric exit zero plus appropriate
positive verifier status. Good-signature prose with a failed/unknown exit never
verifies. OpenPGP/CMS cryptographic evidence, configured native trust, and overall
verifier acceptance remain separate fields. SSH trust follows the configured
native allowed-signers policy. None of these fields grants tool authorization.
Unknown/localized status formats fail closed. Offline certificate fixtures do
not establish live revocation or deployment trust-policy coverage.

## Records, filenames and response bounds

History enumerates complete object IDs separately from message content and
authenticates each stored object against its Git hash before parsing metadata.
Tag enumeration contains only validated refnames, object types and IDs; nested
tags have a depth bound. Message markers/control characters cannot introduce
records or override identity fields. Supported UTF-8 annotation bodies retain
their exact trailing bytes. Stat/patch reads are pinned to individual IDs and
remain opaque; literal history path filters also apply to those reads.

History and tag requests support up to 1000 records. Their aggregate object
reads have additional 16 MiB/4096-command bounds, with tag nesting limited to 16.
These semantic limits compose with the request-wide native raw-byte budget and
deadline; they do not replace it. Filename streams use NUL boundaries with
separate 1 MiB/4096-name bounds. Add, commit staging, history filters and diff
path selections use literal pathspecs. Glob/magic-looking names select their
literal filenames; `.` retains directory/all selection. No new native-pattern
escape is accepted.

The native executor accepts complete valid UTF-8 text only. BOM, valid U+FFFD,
newlines and control bytes remain exact; malformed UTF-8 and invalid string
surrogates fail closed. Raw binary/non-UTF-8 Git object output is unsupported.
Filename/object ambiguity and semantic overflow terminate the request rather
than returning partial success. The JSON response has an additional complete
16 MiB envelope bound independent from the native raw-byte ceiling, including escaped strings
and both structured and text representations. Arrays are never truncated.

Arbitrary-byte native filenames require a qualified byte-capable platform.
Local UTF-8/parser checks do not replace the pending Linux native filesystem,
Git and production-consumer qualification.

## Prompt trust

Repository messages, filenames, changelogs, instruction files and custom wrap-up
text are untrusted reference data. Prompt generators label this boundary and
encode variable repository text as JSON data. Such text cannot authorize
commits, tags, pushes or destructive actions, or override current user/host
instructions. Labels are not a prompt sanitizer and do not guarantee that an
agent ignores malicious content; host authorization remains enforcement.
