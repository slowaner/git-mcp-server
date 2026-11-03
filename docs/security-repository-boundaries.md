# Repository filesystem authority

`GIT_BASE_DIR` is the operator ceiling for Git repository data. Every configured
root must already exist as a real directory. Paths are canonicalized and checked
by components; a sibling with the same text prefix is outside the grant. Both
lexical and canonical spellings of approved operating-system aliases work.
User-controlled root aliases and links below a root are rejected, including
dangling links and new destinations through linked parents. Malformed Unicode
paths are rejected before path normalization or native filesystem calls.

Relative paths keep the first configured root as their anchor. Narrowing a
request to the second root does not change this anchor: a relative path into the
first root is denied. Server-issued `repositoryRoots` restrictions intersect the
operator ceiling on every primary and secondary path. An empty restriction
denies access; absence retains the inherited restriction. No tool input exposes
this authority. Without `GIT_BASE_DIR`, explicit trusted native operation retains
the legacy unrestricted operator filesystem ceiling; configure roots to limit it.

## Execution and discovery

The default restricted execution profile fails before repository filesystem work
because no verified OS containment backend ships. It does not fall back to
trusted execution. The explicit trusted profile still applies canonical grants,
but requires operator-trusted repositories and writers. Realpath, inode pins and
no-follow opens do not make attacker-controlled rename races safe. Windows
reparse-point confinement and hostile same-UID writers are unsupported. A caller
requiring those guarantees must use an enforceable isolation boundary; this
server does not provision one.

Discovery stops at granted roots. Normal, bare and linked repositories are
supported when all backing paths stay in the grant, including Git/common dirs,
worktrees, index and object alternates. Metadata symlinks, linked index files,
local repository config includes, HTTP object alternates and ambiguous local
path/config grammar are rejected before native Git can consult them. Discovery
uses at most 100,000 metadata entries and 1 MiB per metadata/config file. Ordinary
metadata is strict UTF-8; literal BOM and U+FFFD bytes in authority values are
preserved. One initial Git config syntax BOM is supported. Pointer records permit
one line ending without Unicode whitespace normalization.

After this local gate, fixed read-only native config introspection uses the same
controlled executor, environment, includes, request byte budget, deadline and
cancellation as the operation. Trusted operator HOME/system configuration,
conditional includes and signing remain supported. Effective worktree paths and
all fetch/push URLs are authorized before the operation. Native top-level,
Git-dir and common-dir results must agree with canonical discovery. The internal
reader is not a public bypass option. Implicit environment loading remains
disabled as described in [Git execution](security/git-execution.md).

## Destinations, remotes and session state

Init runs from an existing authorized ancestor and creates its destination only
after effective config checks. Clone destinations, local source repositories and
worktree add/move/remove paths use the same capability. Recursive submodule clone
is unsupported because its additional sources cannot be preauthorized here.
Worktree operands are separated from options. Repository file operands and
untracked no-index diff inputs cannot redirect through outside links; `/dev/null`
is permitted only as the fixed empty left side of that internal diff.
The existing readonly diff auto-exclusions permit only removal-only plain ASCII
basenames, without path separators, glob syntax or additional native magic.
An outer `:(literal)` filename wrapper is decoded exactly once for authority
checking; a filename that itself starts with those bytes remains literal.

Every stored remote URL is checked, including dormant/multiple URLs, explicit
push URLs and longest-prefix `insteadOf`/`pushInsteadOf` rewrites. Local file URLs
are decoded as filesystem paths; ordinary paths are never URL-decoded. Local
transfer sources must have authorized backing metadata before object/ref
transfer. Configuring a missing local endpoint inside the grant is allowed;
transfer requires an existing authorized repository. Home-relative paths,
ambiguous local encodings and custom remote-helper transports fail closed.
An unsafe dormant remote can block other operations; repair its configuration
through the trusted operator before retrying. Operator-native hooks, signing,
global includes, helpers and network access remain trusted execution authority,
not an egress sandbox.

Persisted cwd is revalidated on every consumer, including status, working-directory
resources, setup snapshots and wrapup. Restarting with narrower roots does not
reuse the old grant. Snapshot authorization failures are errors rather than
best-effort warnings, and request poisoning prevents caught optional Git calls
from hiding a forbidden path or returning partial success.

See [private filesystem storage](security-filesystem-storage.md) for ownership,
modes, strict text handling and the explicit v2 namespace migration policy.
