# Project Overview

## Purpose

This project exists to keep Linear aligned with Snyk DAST.

Canonical module path:

```text
github.com/tesslio/snyk-dast-linear-sync
```

Snyk DAST is the rebrand of Probely. The tool talks to the Probely REST API
(current hostnames `api.probely.com` / `plus.probely.app`, both configurable)
and is forward-compatible with the Snyk DAST rebrand.

The intended outcome is:

- every relevant Snyk DAST finding has a corresponding Linear issue
- the Linear issue stays current as the Snyk DAST finding changes
- resolved or accepted/invalidated findings move to the correct Linear workflow state
- repeated runs become cheap by skipping unchanged records

This is an operational sync tool, not a generic library.

## Core Contract

The project treats Snyk DAST as the source of truth for security finding data
and Linear as the execution surface for tracking and triage.

It is responsible for:

- reading Snyk DAST findings (and the targets they belong to)
- deciding the desired Linear representation
- reconciling the current Linear state to that desired state

It is not responsible for:

- writing back to Snyk DAST
- preserving arbitrary manual edits inside the managed section of the Linear description
- syncing comments or custom fields beyond the currently managed issue body, title, priority, due date, workflow state, and managed automation label

## Identity Model

Each Snyk DAST finding is identified by:

```text
snyk-dast:<target-id>:<finding-id>
```

The `<finding-id>` is the bare numeric finding id returned by the Snyk DAST
API (the `id` field from `GET /findings/`). Global uniqueness comes from the
`snyk-dast:<target-id>:` prefix. That fingerprint is embedded in the Linear
description metadata block and is the durable join key between systems.

Without that fingerprint, the sync cannot safely deduplicate or update issues.

## Issue Lifecycle

### Create

Create a Linear issue when:

- a Snyk DAST finding exists
- no Linear issue with the same fingerprint exists

### Update

Update the Linear issue when managed fields differ:

- title
- description
- due date
- priority
- mapped state
- managed automation label

### Resolve

When a previously tracked finding no longer exists in Snyk DAST but its target
still exists, move the Linear issue to the resolved (`Done`) state.

When a previously tracked finding no longer exists because its Snyk DAST target
no longer exists, cancel the Linear issue instead.

### Conflict

If multiple Linear issues share the same fingerprint, the sync treats that as a
conflict:

- it logs the conflict
- it keeps the lowest-identifier issue as canonical and cancels the duplicates

## Description Strategy

The Linear issue description is intentionally structured for fast triage first,
deep debugging second. Snyk DAST is a DAST product, so findings describe
vulnerabilities in a scanned web application or API target rather than
source-code locations or package dependencies.

It includes:

- heading with vulnerability title and severity
- target name/host and target URL near the top
- the vulnerable request context: URL, HTTP method, path, parameter, insertion point
- CWE and CVSS score when available
- human-usable Snyk DAST UI link
- Snyk DAST REST API link
- the fix description when Snyk DAST provides one
- target and finding identifiers
- metadata block

The synced title is also structured for scanability. It leads with the scanned
target (host, falling back to target name) and the vulnerable request
(`METHOD path`).

The metadata block also records the managed automation label set when label
management is enabled.

Linear may rewrite parts of the description body when rendering or storing
markdown. The sync therefore normalizes known Linear formatting changes during
compare and cache hashing.

## Managed Labels

`LINEAR_MANAGED_LABEL` controls the label this tool manages on synced issues.

- default: `snyk-dast-automation`
- `off`: disables label management
- any other value: the exact Linear label name to manage

Behavior:

- the configured managed label is added to new synced issues
- unrelated existing labels are preserved
- if the configured managed label changes, the old managed label is removed and the new one is applied
- if label management is disabled, the previously managed label is removed

The configured label must already exist in Linear. If it does not, the run
fails with a clear operator-facing error.

`LINEAR_TARGET_TYPE_LABELS` optionally maps Snyk DAST target `type` values
(`single` for web applications, `api` for APIs) to additional managed Linear
labels.

- format: comma-separated `target_type:label` pairs
- example: `api:snyk-dast-api,single:snyk-dast-web`

`LINEAR_TARGET_TYPE_LABEL_DEFAULT` controls the fallback label for unmapped
target types.

- default: `off`
- `off`: disables the fallback

The metadata block stores the full managed label set so the sync can remove
stale target-type-derived labels while preserving unrelated manual labels.

`LINEAR_PROTECTED_LABELS` names labels this sync must never add to, or remove
from, an existing ticket, for labels another actor owns as control state.

- format: comma-separated label names
- default: empty
- `off`: disables protection entirely

Linear's `issueUpdate` replaces a ticket's whole label set rather than applying a
delta, so every update echoes back the label set the run's opening snapshot saw —
which deletes anything another actor added since. Protection therefore cannot be
served from the snapshot:

- when any label is protected, each update batch re-reads the live labels of the
  issues it is about to write, and protected labels are taken from that read and
  from nowhere else. This preserves one added mid-run and equally respects one
  removed mid-run (an absent label is never re-added).
- an issue missing from that read is indistinguishable from one carrying no
  protected label, so the batch is failed rather than guessed at. The caller
  already retries issues individually, so only the unreadable issue is reported
  failed, and it lands in `FailedOps`, which fails the run.
- the labels connection is checked for truncation (`pageInfo.hasNextPage`) and a
  truncated page fails the issue closed too: a protected label past the page
  boundary would be absent from the read and then deleted by the update, which is
  the exact failure the read exists to prevent. Refusing beats paginating — a
  nested connection cannot be paged within the one query, and an issue with more
  than 250 labels is pathological rather than a case worth serving.
- protected labels are never asserted from the managed set, bounding the blast
  radius of a misconfiguration.
- creates need no handling: there is no pre-existing label set to replace.

The live read is skipped when the protected set is empty, keeping the extra query
off the hot path for deployments that do not need it.

`LINEAR_UNSUBSCRIBE_ACTOR` is an optional operator control for notification
behavior.

- default: `true`
- when enabled, the sync creates issues without subscribing the Linear API actor
- update operations preserve the current subscriber list exactly as it already exists

## State Mapping

Snyk DAST (Probely) finding states map to Linear workflow states as follows:

- `notfixed` / `retesting` -> `Todo`
- `accepted` with a future `expiration_date` (time-limited risk acceptance) -> `Todo` (SLA clock restarts from the acceptance expiry)
- `accepted` with a past `expiration_date` (lapsed risk acceptance) -> `Todo` (due date is the acceptance expiry plus the configured severity offset)
- `notfixed` after a lapsed acceptance (Snyk DAST reverts an expired acceptance to `notfixed`) -> `Todo` (due date still the remembered acceptance expiry plus the configured severity offset, see Acceptance Memory under SQLite Cache)
- `accepted` without an `expiration_date` (permanent risk acceptance) -> `Cancelled`
- `invalid` (false positive) -> `Cancelled`
- `fixed` -> `Done`
- missing finding in an existing Snyk DAST target -> `Done`
- missing finding because the Snyk DAST target no longer exists -> `Cancelled`

The sync also normalizes workflow naming differences such as `Canceled` vs
`Cancelled`.

A time-limited `accepted` finding is kept open in `Todo` rather than cancelled,
because it requires attention once the acceptance expires. Its due date is
calculated from the acceptance expiry date so the SLA extends to the normal
severity offset from when the acceptance ends.

A lapsed time-limited acceptance stays in `Todo` for the same reason: the
acceptance was a request to be reminded at the expiry date, so mapping the
expired state onto a permanent acceptance would cancel the ticket at exactly
the moment it becomes actionable again. Only an acceptance with no expiry at
all is treated as permanent.

Snyk DAST does not leave a lapsed acceptance in the `accepted` state for
long: it reverts the finding to `notfixed` once the expiration date is
reached. From then on the finding no longer tells the sync when the
acceptance ended, so the sync remembers the expiry itself (see Acceptance
Memory under SQLite Cache) and keeps basing the due date on it.

Archived Linear issues are a special case. Linear auto-archives closed issues
and excludes them from the default issue query, while Snyk DAST retains
terminal findings indefinitely, so the sync must ask for archived issues
explicitly (bounded by `LINEAR_ARCHIVE_LOOKBACK_DAYS`) or it recreates a
duplicate each time a ticket leaves the snapshot — once per archive cycle rather
than on every run, since each replacement is visible until Linear archives it in
turn. Archived issues are treated as
terminal and are not mutated in place; a finding that becomes active again gets
a replacement ticket.

The replacement is a product choice, not an API constraint: Linear's
`issueUnarchive` mutation carries no documented precondition, so restoring and
updating the original ticket is a supported alternative. It was considered and
rejected — each recurrence is intended to get a clean ticket with its own SLA
clock rather than one ticket reused across recurrences.

The lookback window bounds elapsed time since **auto-**archiving, not the team's
auto-archive period (which Linear expresses in months). The two are
independent, so a short window is not made safe by a short period. It also does
not bound every archived issue: manually or API-archived issues (trashed ones
included) have `archivedAt` set with `autoArchivedAt` null, so they are returned
regardless of age. Including them can only prevent duplicates, and the pinned
`linear-api` binding has no `IssueFilter.archivedAt` to bound them with.

Since Snyk DAST retains terminal findings indefinitely, each keeps a live
desired issue forever, and any finite window eventually drops its ticket from
the snapshot — minting a duplicate that cannot be reconciled, because the
original is no longer visible to the duplicate-cancellation pass. The copies
therefore accumulate, one per cycle. `LINEAR_ARCHIVE_LOOKBACK_DAYS` defaults to
ten years for that reason: it covers the whole archive in practice, and remains
configurable only as a size/latency escape hatch.

Suppressing creates for already-terminal findings would also remove the cycle,
but was rejected: the project wants every finding to end up with a ticket,
including findings closed before the sync first ran.

### Manual Non-Terminal State Override

When a user manually moves a managed issue to any non-terminal Linear workflow
state that differs from what the sync would set, subsequent syncs preserve the
user's chosen state. This prevents the automation from fighting intentional
triage decisions.

This covers:

- a user moving an open issue from the configured open state (e.g. `Triage`) to `Todo` or `In Progress`
- a user moving a snoozed issue from `Backlog` to `Todo`
- any other non-terminal state that differs from the configured state for the desired model state

Terminal states (`Done`, `Cancelled`) are never preserved: the sync always
transitions to a terminal state when the Snyk DAST finding is fixed or
permanently accepted/invalidated, even if a user manually moved the issue to a
terminal state.

### Due Dates

Due dates are derived from the Snyk DAST finding `created_at` timestamp, not
from when the issue first appears in Linear. For time-limited `accepted`
findings (snoozed), the due date is instead calculated from the acceptance
expiry date so the SLA extends to the normal severity offset from when the
acceptance expires. The expiry keeps being the base after the acceptance has
lapsed, including once Snyk DAST has reverted the finding to `notfixed` and no
longer reports the expiry: the sync remembers it (see Acceptance Memory under
SQLite Cache). Without that memory the due date would fall back to
`created_at` plus the offset, which is usually already in the past, so a
ticket that was correctly dated would suddenly read as long overdue.

Default offsets:

- critical: 15 days
- high: 30 days
- medium: 45 days
- low: 90 days

Past due dates are left as-is. Linear renders past due dates as "overdue", and
the actual past date is more informative than flooring to today: it tells the
triager how long the issue has been past its SLA. Flooring to today would also
cause daily cache churn.

## Performance Model

The project is designed for thousands of issues.

It uses:

- concurrent Snyk DAST and Linear snapshot loading
- worker-based reconciliation
- batched Linear mutations
- rate-limit backoff
- SQLite caching

The cache is critical for steady-state performance. A healthy steady-state run
should do little or no work when nothing has changed.

### Batch Failure Handling

Linear mutations are batched, one GraphQL alias per entry, so a batch can fail
three different ways and each needs different handling to avoid duplicating
tickets:

- **Per-alias failure.** The response carries `success: false`, or omits the
  alias, while the other aliases succeeded. Note that `gqlclient` decodes the
  response body before returning any GraphQL error, so the successful aliases are
  still available even when an error is returned. Only the reported entries are
  retried; retrying the batch would duplicate the ones that already exist.
- **Ambiguous failure.** No aliases were decoded at all, so nothing is known per
  entry. This covers a transport-level failure and equally a GraphQL failure that
  returned no data, such as a rejected query. Crucially it does *not* prove Linear
  rejected the mutation, which may have been committed before the response was
  lost. Creates are therefore reconciled first: `ExistingFingerprints` asks Linear
  which of the batch's fingerprints now have a live issue, and only the rest are
  re-created. If that lookup also fails, nothing is retried and the entries are
  counted as failed. The finding remains in the next Snyk DAST snapshot either
  way; if its issue was never created it is absent from the next Linear snapshot
  and gets created on the next run. Missing a ticket for one cycle is recoverable;
  a duplicate is only undone later by the duplicate-cancellation pass.
- **Ambiguous comment failure.** A comment carries no fingerprint to reconcile
  against, and a duplicated change comment is more disruptive than a missing one
  (the issue state itself is already correct), so these are counted in
  `FailedComments` and not retried.

A residual race remains by construction: Linear's `issueCreate` exposes no
idempotency key, so a write that lands between the reconciliation query and the
retry still duplicates. The duplicate-cancellation pass converges that case on a
later run.

### Exit Status

`RunResult.Err` decides the process exit status, and it is deliberately narrow:
the run fails only when state-changing work was left permanently unapplied.

- `FailedOps` is incremented *after* the per-entry retry has itself failed, or
  after an ambiguous batch create whose reconciliation query failed and whose
  entries were deliberately left for the next run. So a batch failure recovered
  by retry leaves it at zero and the run succeeds — the operation applied, it
  just took two calls. A non-zero count fails the run, because a run that logs a
  dropped ticket and then reports success means nothing downstream notices, and
  the next scheduled run reports success again.
- `FailedComments` is excluded. A missing change comment leaves the synced issue
  state correct, and the feature is opt-in via `LINEAR_COMMENTS`, so it is counted
  and logged but does not fail the run.

The check runs after the `sync complete` summary log, so the counts are reported
regardless of the exit status.

## SQLite Cache

The SQLite cache stores:

- Snyk DAST-side normalized hashes keyed by fingerprint
- Linear-side normalized hashes keyed by fingerprint
- a schema signature for the managed issue format
- the sync's memory of time-limited acceptances, keyed by fingerprint (below)

The hashes are used only as an optimization and are never the only source
used to infer real current state. The acceptance memory is the one exception,
by necessity: it holds what Snyk DAST reported and has since stopped
reporting.

Normal behavior:

1. Read live Snyk DAST data.
2. Read live Linear data.
3. Compare both against the last successful cached hashes.
4. Skip unchanged fingerprints.
5. After successful writes, refresh the cache from the live post-write Linear snapshot.

The post-write refresh matters because Linear may rewrite markdown bodies after
mutation.

The cache fast-path never suppresses a pending move into a terminal state
(`Done`/`Cancelled`): a finding that became fixed or permanently
accepted/invalidated while its ticket sat in an open column must still be
closed, even if its hashes are unchanged since the last run.

### Acceptance Memory

Snyk DAST reverts a finding whose time-limited acceptance has expired to
`notfixed`, and the expiry is then no longer part of what the finding
reports, while it is the base of the ticket's due date for good. Whether the
reverted finding still echoes its past `expiration_date` is not documented,
and the sync does not depend on it. The `snyk_dast_acceptances` table
remembers, per fingerprint, the expiry as reported, the instant the
acceptance stops applying (the end of the expiry day for a date-only value),
and when Snyk DAST last confirmed the acceptance. Nothing is aged out on
read. Snyk DAST stays authoritative: the memory only records what it
previously reported, and a row is forgotten only when Snyk DAST contradicts
it. Per finding, on every snapshot load:

- a finding reported as `accepted` with an expiry replaces its row with that
  expiry and refreshes the confirmation time (the latest report wins, so a
  new acceptance supersedes an older one);
- a finding reported as `accepted` without an expiry (a permanent acceptance)
  drops its row: the permanent decision supersedes the time-limited one;
- a finding no longer reported as `accepted` keeps a row whose expiry has
  lapsed, for good, and the remembered expiry is the due-date base whatever
  state the finding is in (`notfixed`, `retesting`, `fixed`, `invalid`);
- a finding no longer reported as `accepted` while the remembered expiry is
  still ahead contradicts the memory: the acceptance was revoked (or the
  finding was fixed or invalidated before the acceptance ran out). The row is
  kept for seven days of grace from the last confirmation, so a partial or
  stale response does not move the due date, then dropped and logged;
- a fingerprint absent from the snapshot (its target was deleted) keeps its
  row unchanged: Snyk DAST said nothing about it, and the row is inert.

A row without a usable confirmation time is kept; its grace clock starts on
the next run that sees it. A memory that cannot be read or written fails the
snapshot load before any Linear reconciliation: a newly reported acceptance
must be remembered before it becomes a due-date base, and a finding must not
be reconciled from a partial memory. `--bypass-cache` bypasses the hashes
only; it does not touch the acceptance memory. The memory is refreshed on dry
runs too, since it records what Snyk DAST reported rather than anything the
sync did.

### Cold-Start Guard

With an empty acceptance memory, the sync cannot tell an earlier due date
that is a real change from one that merely reflects an expiry it no longer
knows about. A run that starts with no remembered acceptances while the
Linear snapshot holds managed open tickets with due dates therefore engages a
guard: for a matched open ticket whose desired due date is earlier than its
current one, the current date is kept this run (the reason says why) and the
run warns with the count, reported as `held_due_dates`. Later dates still
apply. Before loading can populate the memory, `acceptances_memory_state` in
`sync_meta` records a pending empty start. Both sync and diagnostic loads
preserve this evidence across failures or interruptions, even when rows were
already committed. After a successful pair of snapshots, an open dated ticket
promotes that pending state to the `acceptances_cold_start_at` guard;
otherwise the memory is marked trusted and no guard is engaged. The guard
holds until `--clear-acceptances-cold-start` records trusted memory and
removes the marker. Trust persists even when the table stays empty, including
on subsequent normal runs. Deleting only the guard key does not release
pending memory; use the flag.

The guard is for a lost memory, not a new one. A cache a previous run wrote
(the snapshot save records the schema signature and the hash rows on every
successful run) but that has no acceptance rows is an upgrade from a version
without the memory: no expiry was ever remembered, so none was lost, the
memory is marked trusted from the start and earlier due dates are written as
usual. Only a cache with no prior run data (a new file, or an Actions cache
miss) records a pending start. Either way the memory can only remember what
it has seen: a ticket whose due date had already regressed is not moved later
until Snyk DAST reports the acceptance again.

## Safety Assumptions

- The metadata block must remain intact.
- The managed description body is owned by this tool.
- The Linear team may be shared with another sync, so the snapshot query must
  scope to this tool's own tickets by exact predicates (title prefix, managed
  label) rather than by matching the fingerprint metadata block, which does not
  bound the result set.
- Labels are *not* owned by this tool. Unrelated labels are preserved, and any
  label named in `LINEAR_PROTECTED_LABELS` is treated as another actor's state:
  never written, never deleted, and read live rather than from the snapshot.
- Linear issue history matters, so deleting and recreating all issues is a last resort, not a normal repair path.
- Cache bypass is the correct operator action when the rendering schema or compare logic changes.

## Operator Guidance

After any code change, run:

```bash
go fix ./...
go test ./...
go vet ./...
```

Use a normal run for day-to-day sync:

```bash
go run ./cmd/snyk-dast-linear-sync --env-file .env
```

Use a dry run to inspect planned changes:

```bash
go run ./cmd/snyk-dast-linear-sync --env-file .env --dry-run
```

Use cache bypass when you intentionally changed the managed rendering or need a
full live reconciliation:

```bash
go run ./cmd/snyk-dast-linear-sync --env-file .env --bypass-cache
```

Cache bypass does not touch the acceptance memory. After a run has warned that
the acceptance memory was cold, release the held due dates once the memory is
trusted (for example after the acceptances have been re-seeded from Snyk DAST
and checked):

```bash
go run ./cmd/snyk-dast-linear-sync --env-file .env --clear-acceptances-cold-start
```

## Design Boundaries

If this project grows further, the next reasonable extensions would be:

- richer incremental Snyk DAST fetching using server timestamps where available
- more selective Linear snapshot loading if the API surface allows it safely
- richer cache statistics and observability
- explicit conflict reporting output

The current implementation is intentionally optimized for correctness first,
then steady-state efficiency.
