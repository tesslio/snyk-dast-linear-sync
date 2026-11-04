package sync

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tesslio/snyk-dast-linear-sync/internal/cache"
	"github.com/tesslio/snyk-dast-linear-sync/internal/model"
)

// The tests in this file cover the due dates the sync derives from what the
// Snyk DAST loader remembers about time-limited acceptances, and the
// cold-start guard that protects due dates while that memory is empty.

func rememberedFinding() model.Finding {
	return model.Finding{
		Fingerprint:       "snyk-dast:target-a:1",
		SnykDASTFindingID: "1",
		TargetID:          "target-a",
		TargetName:        "Example App",
		TargetHost:        "app.example.test",
		IssueTitle:        "Example vulnerability",
		Severity:          "high",
		Status:            model.FindingOpen,
		CreatedAt:         time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
}

// storedIssue is the Linear ticket the sync would have written for desired.
func storedIssue(id, identifier, stateName string, desired model.DesiredIssue) model.ExistingIssue {
	return model.ExistingIssue{
		ID:            id,
		Identifier:    identifier,
		Title:         desired.Title,
		Description:   desired.Description,
		DueDate:       desired.DueDate,
		StateName:     stateName,
		Fingerprint:   desired.Fingerprint,
		ManagedLabels: desired.ManagedLabels,
		Priority:      desired.Priority,
	}
}

func singleFindingSnapshot(finding model.Finding) fakeSnykDAST {
	return fakeSnykDAST{snapshot: model.SnykDASTSnapshot{
		Findings:          []model.Finding{finding},
		TargetIDs:         map[string]struct{}{finding.TargetID: {}},
		InactiveTargetIDs: map[string]struct{}{},
	}}
}

// TestRunLapsedAcceptanceDueDateIsStableAcrossRuns is the sync half of the
// regression: a ticket whose due date is the acceptance expiry + SLA must not
// be touched on later runs, once the loader keeps the expiry from its memory
// while Snyk DAST reports the finding as notfixed without one.
func TestRunLapsedAcceptanceDueDateIsStableAcrossRuns(t *testing.T) {
	cfg := minimalCfg()
	finding := rememberedFinding()
	finding.Severity = "medium"
	finding.IgnoreExpiresAt = time.Date(2026, time.February, 10, 0, 0, 0, 0, time.UTC)
	finding.AcceptanceRemembered = true

	existing := storedIssue("existing-1", "SEC-1", "Todo", desiredIssue(cfg, finding))
	if existing.DueDate != "2026-03-27" {
		t.Fatalf("fixture: due date = %q, want 2026-03-27 (expiry + 45 days)", existing.DueDate)
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}
	result, err := New(cfg, discardLogger(), singleFindingSnapshot(finding), linear, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d (%+v), want 0", result.PlannedUpdates, linear.updated)
	}

	// Had the loader forgotten the expiry, the date would regress.
	forgotten := finding
	forgotten.IgnoreExpiresAt = time.Time{}
	forgotten.AcceptanceRemembered = false
	if regressed := desiredIssue(cfg, forgotten); regressed.DueDate >= existing.DueDate {
		t.Fatalf("fixture: without the expiry the due date %q should be earlier than %q", regressed.DueDate, existing.DueDate)
	}
}

// TestRunColdStartGuardHoldsEarlierDueDates: on a run that starts with an
// empty acceptance memory while Linear holds open tickets with due dates, an
// earlier desired due date is not written (it may only reflect an acceptance
// expiry the sync has no memory of), a warning names the count, and a marker
// keeps the guard holding on later runs, even once the memory has rows. A
// later desired date still applies. Clearing the marker releases the guard.
func TestRunColdStartGuardHoldsEarlierDueDates(t *testing.T) {
	cfg := minimalCfg()
	finding := rememberedFinding()
	// Desired: created_at + 30 = 2026-01-31. The ticket was written with a
	// later date by an earlier run that still saw the acceptance.
	existing := storedIssue("existing-1", "SEC-1", "Todo", desiredIssue(cfg, finding))
	existing.DueDate = "2026-06-30"

	store := &fakeCache{}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	run := func(name string, f model.Finding, snapshot []model.ExistingIssue) (RunResult, *fakeLinear) {
		t.Helper()
		logs.Reset()
		store.snapshot = store.saved
		linear := &fakeLinear{snapshot: snapshot}
		result, err := New(cfg, logger, singleFindingSnapshot(f), linear, store).Run(context.Background())
		if err != nil {
			t.Fatalf("%s: Run() error = %v", name, err)
		}
		return result, linear
	}

	// Run 1: empty memory, open dated ticket: the guard engages.
	result, linear := run("cold start", finding, []model.ExistingIssue{existing})
	if len(linear.updated) != 0 {
		t.Fatalf("cold start: updated %+v, want nothing (the earlier date is held)", linear.updated)
	}
	if result.HeldDueDates != 1 {
		t.Fatalf("cold start: HeldDueDates = %d, want 1", result.HeldDueDates)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "held_due_dates=1") {
		t.Fatalf("cold start: want a warning naming the held count, got:\n%s", logs.String())
	}
	since, ok := store.meta[acceptancesColdStartMetaKey]
	if !ok || since == "" {
		t.Fatalf("cold start: marker %q not set in cache meta: %v", acceptancesColdStartMetaKey, store.meta)
	}

	// Run 2: the memory has rows now, but the marker still holds.
	store.acceptanceRows = true
	result, linear = run("marker holds", finding, []model.ExistingIssue{existing})
	if len(linear.updated) != 0 || result.HeldDueDates != 1 {
		t.Fatalf("marker holds: updated %+v held %d, want nothing updated and 1 held", linear.updated, result.HeldDueDates)
	}

	// Run 3: a later desired date is a real change and is written.
	later := finding
	later.IgnoreExpiresAt = time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	later.AcceptanceRemembered = true
	result, linear = run("later date", later, []model.ExistingIssue{existing})
	if len(linear.updated) != 1 || linear.updated[0].DueDate != "2026-10-01" {
		t.Fatalf("later date: updated %+v, want one update to 2026-10-01", linear.updated)
	}
	if result.HeldDueDates != 0 {
		t.Fatalf("later date: HeldDueDates = %d, want 0", result.HeldDueDates)
	}

	// Run 4: the operator clears the marker; the earlier date is written.
	cfg.Cache.ClearAcceptancesColdStart = true
	result, linear = run("cleared", finding, []model.ExistingIssue{existing})
	if _, ok := store.meta[acceptancesColdStartMetaKey]; ok {
		t.Fatalf("cleared: marker still set: %v", store.meta)
	}
	if len(linear.updated) != 1 || linear.updated[0].DueDate != "2026-01-31" {
		t.Fatalf("cleared: updated %+v, want one update to 2026-01-31", linear.updated)
	}
	if result.HeldDueDates != 0 || strings.Contains(logs.String(), "cold-start guard is holding") {
		t.Fatalf("cleared: HeldDueDates = %d, logs:\n%s", result.HeldDueDates, logs.String())
	}

	// Run 5: the guard stays released (rows present, no marker) and the
	// ticket, now carrying the earlier date, is at steady state.
	cfg.Cache.ClearAcceptancesColdStart = false
	written := storedIssue("existing-1", "SEC-1", "Todo", linear.updated[0])
	if result, linear = run("released", finding, []model.ExistingIssue{written}); len(linear.updated) != 0 || result.HeldDueDates != 0 {
		t.Fatalf("released: updated %+v held %d, want steady state", linear.updated, result.HeldDueDates)
	}
	if _, ok := store.meta[acceptancesColdStartMetaKey]; ok {
		t.Fatalf("released: marker re-set: %v", store.meta)
	}
}

// TestRunUpgradeFromPriorCacheDoesNotEngageGuard: the first run of this
// version against a cache a previous version wrote finds the acceptance
// table empty, but nothing was lost (no expiry was ever remembered), so an
// earlier due date is a real change and is written, no marker is left, and
// the memory is trusted. Only a cache with no prior run data (a new or lost
// file) engages the guard, as TestRunColdStartGuardHoldsEarlierDueDates
// covers.
func TestRunUpgradeFromPriorCacheDoesNotEngageGuard(t *testing.T) {
	cfg := minimalCfg()
	finding := rememberedFinding()
	existing := storedIssue("existing-1", "SEC-1", "Todo", desiredIssue(cfg, finding))
	existing.DueDate = "2026-06-30"
	store := &fakeCache{snapshot: cache.Snapshot{
		SchemaSignature: managedSchemaSignature(),
		SnykDASTHashes:  map[string]string{"snyk-dast:target-a:9": "stale"},
		LinearHashes:    map[string]string{"snyk-dast:target-a:9": "stale"},
	}}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	linear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}
	result, err := New(cfg, logger, singleFindingSnapshot(finding), linear, store).Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(linear.updated) != 1 || linear.updated[0].DueDate != "2026-01-31" {
		t.Fatalf("upgrade: updated %+v, want one update to the earlier date 2026-01-31", linear.updated)
	}
	if result.HeldDueDates != 0 || strings.Contains(logs.String(), "cold-start") {
		t.Fatalf("upgrade: HeldDueDates = %d, logs:\n%s", result.HeldDueDates, logs.String())
	}
	if _, ok := store.meta[acceptancesColdStartMetaKey]; ok {
		t.Fatalf("upgrade: marker set: %v", store.meta)
	}
	if state := store.meta[cache.AcceptanceMemoryStateKey]; state != cache.AcceptanceMemoryTrusted {
		t.Fatalf("upgrade: memory state = %q, want trusted", state)
	}
}

// TestRunColdStartGuardNeedsOpenDatedTickets: an empty memory on a fresh
// deployment with nothing open and dated in Linear has nothing to protect,
// so no marker is left behind and the memory is marked trusted.
func TestRunColdStartGuardNeedsOpenDatedTickets(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Done = "Done"
	finding := rememberedFinding()
	done := storedIssue("existing-1", "SEC-1", "Done", desiredIssue(cfg, finding))
	done.DueDate = "2026-06-30"
	store := &fakeCache{}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{done}}
	result, err := New(cfg, discardLogger(), singleFindingSnapshot(finding), linear, store).Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if _, ok := store.meta[acceptancesColdStartMetaKey]; ok {
		t.Fatalf("marker set with only a closed dated ticket: %v", store.meta)
	}
	if result.HeldDueDates != 0 {
		t.Fatalf("HeldDueDates = %d, want 0", result.HeldDueDates)
	}
	if state := store.meta["acceptances_memory_state"]; state != "trusted" {
		t.Fatalf("memory state = %q, want trusted after a run with nothing to protect", state)
	}
}

type snapshotLoaderFunc func(context.Context) (model.SnykDASTSnapshot, error)

func (f snapshotLoaderFunc) LoadSnapshot(ctx context.Context) (model.SnykDASTSnapshot, error) {
	return f(ctx)
}

type failingSnapshotLinear struct {
	*fakeLinear
	seeded <-chan struct{}
}

func (l failingSnapshotLinear) LoadSnapshot(context.Context) ([]model.ExistingIssue, error) {
	<-l.seeded
	return nil, errors.New("fixture snapshot failure")
}

// TestRunColdStartSurvivesFailedLoads: a run that seeds the memory and then
// fails (either snapshot) must not leave a populated memory that looks
// trusted on the retry; the empty start is remembered and the guard still
// engages.
func TestRunColdStartSurvivesFailedLoads(t *testing.T) {
	for _, failing := range []string{"linear", "snyk-dast-after-commit"} {
		t.Run(failing, func(t *testing.T) {
			cfg := minimalCfg()
			finding := rememberedFinding()
			existing := storedIssue("existing-1", "SEC-1", "Todo", desiredIssue(cfg, finding))
			existing.DueDate = "2026-06-30"
			store := &fakeCache{}
			seeded := make(chan struct{})
			snykdast := snapshotLoaderFunc(func(context.Context) (model.SnykDASTSnapshot, error) {
				store.acceptanceRows = true // the loader independently committed rows
				close(seeded)
				if failing == "snyk-dast-after-commit" {
					return model.SnykDASTSnapshot{}, errors.New("fixture post-commit failure")
				}
				return singleFindingSnapshot(finding).snapshot, nil
			})
			var linear LinearClient = &fakeLinear{snapshot: []model.ExistingIssue{existing}}
			if failing == "linear" {
				linear = failingSnapshotLinear{fakeLinear: &fakeLinear{}, seeded: seeded}
			}
			if _, err := New(cfg, discardLogger(), snykdast, linear, store).Run(context.Background()); err == nil {
				t.Fatal("want failed load")
			}
			if !store.acceptanceRows {
				t.Fatal("fixture did not seed the memory")
			}
			retryLinear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}
			result, err := New(cfg, discardLogger(), singleFindingSnapshot(finding), retryLinear, store).Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if result.HeldDueDates != 1 || len(retryLinear.updated) != 0 {
				t.Fatalf("retry lost protection: held %d updates %+v", result.HeldDueDates, retryLinear.updated)
			}
		})
	}
}

// TestRunClearColdStartWithNoAcceptancesStaysReleased: clearing the marker
// is a durable release even when Snyk DAST has no acceptances to remember,
// so the next normal run does not engage the guard again.
func TestRunClearColdStartWithNoAcceptancesStaysReleased(t *testing.T) {
	cfg := minimalCfg()
	cfg.Cache.ClearAcceptancesColdStart = true
	finding := rememberedFinding()
	existing := storedIssue("existing-1", "SEC-1", "Todo", desiredIssue(cfg, finding))
	existing.DueDate = "2026-06-30"
	store := &fakeCache{meta: map[string]string{acceptancesColdStartMetaKey: "2026-01-01T00:00:00Z"}}
	for run := range 2 {
		linear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}
		result, err := New(cfg, discardLogger(), singleFindingSnapshot(finding), linear, store).Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		// The ticket still carries the later date on the normal run, proving
		// the release is durable rather than a one-run effect.
		if result.HeldDueDates != 0 || len(linear.updated) != 1 || linear.updated[0].DueDate != "2026-01-31" {
			t.Fatalf("run %d: held %d updates %+v", run, result.HeldDueDates, linear.updated)
		}
		if _, ok := store.meta[acceptancesColdStartMetaKey]; ok {
			t.Fatal("marker recreated")
		}
		cfg.Cache.ClearAcceptancesColdStart = false
	}
}

// TestRunAcceptanceMemoryFailureDoesNotReconcileLinear: a load that fails
// because the memory is unavailable fails the run before Linear is written.
func TestRunAcceptanceMemoryFailureDoesNotReconcileLinear(t *testing.T) {
	cfg := minimalCfg()
	finding := rememberedFinding()
	existing := storedIssue("existing-1", "SEC-1", "Todo", desiredIssue(cfg, finding))
	linear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}
	wantErr := errors.New("fixture acceptance-memory persistence failure")
	snykdast := snapshotLoaderFunc(func(context.Context) (model.SnykDASTSnapshot, error) {
		return model.SnykDASTSnapshot{}, wantErr
	})
	if _, err := New(cfg, discardLogger(), snykdast, linear, &fakeCache{acceptanceRows: true}).Run(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("Run error = %v, want the memory failure", err)
	}
	if len(linear.created) != 0 || len(linear.updated) != 0 || len(linear.comments) != 0 {
		t.Fatalf("failed load mutated Linear: creates %d updates %d comments %d", len(linear.created), len(linear.updated), len(linear.comments))
	}
}
