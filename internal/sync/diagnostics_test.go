package sync

import (
	"testing"
	"time"

	"github.com/tesslio/snyk-dast-linear-sync/internal/config"
	"github.com/tesslio/snyk-dast-linear-sync/internal/model"
)

// TestDiagnoseDueDateReportsColdStartHold: with the cold-start marker in
// the cache, the diagnostic reports the outcome the sync would produce (the
// existing due date kept, no update for it) while still exposing the date
// the SLA alone would give.
func TestDiagnoseDueDateReportsColdStartHold(t *testing.T) {
	cfg := minimalCfg()
	finding := rememberedFinding() // created 2026-01-01, high: SLA gives 2026-01-31
	existing := storedIssue("existing-1", "SEC-1", "Todo", desiredIssue(cfg, finding))
	existing.DueDate = "2026-06-30"

	diag := DiagnoseDueDate(cfg, finding, existing, DiagnoseOptions{ColdStartGuardActive: true, ColdStartSince: "2026-03-01T00:00:00Z"})
	if !diag.DueDateHeldByColdStart || !diag.ColdStartGuardActive || diag.ColdStartSince != "2026-03-01T00:00:00Z" {
		t.Fatalf("held %v active %v since %q, want the hold reported", diag.DueDateHeldByColdStart, diag.ColdStartGuardActive, diag.ColdStartSince)
	}
	if diag.Desired.DueDate != "2026-06-30" || diag.UnguardedDueDate != "2026-01-31" {
		t.Fatalf("desired %q unguarded %q, want the held date and the SLA date", diag.Desired.DueDate, diag.UnguardedDueDate)
	}
	if diag.WouldUpdate || diag.Diff.DueDateChanged {
		t.Fatalf("WouldUpdate %v DueDateChanged %v, want no update while the date is held", diag.WouldUpdate, diag.Diff.DueDateChanged)
	}
	if diag.Desired.DueDateReason != coldStartHoldReason {
		t.Fatalf("reason = %q, want the sync's hold reason", diag.Desired.DueDateReason)
	}

	// Without the marker the same inputs report the earlier date as a change.
	diag = DiagnoseDueDate(cfg, finding, existing, DiagnoseOptions{})
	if diag.DueDateHeldByColdStart || diag.Desired.DueDate != "2026-01-31" || !diag.WouldUpdate {
		t.Fatalf("unguarded: held %v desired %q would update %v, want the SLA date written", diag.DueDateHeldByColdStart, diag.Desired.DueDate, diag.WouldUpdate)
	}

	// A later desired date is never held.
	later := finding
	later.IgnoreExpiresAt = time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	diag = DiagnoseDueDate(cfg, later, existing, DiagnoseOptions{ColdStartGuardActive: true})
	if diag.DueDateHeldByColdStart || diag.Desired.DueDate != "2026-10-01" {
		t.Fatalf("later date: held %v desired %q, want written", diag.DueDateHeldByColdStart, diag.Desired.DueDate)
	}
}

func TestDiagnoseDueDateExposesCreationAndAcceptanceExpiryScenarios(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
	}
	finding := model.Finding{
		Fingerprint:       "snyk-dast:target-a:finding-1",
		SnykDASTFindingID: "su2d3k-1",
		TargetName:        "Example App",
		Severity:          "high",
		Status:            model.FindingOpen,
		CreatedAt:         time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		IgnoreExpiresAt:   time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC),
	}
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       "Snyk DAST: [high] example",
		Description: "body\n<!-- snyk-dast-linear-sync\nfingerprint: snyk-dast:target-a:finding-1\n-->",
		StateName:   "Todo",
		Fingerprint: finding.Fingerprint,
		Priority:    2,
	}

	diag := DiagnoseDueDate(cfg, finding, existing, DiagnoseOptions{})

	if !diag.WouldUpdate {
		t.Fatalf("WouldUpdate = false, want true (due date missing on existing issue)")
	}

	if len(diag.Scenarios) != 2 {
		t.Fatalf("scenarios = %d, want 2 (creation and acceptance expiry)", len(diag.Scenarios))
	}

	creation := diag.Scenarios[0]
	if creation.Name != "finding creation (CreatedAt + severity SLA)" {
		t.Fatalf("creation scenario name = %q", creation.Name)
	}
	if creation.DueDate != "2026-01-31" {
		t.Fatalf("creation due date = %q, want 2026-01-31", creation.DueDate)
	}

	acceptanceExpiry := diag.Scenarios[1]
	if acceptanceExpiry.Name != "acceptance expiry (IgnoreExpiresAt + severity SLA)" {
		t.Fatalf("acceptance expiry scenario name = %q", acceptanceExpiry.Name)
	}
	if acceptanceExpiry.DueDate != "2026-07-01" {
		t.Fatalf("acceptance expiry due date = %q, want 2026-07-01", acceptanceExpiry.DueDate)
	}

	if diag.Desired.DueDate != "2026-07-01" {
		t.Fatalf("desired due date = %q, want 2026-07-01 (acceptance expiry wins)", diag.Desired.DueDate)
	}
}

func TestDiagnoseDueDateWasSnoozedWhenFindingStatusIsSnoozed(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{HighDays: 30},
		},
	}
	finding := model.Finding{
		Fingerprint:       "snyk-dast:target-a:finding-1",
		SnykDASTFindingID: "su2d3k-1",
		TargetName:        "Example App",
		Severity:          "high",
		Status:            model.FindingSnoozed,
		CreatedAt:         time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       "Snyk DAST: [high] example",
		Description: "body\n<!-- snyk-dast-linear-sync\nfingerprint: snyk-dast:target-a:finding-1\n-->",
		StateName:   "Todo",
		Fingerprint: finding.Fingerprint,
		Priority:    2,
	}

	diag := DiagnoseDueDate(cfg, finding, existing, DiagnoseOptions{})

	if !diag.WasSnoozed {
		t.Fatal("WasSnoozed = false, want true")
	}
}
