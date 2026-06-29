package sync

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RichardoC/snyk-dast-linear-sync/internal/cache"
	"github.com/RichardoC/snyk-dast-linear-sync/internal/config"
	"github.com/RichardoC/snyk-dast-linear-sync/internal/model"
)

type fakeSnykDAST struct {
	snapshot model.SnykDASTSnapshot
}

func (f fakeSnykDAST) LoadSnapshot(context.Context) (model.SnykDASTSnapshot, error) {
	return f.snapshot, nil
}

type fakeLinear struct {
	snapshot []model.ExistingIssue
	created  []model.DesiredIssue
	updated  []model.DesiredIssue
	updates  []model.IssueUpdate
	comments []model.IssueUpdate
}

type fakeCache struct {
	snapshot cache.Snapshot
	saved    cache.Snapshot
}

func (f *fakeLinear) LoadSnapshot(context.Context) ([]model.ExistingIssue, error) {
	return f.snapshot, nil
}

func (f *fakeLinear) CreateIssues(_ context.Context, desired []model.DesiredIssue) error {
	f.created = append(f.created, desired...)
	return nil
}

func (f *fakeLinear) UpdateIssues(_ context.Context, updates []model.IssueUpdate) error {
	for _, update := range updates {
		f.updated = append(f.updated, update.Desired)
		f.updates = append(f.updates, update)
	}
	return nil
}

func (f *fakeLinear) PostComments(_ context.Context, updates []model.IssueUpdate) error {
	f.comments = append(f.comments, updates...)
	return nil
}

func (f *fakeCache) Load(context.Context) (cache.Snapshot, error) {
	return f.snapshot, nil
}

func (f *fakeCache) Save(_ context.Context, snapshot cache.Snapshot) error {
	f.saved = snapshot
	return nil
}

func TestRunPlansCreateUpdateAndResolve(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{
			Workers: 1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:       "snyk-dast:target-a:finding-1",
					SnykDASTFindingID: "su2d3k-1",
					TargetID:          "target-a",
					TargetName:        "Example App",
					TargetHost:        "example.com",
					IssueTitle:        "Reflected XSS",
					Severity:          "high",
					Status:            model.FindingOpen,
					IssueURL:          "https://app.probely.com/targets/target-a/findings/1",
					CreatedAt:         time.Date(2026, time.August, 1, 14, 0, 0, 0, time.UTC),
				},
				{
					Fingerprint:       "snyk-dast:target-b:finding-2",
					SnykDASTFindingID: "su2d3k-2",
					TargetID:          "target-b",
					TargetName:        "Other App",
					IssueTitle:        "SQL Injection",
					Severity:          "low",
					Status:            model.FindingIgnored,
					IssueURL:          "https://app.probely.com/targets/target-b/findings/2",
					CreatedAt:         time.Date(2026, time.August, 1, 9, 0, 0, 0, time.UTC),
				},
			},
			TargetIDs: map[string]struct{}{
				"target-a": {},
				"target-b": {},
				"target-z": {},
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk-dast:target-a:finding-1",
			},
			{
				ID:          "existing-2",
				Identifier:  "SEC-2",
				Title:       "old resolved issue",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk-dast:target-z:finding-9",
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedCreates != 1 {
		t.Fatalf("PlannedCreates = %d, want 1", result.PlannedCreates)
	}
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.created) != 1 {
		t.Fatalf("created = %d, want 1", len(linear.created))
	}
	if len(linear.updated) != 2 {
		t.Fatalf("updated = %d, want 2", len(linear.updated))
	}
	if linear.created[0].DueDate != "2026-10-30" {
		t.Fatalf("created due date = %q, want %q", linear.created[0].DueDate, "2026-10-30")
	}
	if !containsDesiredState(linear.updated, model.StateDone) {
		t.Fatalf("updated states = %#v, want one %q", desiredStates(linear.updated), model.StateDone)
	}
}

func TestRunSkipsCachedUnchangedIssue(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{
			Workers: 1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:       "snyk-dast:target-a:finding-1",
					SnykDASTFindingID: "su2d3k-1",
					TargetID:          "target-a",
					TargetName:        "Example App",
					TargetHost:        "example.com",
					IssueTitle:        "Reflected XSS",
					Severity:          "high",
					Status:            model.FindingOpen,
					IssueURL:          "https://app.probely.com/targets/target-a/findings/1",
					IssueAPIURL:       "https://api.probely.com/findings/1/",
					CreatedAt:         time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			TargetIDs: map[string]struct{}{
				"target-a": {},
			},
		},
	}
	desired := desiredIssue(cfg, snykdast.snapshot.Findings[0])
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       desired.Title,
		Description: desired.Description,
		DueDate:     desired.DueDate,
		StateName:   "Todo",
		Fingerprint: desired.Fingerprint,
		Priority:    desired.Priority,
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			SnykDASTHashes: map[string]string{
				desired.Fingerprint: desiredIssueHash(desired),
			},
			LinearHashes: map[string]string{
				desired.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{existing},
	}

	service := New(cfg, logger, snykdast, linear, cacheStore)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

// TestRunCancelsIgnoredFindingEvenIfCached verifies that a finding which is
// ignored in Snyk DAST (desired state Cancelled) is moved to Cancelled even
// when its ticket was manually parked in "Todo" and the cache claims nothing
// changed.
func TestRunCancelsIgnoredFindingEvenIfCached(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:       "snyk-dast:target-a:finding-1",
					SnykDASTFindingID: "su2d3k-1",
					TargetID:          "target-a",
					TargetName:        "Example App",
					IssueTitle:        "Information Disclosure",
					Severity:          "low",
					Status:            model.FindingIgnored,
					CreatedAt:         time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}
	desired := desiredIssue(cfg, snykdast.snapshot.Findings[0])
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       desired.Title,
		Description: desired.Description,
		DueDate:     desired.DueDate,
		StateName:   "Todo",
		Fingerprint: desired.Fingerprint,
		Priority:    desired.Priority,
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			SnykDASTHashes: map[string]string{
				desired.Fingerprint: desiredIssueHash(desired),
			},
			LinearHashes: map[string]string{
				desired.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}

	service := New(cfg, logger, snykdast, linear, cacheStore)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("updated state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

// TestRunCacheStillSkipsNonTerminalStateDivergence locks in the narrow scope
// of the terminal-transition cache guard: an open finding whose ticket
// diverges only in a non-terminal state must still be cache-suppressed when
// its hashes are unchanged.
func TestRunCacheStillSkipsNonTerminalStateDivergence(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:       "snyk-dast:target-a:finding-1",
					SnykDASTFindingID: "su2d3k-1",
					TargetID:          "target-a",
					TargetName:        "Example App",
					IssueTitle:        "Reflected XSS",
					Severity:          "high",
					Status:            model.FindingOpen, // desired Todo — non-terminal
					CreatedAt:         time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}
	desired := desiredIssue(cfg, snykdast.snapshot.Findings[0]) // State == Todo
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       desired.Title,
		Description: desired.Description,
		DueDate:     desired.DueDate,
		StateName:   "Triage",
		Fingerprint: desired.Fingerprint,
		Priority:    desired.Priority,
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			SnykDASTHashes: map[string]string{
				desired.Fingerprint: desiredIssueHash(desired),
			},
			LinearHashes: map[string]string{
				desired.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{snapshot: []model.ExistingIssue{existing}}

	service := New(cfg, logger, snykdast, linear, cacheStore)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (non-terminal divergence stays cached)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

func TestRunCancelsMissingIssueWhenTargetDeleted(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			TargetIDs: map[string]struct{}{
				"target-a": {},
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "missing target issue",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk-dast:target-z:finding-9",
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("resolved state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

func TestRunCancelsMissingIssueWhenTargetDeletedEvenIfCached(t *testing.T) {
	cfg := config.Config{
		Cache: config.CacheConfig{},
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			TargetIDs: map[string]struct{}{
				"target-a": {},
			},
		},
	}
	existing := model.ExistingIssue{
		ID:          "existing-1",
		Identifier:  "SEC-1",
		Title:       "missing target issue",
		Description: "old description",
		StateName:   "Todo",
		Fingerprint: "snyk-dast:target-z:finding-9",
	}
	cacheStore := &fakeCache{
		snapshot: cache.Snapshot{
			SchemaSignature: managedSchemaSignature(),
			LinearHashes: map[string]string{
				existing.Fingerprint: existingIssueHash(existing),
			},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{existing},
	}

	service := New(cfg, logger, snykdast, linear, cacheStore)

	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(linear.updated))
	}
	if linear.updated[0].State != model.StateCancelled {
		t.Fatalf("resolved state = %q, want %q", linear.updated[0].State, model.StateCancelled)
	}
}

func TestNeedsUpdateUsesCaseInsensitiveLabels(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-01",
		State:       model.StateTodo,
		Priority:    2,
	}

	if needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = true, want false")
	}
}

func containsDesiredState(desired []model.DesiredIssue, state model.IssueState) bool {
	for _, issue := range desired {
		if issue.State == state {
			return true
		}
	}
	return false
}

func desiredStates(desired []model.DesiredIssue) []model.IssueState {
	out := make([]model.IssueState, 0, len(desired))
	for _, issue := range desired {
		out = append(out, issue.State)
	}
	return out
}

func TestDesiredIssueDueDateUsesCreatedAt(t *testing.T) {
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
		Severity:          "critical",
		Status:            model.FindingOpen,
		CreatedAt:         time.Date(2026, time.August, 11, 23, 30, 0, 0, time.FixedZone("minus0500", -5*60*60)),
	}

	desired := desiredIssue(cfg, finding)

	if desired.DueDate != "2026-08-27" {
		t.Fatalf("desired due date = %q, want %q", desired.DueDate, "2026-08-27")
	}
}

func TestDesiredIssueDueDateLeavesPastSLAAsIs(t *testing.T) {
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
	}

	desired := desiredIssue(cfg, finding)

	if desired.DueDate != "2026-01-31" {
		t.Fatalf("desired due date = %q, want %q (raw SLA date for past issues)", desired.DueDate, "2026-01-31")
	}
}

func TestDesiredIssueDueDateUsesAcceptanceExpiryWhenSnoozed(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				HighDays: 30,
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

	desired := desiredIssue(cfg, finding)

	// IgnoreExpiresAt wins over CreatedAt: June 1 + 30 days = July 1.
	if desired.DueDate != "2026-07-01" {
		t.Fatalf("desired due date = %q, want %q (acceptance expiry + high offset)", desired.DueDate, "2026-07-01")
	}
}

func TestDesiredIssueRendersDASTContext(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Labels: config.LabelConfig{
				Managed:           "snyk-dast-automation",
				TargetType:        map[string]string{"api": "snyk-dast-api"},
				TargetTypeDefault: "snyk-dast-web",
			},
		},
	}
	finding := model.Finding{
		Fingerprint:       "snyk-dast:target-a:finding-1",
		SnykDASTFindingID: "su2d3k-1",
		TargetID:          "target-a",
		TargetName:        "Example API",
		TargetType:        "api",
		TargetURL:         "https://api.example.com",
		TargetHost:        "api.example.com",
		IssueTitle:        "Broken Access Control",
		Severity:          "high",
		Status:            model.FindingOpen,
		IssueURL:          "https://app.probely.com/targets/target-a/findings/1",
		IssueAPIURL:       "https://api.probely.com/findings/1/",
		FindingURL:        "https://api.example.com/users/42",
		Method:            "get",
		Path:              "users/42",
		Parameter:         "id",
		InsertionPoint:    "parameter",
		CWE:               "CWE-284",
		CWEName:           "Improper Access Control",
		CVSS:              7.5,
	}

	desired := desiredIssue(cfg, finding)

	if desired.Title != "Snyk DAST: [high] api.example.com: Broken Access Control at GET users/42" {
		t.Fatalf("title = %q", desired.Title)
	}
	if !strings.Contains(desired.Description, "## Broken Access Control [HIGH]") {
		t.Fatalf("description missing heading: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "URL: [GET users/42](https://api.example.com/users/42)") {
		t.Fatalf("description missing vulnerable URL line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Method: `GET`") {
		t.Fatalf("description missing method line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Path: `users/42`") {
		t.Fatalf("description missing path line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Parameter: `id` (Parameter)") {
		t.Fatalf("description missing parameter line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "CWE: `CWE-284` (Improper Access Control)") {
		t.Fatalf("description missing CWE line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "CVSS: `7.5`") {
		t.Fatalf("description missing CVSS line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Snyk DAST: [Open finding](https://app.probely.com/targets/target-a/findings/1)") {
		t.Fatalf("description missing Snyk DAST link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "API: [Finding details](https://api.probely.com/findings/1/)") {
		t.Fatalf("description missing API link: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Status: `open`") {
		t.Fatalf("description missing status line: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "managed_labels: snyk-dast-api,snyk-dast-automation") {
		t.Fatalf("description missing managed labels metadata: %s", desired.Description)
	}
	// NormalizeManagedLabelNames sorts labels alphabetically, so snyk-dast-api
	// precedes snyk-dast-automation regardless of insertion order.
	if len(desired.ManagedLabels) != 2 || desired.ManagedLabels[0] != "snyk-dast-api" || desired.ManagedLabels[1] != "snyk-dast-automation" {
		t.Fatalf("ManagedLabels = %#v, want [snyk-dast-api snyk-dast-automation]", desired.ManagedLabels)
	}
}

func TestDesiredIssueRendersSnykCodeCorrelation(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Labels: config.LabelConfig{
				Managed: "snyk-dast-automation",
			},
		},
	}
	finding := model.Finding{
		Fingerprint:       "snyk-dast:target-a:finding-1",
		SnykDASTFindingID: "su2d3k-1",
		TargetID:          "target-a",
		TargetName:        "Example API",
		TargetHost:        "api.example.com",
		IssueTitle:        "SQL Injection",
		Severity:          "high",
		Status:            model.FindingOpen,
		Method:            "get",
		Path:              "users/42",
		CorrelationMarkdown: []string{
			"**Snyk Code:** [SQL Injection in `src/db/query.go:42`](https://app.snyk.io/org/example/project/abc#issue-SNYK-GO-1234)",
			"Repository: `owner/repo` — confirmed correlation",
		},
	}

	desired := desiredIssue(cfg, finding)

	if !strings.Contains(desired.Description, "### Snyk Code correlation") {
		t.Fatalf("description missing Snyk Code correlation heading: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Linked Snyk Code source vulnerability responsible for this runtime finding.") {
		t.Fatalf("description missing correlation subtitle: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "SQL Injection in `src/db/query.go:42`") {
		t.Fatalf("description missing correlation markdown block: %s", desired.Description)
	}
	if !strings.Contains(desired.Description, "Repository: `owner/repo`") {
		t.Fatalf("description missing second correlation block: %s", desired.Description)
	}
}

func TestDesiredIssueOmitsCorrelationSectionWhenEmpty(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Labels: config.LabelConfig{Managed: "snyk-dast-automation"},
		},
	}
	finding := model.Finding{
		Fingerprint:       "snyk-dast:target-a:finding-1",
		SnykDASTFindingID: "su2d3k-1",
		TargetName:        "Example App",
		IssueTitle:        "XSS",
		Severity:          "medium",
		Status:            model.FindingOpen,
	}

	desired := desiredIssue(cfg, finding)

	if strings.Contains(desired.Description, "Snyk Code correlation") {
		t.Fatalf("description should not contain correlation section when empty: %s", desired.Description)
	}
}

func TestDesiredIssueUsesTargetTypeDefaultLabel(t *testing.T) {
	cfg := config.Config{
		Linear: config.LinearConfig{
			Labels: config.LabelConfig{
				Managed:           "snyk-dast-automation",
				TargetTypeDefault: "snyk-dast-web",
			},
		},
	}
	finding := model.Finding{
		Fingerprint: "snyk-dast:target-a:finding-1",
		TargetType:  "single",
		IssueTitle:  "XSS",
		Severity:    "medium",
		Status:      model.FindingOpen,
	}

	desired := desiredIssue(cfg, finding)

	found := false
	for _, label := range desired.ManagedLabels {
		if label == "snyk-dast-web" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ManagedLabels = %#v, want snyk-dast-web fallback", desired.ManagedLabels)
	}
}

func TestIssueTitleUsesTargetNameWhenNoHost(t *testing.T) {
	finding := model.Finding{
		IssueTitle: "TLS Misconfiguration",
		Severity:   "medium",
		TargetName: "Marketing Site",
		Path:       "login",
		Method:     "post",
	}

	title := issueTitle(finding)

	if title != "Snyk DAST: [medium] Marketing Site: TLS Misconfiguration at POST login" {
		t.Fatalf("title = %q", title)
	}
}

func TestUpsertManagedMetadataRemovesVisibleFingerprintFooter(t *testing.T) {
	description := "Status: `open`\n\n<!-- snyk-dast-linear-sync\nfingerprint: snyk-dast:target-a:finding-1\n-->\nFingerprint: snyk-dast:target-a:finding-1"

	got := upsertManagedMetadata(description, "snyk-dast:target-a:finding-1", []string{"snyk-dast-automation", "snyk-dast-api"})

	if strings.Contains(got, "Fingerprint: snyk-dast:target-a:finding-1") {
		t.Fatalf("upsertManagedMetadata() left visible fingerprint footer: %s", got)
	}
	if !strings.Contains(got, "managed_labels: snyk-dast-api,snyk-dast-automation") {
		t.Fatalf("upsertManagedMetadata() missing managed labels metadata: %s", got)
	}
}

// TestUpsertManagedMetadataIgnoresInlineMarker verifies that the metadata
// marker appearing mid-sentence in user text does not corrupt the description.
func TestUpsertManagedMetadataIgnoresInlineMarker(t *testing.T) {
	description := "See <!-- snyk-dast-linear-sync notes --> for details\n\nStatus: `open`"

	got := upsertManagedMetadata(description, "snyk-dast:target-a:finding-1", []string{"snyk-dast-automation"})

	if !strings.Contains(got, "See <!-- snyk-dast-linear-sync notes -->") {
		t.Fatalf("upsertManagedMetadata() corrupted inline marker: %s", got)
	}
	if !strings.Contains(got, "<!-- snyk-dast-linear-sync\nfingerprint: snyk-dast:target-a:finding-1") {
		t.Fatalf("upsertManagedMetadata() missing proper metadata block: %s", got)
	}
}

func TestFindMetadataBlockStartAnchoredToLineBoundary(t *testing.T) {
	cases := []struct {
		name        string
		description string
		wantIdx     int
	}{
		{
			name:        "marker at start of description",
			description: "<!-- snyk-dast-linear-sync\nfingerprint: test\n-->",
			wantIdx:     0,
		},
		{
			name:        "marker at start of line",
			description: "Some text\n<!-- snyk-dast-linear-sync\nfingerprint: test\n-->",
			wantIdx:     10,
		},
		{
			name:        "marker mid-sentence should not match",
			description: "See <!-- snyk-dast-linear-sync notes --> for details",
			wantIdx:     -1,
		},
		{
			name:        "no marker at all",
			description: "Just a normal description",
			wantIdx:     -1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := findMetadataBlockStart(tc.description)
			if got != tc.wantIdx {
				t.Fatalf("findMetadataBlockStart() = %d, want %d", got, tc.wantIdx)
			}
		})
	}
}

func TestNeedsUpdateDetectsManagedLabelChange(t *testing.T) {
	existing := model.ExistingIssue{
		Title:         "title",
		Description:   "description",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		ManagedLabels: []string{"old-label"},
		Labels: []model.IssueLabel{
			{ID: "label-1", Name: "old-label"},
		},
		Priority: 2,
	}
	desired := model.DesiredIssue{
		Title:         "title",
		Description:   "description",
		DueDate:       "2026-04-01",
		State:         model.StateTodo,
		ManagedLabels: []string{"new-label"},
		Priority:      2,
	}

	if !needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = false, want true")
	}
}

func TestManagedLabelsUsesConfiguredCheckTypeMapping(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:   "snyk-dast-automation",
		CheckType: map[string]string{"passive": "snyk-dast-passive", "active": "snyk-dast-active"},
	}, model.Finding{CheckType: "passive"})

	found := false
	for _, l := range labels {
		if l == "snyk-dast-passive" {
			found = true
		}
	}
	if !found {
		t.Fatalf("managedLabels() = %#v, want snyk-dast-passive for passive check", labels)
	}
}

func TestManagedLabelsUsesConfiguredTargetTypeMapping(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed:    "snyk-dast-automation",
		TargetType: map[string]string{"api": "snyk-dast-api"},
	}, model.Finding{TargetType: "api"})

	// Labels are normalized (sorted) alphabetically.
	if len(labels) != 2 || labels[0] != "snyk-dast-api" || labels[1] != "snyk-dast-automation" {
		t.Fatalf("managedLabels() = %#v, want [snyk-dast-api snyk-dast-automation]", labels)
	}
}

func TestManagedLabelsOmitsTargetTypeLabelWhenNoMapping(t *testing.T) {
	labels := managedLabels(config.LabelConfig{
		Managed: "snyk-dast-automation",
	}, model.Finding{TargetType: "single"})

	if len(labels) != 1 || labels[0] != "snyk-dast-automation" {
		t.Fatalf("managedLabels() = %#v, want [snyk-dast-automation]", labels)
	}
}

func TestNeedsUpdateClearsDueDateWhenDesiredIsEmpty(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-07-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "",
		State:       model.StateTodo,
		Priority:    2,
	}

	if !needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = false, want true (must clear stale due date)")
	}
}

func TestNeedsUpdateSkipsDueDateWhenBothEmpty(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "",
		State:       model.StateTodo,
		Priority:    2,
	}

	if needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = true, want false (both due dates empty)")
	}
}

func TestNeedsUpdateIncludesDueDate(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:       "title",
		Description: "description",
		DueDate:     "2026-04-15",
		State:       model.StateTodo,
		Priority:    2,
	}

	if !needsUpdate(existing, desired) {
		t.Fatal("needsUpdate() = false, want true")
	}
}

func TestIdentifierNum(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"PROB-1", 1},
		{"SEC-42", 42},
		{"SNYK-11596", 11596},
		{"nodash", 0},
		{"", 0},
		{"SNYK-abc", 0},
	}
	for _, tc := range cases {
		if got := identifierNum(tc.input); got != tc.want {
			t.Errorf("identifierNum(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestRunCancelsDuplicateFingerprintKeepsLowerIdentifier(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:       "snyk-dast:target-a:finding-1",
					SnykDASTFindingID: "su2d3k-1",
					TargetID:          "target-a",
					TargetName:        "Example App",
					IssueTitle:        "CVE-2026-1234",
					Severity:          "high",
					Status:            model.FindingOpen,
				},
			},
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-20",
				Title:       "Snyk DAST: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-dast-linear-sync\nfingerprint: snyk-dast:target-a:finding-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk-dast:target-a:finding-1",
				Priority:    2,
			},
			{
				ID:          "issue-b",
				Identifier:  "SNYK-10",
				Title:       "Snyk DAST: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-dast-linear-sync\nfingerprint: snyk-dast:target-a:finding-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk-dast:target-a:finding-1",
				Priority:    2,
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Conflicts != 1 {
		t.Fatalf("Conflicts = %d, want 1", result.Conflicts)
	}
	if result.CancelledDuplicates != 1 {
		t.Fatalf("CancelledDuplicates = %d, want 1", result.CancelledDuplicates)
	}

	cancelledIDs := cancelledIdentifiers(linear.updates)
	if len(cancelledIDs) != 1 || cancelledIDs[0] != "SNYK-20" {
		t.Fatalf("cancelled identifiers = %v, want [SNYK-20]", cancelledIDs)
	}
}

func TestRunDuplicateCancellationIsIdempotentWhenAlreadyCancelled(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:       "snyk-dast:target-a:finding-1",
					SnykDASTFindingID: "su2d3k-1",
					TargetID:          "target-a",
					TargetName:        "Example App",
					IssueTitle:        "CVE-2026-1234",
					Severity:          "high",
					Status:            model.FindingOpen,
				},
			},
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-20",
				Title:       "Snyk DAST: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-dast-linear-sync\nfingerprint: snyk-dast:target-a:finding-1\n-->",
				StateName:   "Cancelled",
				Fingerprint: "snyk-dast:target-a:finding-1",
				Priority:    2,
			},
			{
				ID:          "issue-b",
				Identifier:  "SNYK-10",
				Title:       "Snyk DAST: [high] CVE-2026-1234",
				Description: "old body\n<!-- snyk-dast-linear-sync\nfingerprint: snyk-dast:target-a:finding-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk-dast:target-a:finding-1",
				Priority:    2,
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Conflicts != 1 {
		t.Fatalf("Conflicts = %d, want 1", result.Conflicts)
	}
	if result.CancelledDuplicates != 0 {
		t.Fatalf("CancelledDuplicates = %d, want 0 (already cancelled)", result.CancelledDuplicates)
	}
}

func TestRunCancelsDuplicateAndStillSyncsCanonical(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:       "snyk-dast:target-a:finding-1",
					SnykDASTFindingID: "su2d3k-1",
					TargetID:          "target-a",
					TargetName:        "Example App",
					IssueTitle:        "CVE-2026-1234",
					Severity:          "high",
					Status:            model.FindingOpen,
				},
			},
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "issue-a",
				Identifier:  "SNYK-20",
				Title:       "stale title",
				Description: "d\n<!-- snyk-dast-linear-sync\nfingerprint: snyk-dast:target-a:finding-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk-dast:target-a:finding-1",
			},
			{
				ID:          "issue-b",
				Identifier:  "SNYK-10",
				Title:       "stale title",
				Description: "d\n<!-- snyk-dast-linear-sync\nfingerprint: snyk-dast:target-a:finding-1\n-->",
				StateName:   "Todo",
				Fingerprint: "snyk-dast:target-a:finding-1",
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.CancelledDuplicates != 1 {
		t.Fatalf("CancelledDuplicates = %d, want 1", result.CancelledDuplicates)
	}
	if !containsStr(updatedIdentifiers(linear.updates), "SNYK-10") {
		t.Fatalf("SNYK-10 (canonical) was not updated; updates: %v", updatedIdentifiers(linear.updates))
	}
	if !containsStr(cancelledIdentifiers(linear.updates), "SNYK-20") {
		t.Fatalf("SNYK-20 (duplicate) was not cancelled; cancelled: %v", cancelledIdentifiers(linear.updates))
	}
}

// minimalCfg returns the smallest valid Config needed to run the service in tests.
func minimalCfg() config.Config {
	return config.Config{
		Linear: config.LinearConfig{
			Due: config.DueDateConfig{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   45,
				LowDays:      90,
			},
		},
		Sync: config.SyncConfig{Workers: 1},
	}
}

func cancelledIdentifiers(updates []model.IssueUpdate) []string {
	var out []string
	for _, u := range updates {
		if u.Desired.State == model.StateCancelled {
			out = append(out, u.Existing.Identifier)
		}
	}
	return out
}

func updatedIdentifiers(updates []model.IssueUpdate) []string {
	out := make([]string, 0, len(updates))
	for _, u := range updates {
		out = append(out, u.Existing.Identifier)
	}
	return out
}

func containsStr(slice []string, s string) bool {
	return slices.Contains(slice, s)
}

func TestRunRespectsManualBacklogMove(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint:       "snyk-dast:target-a:finding-1",
		SnykDASTFindingID: "su2d3k-1",
		TargetID:          "target-a",
		TargetName:        "Example App",
		IssueTitle:        "XSS",
		Severity:          "high",
		Status:            model.FindingOpen,
		CreatedAt:         time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings:  []model.Finding{finding},
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Backlog",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (Backlog override should prevent state-only update)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

func TestRunDoesNotOverrideBacklogForFixedFindings(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Backlog = "Backlog"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint:       "snyk-dast:target-a:finding-1",
		SnykDASTFindingID: "su2d3k-1",
		TargetID:          "target-a",
		TargetName:        "Example App",
		IssueTitle:        "XSS",
		Severity:          "high",
		Status:            model.FindingFixed,
		CreatedAt:         time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	desired := desiredIssue(cfg, finding)

	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings:  []model.Finding{finding},
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Backlog",
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1 (fixed finding should move to Done)", result.PlannedUpdates)
	}
	if linear.updated[0].State != model.StateDone {
		t.Fatalf("updated state = %q, want %q", linear.updated[0].State, model.StateDone)
	}
}

func TestRunPreservesNonTerminalStateWhenUserMovesToTodo(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint:       "snyk-dast:target-a:finding-1",
		SnykDASTFindingID: "su2d3k-1",
		TargetID:          "target-a",
		TargetName:        "Example App",
		IssueTitle:        "XSS",
		Severity:          "high",
		Status:            model.FindingOpen,
		CreatedAt:         time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings:  []model.Finding{finding},
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}

	desired := desiredIssue(cfg, finding)
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       desired.Title,
				Description: desired.Description,
				DueDate:     desired.DueDate,
				StateName:   "Todo", // not the configured open state "Triage"
				Fingerprint: finding.Fingerprint,
				Priority:    desired.Priority,
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 0 {
		t.Fatalf("PlannedUpdates = %d, want 0 (Todo state should be preserved)", result.PlannedUpdates)
	}
	if len(linear.updated) != 0 {
		t.Fatalf("updated = %d, want 0", len(linear.updated))
	}
}

func TestRunDoesNotPreserveTerminalStates(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.States.Todo = "Triage"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	finding := model.Finding{
		Fingerprint:       "snyk-dast:target-a:finding-1",
		SnykDASTFindingID: "su2d3k-1",
		TargetID:          "target-a",
		TargetName:        "Example App",
		IssueTitle:        "XSS",
		Severity:          "high",
		Status:            model.FindingOpen,
		CreatedAt:         time.Date(2026, time.March, 1, 14, 0, 0, 0, time.UTC),
	}

	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings:  []model.Finding{finding},
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}

	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: "old description",
				StateName:   "Done", // terminal state — should NOT be preserved
				Fingerprint: finding.Fingerprint,
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates == 0 {
		t.Fatal("PlannedUpdates = 0, want > 0 (Done state should NOT be preserved for open finding)")
	}
}

func TestRunPostsChangeCommentsOnUpdate(t *testing.T) {
	cfg := minimalCfg()
	cfg.Linear.CommentsEnabled = true
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:       "snyk-dast:target-a:finding-1",
					SnykDASTFindingID: "su2d3k-1",
					TargetID:          "target-a",
					TargetName:        "Example App",
					IssueTitle:        "Updated title",
					Severity:          "high",
					Status:            model.FindingOpen,
					CreatedAt:         time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
			},
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}

	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "stale title",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk-dast:target-a:finding-1",
				Priority:    3,
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	if len(linear.comments) != 1 {
		t.Fatalf("comments = %d, want 1", len(linear.comments))
	}
}

func TestRunSkipsCommentsForResolve(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:            "existing-1",
				Identifier:    "SEC-1",
				Title:         "resolved issue",
				Description:   "old description\n\u003c!-- snyk-dast-linear-sync\nfingerprint: snyk-dast:target-z:finding-9\n--\u003e",
				StateName:     "Todo",
				Fingerprint:   "snyk-dast:target-z:finding-9",
				ManagedLabels: []string{"snyk-dast-automation"},
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedResolves != 1 {
		t.Fatalf("PlannedResolves = %d, want 1", result.PlannedResolves)
	}
	if len(linear.comments) != 0 {
		t.Fatalf("comments = %d, want 0 (no comments for resolve)", len(linear.comments))
	}
}

func TestComputeDiffDetectsAllChanges(t *testing.T) {
	existing := model.ExistingIssue{
		ID:            "issue-1",
		Identifier:    "SEC-1",
		Title:         "old title",
		Description:   "old description",
		DueDate:       "2026-04-01",
		StateName:     "Todo",
		Priority:      3,
		ManagedLabels: []string{"snyk-dast-automation"},
		Labels:        []model.IssueLabel{{ID: "label-1", Name: "snyk-dast-automation"}},
	}
	desired := model.DesiredIssue{
		Title:         "new title",
		Description:   "new description",
		DueDate:       "2026-05-01",
		State:         model.StateBacklog,
		Priority:      1,
		ManagedLabels: []string{"snyk-dast-automation", "snyk-dast-api"},
	}

	diff := ComputeDiff(existing, desired)

	if !diff.TitleChanged || !diff.DescriptionChanged || !diff.DueDateChanged || !diff.StateChanged || !diff.PriorityChanged {
		t.Fatalf("expected all field changes, got: %+v", diff)
	}
	if len(diff.LabelsAdded) != 1 || diff.LabelsAdded[0] != "snyk-dast-api" {
		t.Fatalf("labels added = %v, want [snyk-dast-api]", diff.LabelsAdded)
	}
	if !diff.LabelsNeedUpdate {
		t.Fatal("expected LabelsNeedUpdate when labels are added")
	}
}

func TestComputeDiffNoStateChangeWhenPreserveState(t *testing.T) {
	existing := model.ExistingIssue{
		Title:       "title",
		Description: "desc",
		DueDate:     "2026-04-01",
		StateName:   "Todo",
		Priority:    2,
	}
	desired := model.DesiredIssue{
		Title:         "title",
		Description:   "desc",
		DueDate:       "2026-04-01",
		State:         model.StateBacklog,
		PreserveState: true,
		ManagedLabels: []string{"snyk-dast-automation"},
		Priority:      2,
	}

	diff := ComputeDiff(existing, desired)

	if diff.StateChanged {
		t.Fatal("expected no state change when PreserveState=true")
	}
}

func TestIsConfiguredBacklogState(t *testing.T) {
	cases := []struct {
		existing   string
		configured string
		want       bool
	}{
		{"Backlog", "Backlog", true},
		{"backlog", "Backlog", true},
		{"Todo", "Backlog", false},
		{"", "Backlog", false},
	}
	for _, tc := range cases {
		got := isConfiguredBacklogState(tc.existing, tc.configured)
		if got != tc.want {
			t.Errorf("isConfiguredBacklogState(%q, %q) = %v, want %v", tc.existing, tc.configured, got, tc.want)
		}
	}
}

// TestRunSnoozedFindingStaysOpenWithExtendedDueDate verifies that a finding
// with a time-limited acceptance (snoozed) is kept open in Todo with a due
// date calculated from the acceptance expiry, not cancelled.
func TestRunSnoozedFindingStaysOpenWithExtendedDueDate(t *testing.T) {
	cfg := minimalCfg()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	acceptanceExpiry := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	snykdast := fakeSnykDAST{
		snapshot: model.SnykDASTSnapshot{
			Findings: []model.Finding{
				{
					Fingerprint:       "snyk-dast:target-a:finding-1",
					SnykDASTFindingID: "su2d3k-1",
					TargetID:          "target-a",
					TargetName:        "Example App",
					IssueTitle:        "CVE-2026-1234",
					Severity:          "high",
					Status:            model.FindingOpen,
					CreatedAt:         time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
					IgnoreExpiresAt:   acceptanceExpiry,
				},
			},
			TargetIDs: map[string]struct{}{"target-a": {}},
		},
	}
	linear := &fakeLinear{
		snapshot: []model.ExistingIssue{
			{
				ID:          "existing-1",
				Identifier:  "SEC-1",
				Title:       "Snyk DAST: [high] CVE-2026-1234",
				Description: "old description",
				StateName:   "Todo",
				Fingerprint: "snyk-dast:target-a:finding-1",
				Priority:    2,
			},
		},
	}

	service := New(cfg, logger, snykdast, linear, nil)
	result, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.PlannedUpdates != 1 {
		t.Fatalf("PlannedUpdates = %d, want 1", result.PlannedUpdates)
	}
	updated := linear.updated[0]
	if updated.State != model.StateTodo {
		t.Fatalf("updated state = %q, want %q (snoozed stays open)", updated.State, model.StateTodo)
	}
	// Due date should be calculated from IgnoreExpiresAt (2026-06-01) + 30 days = 2026-07-01
	if updated.DueDate != "2026-07-01" {
		t.Fatalf("updated due date = %q, want %q", updated.DueDate, "2026-07-01")
	}
}
