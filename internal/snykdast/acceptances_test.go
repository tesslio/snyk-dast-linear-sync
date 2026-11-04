package snykdast

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tesslio/snyk-dast-linear-sync/internal/cache"
	"github.com/tesslio/snyk-dast-linear-sync/internal/model"
)

// The tests in this file cover the acceptance memory: what the loader
// remembers about a finding's time-limited acceptance once Snyk DAST stops
// reporting it, and what it forgets.

const (
	testTargetID    = "target-a"
	testFingerprint = "snyk-dast:target-a:1"
)

// memoryStore is an in-memory AcceptanceStore.
type memoryStore struct {
	rows    map[string]cache.AcceptanceMeta
	meta    map[string]string
	loadErr error
	saveErr error
	saves   int
}

func newMemoryStore() *memoryStore {
	return &memoryStore{rows: map[string]cache.AcceptanceMeta{}, meta: map[string]string{}}
}

func (m *memoryStore) GetMeta(_ context.Context, key string) (string, bool, error) {
	value, ok := m.meta[key]
	return value, ok, nil
}

func (m *memoryStore) SetMeta(_ context.Context, key, value string) error {
	m.meta[key] = value
	return nil
}

func (m *memoryStore) HasAcceptanceRows(context.Context) (bool, error) {
	return len(m.rows) > 0, nil
}

func (m *memoryStore) LoadAcceptances(context.Context) (map[string]cache.AcceptanceMeta, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	out := make(map[string]cache.AcceptanceMeta, len(m.rows))
	maps.Copy(out, m.rows)
	return out, nil
}

func (m *memoryStore) SaveAcceptances(_ context.Context, rows map[string]cache.AcceptanceMeta) error {
	m.saves++
	if m.saveErr != nil {
		return m.saveErr
	}
	m.rows = make(map[string]cache.AcceptanceMeta, len(rows))
	maps.Copy(m.rows, rows)
	return nil
}

// fakeAPI serves the three list endpoints the snapshot load reads, with the
// findings it is told to report.
type fakeAPI struct {
	findings []findingNode
}

func (a *fakeAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/targets/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(paginatedTargets{Count: 1, Page: 1, PageTotal: 1, Length: 100, Results: []targetNode{
			{ID: testTargetID, Type: "single", Site: struct {
				Name string `json:"name"`
				URL  string `json:"url"`
				Host string `json:"host"`
			}{Name: "Example App", URL: "https://app.example.test", Host: "app.example.test"}},
		}})
	})
	mux.HandleFunc("/findings/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(paginatedFindings{Count: len(a.findings), Page: 1, PageTotal: 1, Length: 100, Results: a.findings})
	})
	mux.HandleFunc("/definitions/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(paginatedDefinitions{Count: 0, Page: 1, PageTotal: 1, Length: 100})
	})
	return mux
}

func testFinding(state string, expirationDate *string) findingNode {
	node := findingNode{
		ID:             json.Number("1"),
		State:          state,
		Severity:       30,
		CreatedAt:      new("2026-01-01T00:00:00Z"),
		LastFound:      "2026-01-15T00:00:00Z",
		ExpirationDate: expirationDate,
	}
	node.Definition.ID = "def-1"
	node.Definition.Name = "Example vulnerability"
	node.Target = targetSummary{ID: testTargetID, Name: "Example App", Type: "single"}
	return node
}

//go:fix inline
func ptr(s string) *string { return new(s) }

type testHarness struct {
	api    *fakeAPI
	client *Client
	store  *memoryStore
	logs   *bytes.Buffer
}

func newTestHarness(t *testing.T, store *memoryStore) *testHarness {
	t.Helper()
	api := &fakeAPI{}
	server := httptest.NewServer(api.handler())
	t.Cleanup(server.Close)
	base, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	client := &Client{
		apiBase:     base,
		httpClient:  server.Client(),
		logger:      slog.New(slog.NewTextHandler(logs, nil)),
		concurrency: 2,
	}
	if store != nil {
		client.SetCache(store)
	}
	return &testHarness{api: api, client: client, store: store, logs: logs}
}

// load runs one snapshot load at the given instant with the given finding
// and returns the normalised finding.
func (h *testHarness) load(t *testing.T, now time.Time, node findingNode) model.Finding {
	t.Helper()
	h.logs.Reset()
	h.api.findings = []findingNode{node}
	h.client.now = func() time.Time { return now }
	snapshot, err := h.client.LoadSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LoadSnapshot() at %v error = %v", now, err)
	}
	if len(snapshot.Findings) != 1 {
		t.Fatalf("LoadSnapshot() at %v returned %d findings, want 1", now, len(snapshot.Findings))
	}
	return snapshot.Findings[0]
}

func dateOnly(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// TestLoadSnapshotRemembersLapsedAcceptanceAcrossRuns is the regression test
// for the due-date regression: once Snyk DAST reverts a finding whose
// acceptance ran out to notfixed, the expiry is no longer in the response,
// and without memory the due date fell back to created_at + SLA. The expiry
// must keep being reported on every later run, however long ago the
// acceptance was last confirmed, whether or not the API still echoes the
// past expiration_date on the notfixed finding.
func TestLoadSnapshotRemembersLapsedAcceptanceAcrossRuns(t *testing.T) {
	for _, echoesDate := range []bool{false, true} {
		name := "expiration_date dropped on reversion"
		if echoesDate {
			name = "expiration_date still echoed on reversion"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
			expiry := now.AddDate(0, 0, -2)
			h := newTestHarness(t, newMemoryStore())

			// Run 1: Snyk DAST still reports the lapsed acceptance.
			got := h.load(t, now, testFinding("accepted", new(dateOnly(expiry))))
			if got.Status != model.FindingOpen || !got.IgnoreExpiresAt.Equal(expiry) || got.AcceptanceRemembered {
				t.Fatalf("run 1: status %q expiry %v remembered %v, want open, %v, from the API", got.Status, got.IgnoreExpiresAt, got.AcceptanceRemembered, expiry)
			}
			row, ok := h.store.rows[testFingerprint]
			if !ok || !row.ExpiresAt.Equal(expiry) || !row.ConfirmedAt.Equal(now) {
				t.Fatalf("run 1: remembered row = %+v, want expiry %v confirmed at %v", row, expiry, now)
			}

			// Runs 2..n: Snyk DAST has reverted the finding to notfixed.
			var reverted *string
			if echoesDate {
				reverted = new(dateOnly(expiry))
			}
			for _, days := range []int{1, 8, 30, 400} {
				at := now.AddDate(0, 0, days)
				got := h.load(t, at, testFinding("notfixed", reverted))
				if got.Status != model.FindingOpen {
					t.Fatalf("day %d: status %q, want open", days, got.Status)
				}
				if !got.IgnoreExpiresAt.Equal(expiry) || !got.AcceptanceRemembered {
					t.Fatalf("day %d: expiry %v remembered %v, want the lapsed expiry %v remembered", days, got.IgnoreExpiresAt, got.AcceptanceRemembered, expiry)
				}
				row := h.store.rows[testFingerprint]
				if !row.ExpiresAt.Equal(expiry) || !row.ConfirmedAt.Equal(now) {
					t.Fatalf("day %d: row = %+v, want the original expiry and confirmation time kept", days, row)
				}
				if strings.Contains(h.logs.String(), "dropping remembered acceptance") {
					t.Fatalf("day %d: a lapsed acceptance must never be dropped:\n%s", days, h.logs.String())
				}
			}
		})
	}
}

// TestLoadSnapshotKeepsLapsedExpiryThroughRetestAndFix: the remembered
// expiry stays the due-date base whatever non-accepted state the finding
// moves through, so the ticket's due date does not move when the finding is
// retested or closed.
func TestLoadSnapshotKeepsLapsedExpiryThroughRetestAndFix(t *testing.T) {
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	expiry := now.AddDate(0, 0, -2)
	h := newTestHarness(t, newMemoryStore())
	h.load(t, now, testFinding("accepted", new(dateOnly(expiry))))

	for i, tc := range []struct {
		state string
		want  model.FindingStatus
	}{
		{"retesting", model.FindingOpen},
		{"notfixed", model.FindingOpen},
		{"fixed", model.FindingFixed},
		{"invalid", model.FindingIgnored},
	} {
		got := h.load(t, now.AddDate(0, 0, i+1), testFinding(tc.state, nil))
		if got.Status != tc.want || !got.IgnoreExpiresAt.Equal(expiry) || !got.AcceptanceRemembered {
			t.Fatalf("%s: status %q expiry %v remembered %v, want %q with the lapsed expiry remembered", tc.state, got.Status, got.IgnoreExpiresAt, got.AcceptanceRemembered, tc.want)
		}
	}
}

// TestLoadSnapshotDropsRevokedAcceptanceAfterGrace: an acceptance whose
// expiry is still ahead that Snyk DAST stops reporting was revoked. The
// memory is kept for seven days after the last confirmation, so a partial
// response does not move the due date, then dropped with a log line.
func TestLoadSnapshotDropsRevokedAcceptanceAfterGrace(t *testing.T) {
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	expiry := now.AddDate(0, 0, 60)
	h := newTestHarness(t, newMemoryStore())

	got := h.load(t, now, testFinding("accepted", new(dateOnly(expiry))))
	if got.Status != model.FindingSnoozed || !got.IgnoreExpiresAt.Equal(expiry) {
		t.Fatalf("run 1: status %q expiry %v, want snoozed until %v", got.Status, got.IgnoreExpiresAt, expiry)
	}

	// Within the grace: the finding is open, but the expiry still applies.
	for _, days := range []int{1, 6} {
		got := h.load(t, now.AddDate(0, 0, days), testFinding("notfixed", nil))
		if got.Status != model.FindingOpen || !got.IgnoreExpiresAt.Equal(expiry) || !got.AcceptanceRemembered {
			t.Fatalf("day %d: status %q expiry %v remembered %v, want open with the expiry remembered during the grace", days, got.Status, got.IgnoreExpiresAt, got.AcceptanceRemembered)
		}
		if _, ok := h.store.rows[testFingerprint]; !ok {
			t.Fatalf("day %d: row dropped within the grace", days)
		}
	}

	// Past the grace: revoked.
	got = h.load(t, now.AddDate(0, 0, 7), testFinding("notfixed", nil))
	if got.Status != model.FindingOpen || !got.IgnoreExpiresAt.IsZero() || got.AcceptanceRemembered {
		t.Fatalf("day 7: status %q expiry %v remembered %v, want open with no expiry", got.Status, got.IgnoreExpiresAt, got.AcceptanceRemembered)
	}
	if _, ok := h.store.rows[testFingerprint]; ok {
		t.Fatalf("day 7: row still remembered: %+v", h.store.rows)
	}
	if !strings.Contains(h.logs.String(), "dropping remembered acceptance") || !strings.Contains(h.logs.String(), testFingerprint) {
		t.Fatalf("day 7: want a log line naming the dropped acceptance, got:\n%s", h.logs.String())
	}

	// Later runs stay forgotten.
	got = h.load(t, now.AddDate(0, 0, 8), testFinding("notfixed", nil))
	if !got.IgnoreExpiresAt.IsZero() || got.AcceptanceRemembered {
		t.Fatalf("day 8: expiry %v remembered %v, want none", got.IgnoreExpiresAt, got.AcceptanceRemembered)
	}
}

// TestLoadSnapshotReconfirmationResetsGrace: a finding that comes back as
// accepted within the grace was a partial response, not a revocation. The
// confirmation time is refreshed and the grace starts over.
func TestLoadSnapshotReconfirmationResetsGrace(t *testing.T) {
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	expiry := now.AddDate(0, 0, 60)
	h := newTestHarness(t, newMemoryStore())
	h.load(t, now, testFinding("accepted", new(dateOnly(expiry))))
	h.load(t, now.AddDate(0, 0, 5), testFinding("notfixed", nil))
	got := h.load(t, now.AddDate(0, 0, 6), testFinding("accepted", new(dateOnly(expiry))))
	if got.Status != model.FindingSnoozed || got.AcceptanceRemembered {
		t.Fatalf("reconfirmed: status %q remembered %v, want snoozed from the API", got.Status, got.AcceptanceRemembered)
	}
	if row := h.store.rows[testFingerprint]; !row.ConfirmedAt.Equal(now.AddDate(0, 0, 6)) {
		t.Fatalf("reconfirmed: ConfirmedAt = %v, want refreshed to the reconfirming run", row.ConfirmedAt)
	}
	// Six more days of silence are still within the new grace.
	got = h.load(t, now.AddDate(0, 0, 12), testFinding("notfixed", nil))
	if !got.IgnoreExpiresAt.Equal(expiry) || !got.AcceptanceRemembered {
		t.Fatalf("day 12: expiry %v remembered %v, want kept within the refreshed grace", got.IgnoreExpiresAt, got.AcceptanceRemembered)
	}
}

// TestLoadSnapshotLaterAcceptanceReplacesMemory: a new time-limited
// acceptance replaces the remembered lapsed one, and once it lapses in turn
// its expiry is the one remembered.
func TestLoadSnapshotLaterAcceptanceReplacesMemory(t *testing.T) {
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	first := now.AddDate(0, 0, -10)
	second := now.AddDate(0, 0, 20)
	h := newTestHarness(t, newMemoryStore())
	h.load(t, now, testFinding("accepted", new(dateOnly(first))))
	h.load(t, now.AddDate(0, 0, 1), testFinding("notfixed", nil))

	got := h.load(t, now.AddDate(0, 0, 2), testFinding("accepted", new(dateOnly(second))))
	if got.Status != model.FindingSnoozed || !got.IgnoreExpiresAt.Equal(second) || got.AcceptanceRemembered {
		t.Fatalf("re-accepted: status %q expiry %v remembered %v, want snoozed until %v from the API", got.Status, got.IgnoreExpiresAt, got.AcceptanceRemembered, second)
	}
	if row := h.store.rows[testFingerprint]; !row.ExpiresAt.Equal(second) {
		t.Fatalf("re-accepted: remembered expiry %v, want %v", row.ExpiresAt, second)
	}

	got = h.load(t, now.AddDate(0, 0, 30), testFinding("notfixed", nil))
	if got.Status != model.FindingOpen || !got.IgnoreExpiresAt.Equal(second) || !got.AcceptanceRemembered {
		t.Fatalf("second lapse: status %q expiry %v remembered %v, want open with %v remembered", got.Status, got.IgnoreExpiresAt, got.AcceptanceRemembered, second)
	}
}

// TestLoadSnapshotPermanentAcceptanceSupersedesMemory: a permanent
// acceptance (no expiry) is a different decision; the remembered
// time-limited one is dropped, and when the permanent acceptance is later
// lifted the due date is based on the finding's creation again.
func TestLoadSnapshotPermanentAcceptanceSupersedesMemory(t *testing.T) {
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	h := newTestHarness(t, newMemoryStore())
	h.load(t, now, testFinding("accepted", new(dateOnly(now.AddDate(0, 0, -10)))))

	got := h.load(t, now.AddDate(0, 0, 1), testFinding("accepted", nil))
	if got.Status != model.FindingIgnored || !got.IgnoreExpiresAt.IsZero() || got.AcceptanceRemembered {
		t.Fatalf("permanent: status %q expiry %v remembered %v, want ignored with no expiry", got.Status, got.IgnoreExpiresAt, got.AcceptanceRemembered)
	}
	if _, ok := h.store.rows[testFingerprint]; ok {
		t.Fatalf("permanent: time-limited acceptance still remembered: %+v", h.store.rows)
	}
	got = h.load(t, now.AddDate(0, 0, 2), testFinding("notfixed", nil))
	if got.Status != model.FindingOpen || !got.IgnoreExpiresAt.IsZero() {
		t.Fatalf("lifted: status %q expiry %v, want open with no expiry", got.Status, got.IgnoreExpiresAt)
	}
}

// TestLoadSnapshotKeepsMemoryForAbsentFinding: a finding missing from the
// snapshot (its target was deleted) says nothing about its acceptance; the
// row is kept, inert, in case the finding comes back.
func TestLoadSnapshotKeepsMemoryForAbsentFinding(t *testing.T) {
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	expiry := now.AddDate(0, 0, -10)
	store := newMemoryStore()
	store.rows["snyk-dast:target-b:9"] = cache.AcceptanceMeta{Fingerprint: "snyk-dast:target-b:9", ExpiresAt: expiry, ActiveUntil: expiry.AddDate(0, 0, 1), ConfirmedAt: now.AddDate(0, 0, -30)}
	h := newTestHarness(t, store)
	h.load(t, now, testFinding("notfixed", nil))
	row, ok := store.rows["snyk-dast:target-b:9"]
	if !ok || !row.ExpiresAt.Equal(expiry) || !row.ConfirmedAt.Equal(now.AddDate(0, 0, -30)) {
		t.Fatalf("row for the absent finding = %+v, %v; want kept unchanged", row, ok)
	}
}

// TestLoadSnapshotUnknownConfirmationStartsGraceNow: a remembered future
// expiry with no confirmation time is kept, and its grace runs from the
// first run that sees it rather than never.
func TestLoadSnapshotUnknownConfirmationStartsGraceNow(t *testing.T) {
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	expiry := now.AddDate(0, 0, 60)
	store := newMemoryStore()
	store.rows[testFingerprint] = cache.AcceptanceMeta{Fingerprint: testFingerprint, ExpiresAt: expiry, ActiveUntil: expiry.AddDate(0, 0, 1)}
	h := newTestHarness(t, store)
	got := h.load(t, now, testFinding("notfixed", nil))
	if !got.IgnoreExpiresAt.Equal(expiry) || !got.AcceptanceRemembered {
		t.Fatalf("run 1: expiry %v remembered %v, want kept", got.IgnoreExpiresAt, got.AcceptanceRemembered)
	}
	if row := store.rows[testFingerprint]; !row.ConfirmedAt.Equal(now) {
		t.Fatalf("run 1: ConfirmedAt = %v, want stamped now", row.ConfirmedAt)
	}
	got = h.load(t, now.AddDate(0, 0, 7), testFinding("notfixed", nil))
	if !got.IgnoreExpiresAt.IsZero() {
		t.Fatalf("day 7: expiry %v, want dropped once the grace from the stamp has run out", got.IgnoreExpiresAt)
	}
}

// TestLoadSnapshotWithoutCacheDoesNotRemember: without a cache the loader
// behaves as before: a reverted finding carries no expiry.
func TestLoadSnapshotWithoutCacheDoesNotRemember(t *testing.T) {
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	h := newTestHarness(t, nil)
	got := h.load(t, now, testFinding("accepted", new(dateOnly(now.AddDate(0, 0, -2)))))
	if got.Status != model.FindingOpen || got.IgnoreExpiresAt.IsZero() {
		t.Fatalf("run 1: status %q expiry %v, want open with the API expiry", got.Status, got.IgnoreExpiresAt)
	}
	got = h.load(t, now.AddDate(0, 0, 1), testFinding("notfixed", nil))
	if !got.IgnoreExpiresAt.IsZero() || got.AcceptanceRemembered {
		t.Fatalf("run 2: expiry %v remembered %v, want none without a cache", got.IgnoreExpiresAt, got.AcceptanceRemembered)
	}
}

// TestLoadSnapshotFailsWhenMemoryIsUnavailable: a memory that cannot be
// read or written fails the load, so Linear is never reconciled from a
// partial memory and a newly reported acceptance is never lost.
func TestLoadSnapshotFailsWhenMemoryIsUnavailable(t *testing.T) {
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	for _, fault := range []string{"load", "save"} {
		t.Run(fault, func(t *testing.T) {
			store := newMemoryStore()
			wantErr := errors.New("fixture memory failure")
			if fault == "load" {
				store.loadErr = wantErr
			} else {
				store.saveErr = wantErr
			}
			h := newTestHarness(t, store)
			h.api.findings = []findingNode{testFinding("accepted", new(dateOnly(now.AddDate(0, 0, 10))))}
			h.client.now = func() time.Time { return now }
			if _, err := h.client.LoadSnapshot(context.Background()); !errors.Is(err, wantErr) {
				t.Fatalf("LoadSnapshot() error = %v, want the memory failure", err)
			}
		})
	}
}

// TestLoadSnapshotRecordsPendingMemoryState: the loader records an empty
// start before seeding rows, so a run that fails after the load still
// leaves the cold-start evidence behind.
func TestLoadSnapshotRecordsPendingMemoryState(t *testing.T) {
	now := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	h := newTestHarness(t, newMemoryStore())
	h.load(t, now, testFinding("accepted", new(dateOnly(now.AddDate(0, 0, 10)))))
	if state := h.store.meta[cache.AcceptanceMemoryStateKey]; state != "pending" {
		t.Fatalf("memory state = %q, want pending", state)
	}
	if len(h.store.rows) != 1 {
		t.Fatalf("rows = %+v, want the acceptance seeded", h.store.rows)
	}
}
