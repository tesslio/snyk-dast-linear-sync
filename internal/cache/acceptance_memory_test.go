package cache

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "test-cache.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestAcceptancesRoundTripAndReplace pins the storage contract of the
// acceptance memory: every field survives a save and load, a row with an
// unknown confirmation time is stamped at write time, a row with no expiry
// is not stored (it cannot serve as a due-date base), and a save replaces
// the whole set.
func TestAcceptancesRoundTripAndReplace(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	expires := time.Date(2026, time.February, 10, 0, 0, 0, 0, time.UTC)
	confirmed := time.Date(2026, time.January, 20, 8, 30, 15, 123456789, time.UTC)
	before := time.Now().UTC().Add(-time.Second)
	if err := store.SaveAcceptances(ctx, map[string]AcceptanceMeta{
		"snyk-dast:target-a:1": {Fingerprint: "snyk-dast:target-a:1", ExpiresAt: expires, ActiveUntil: expires.AddDate(0, 0, 1), ConfirmedAt: confirmed, ContradictedAt: confirmed.AddDate(0, 0, 2)},
		"snyk-dast:target-a:2": {Fingerprint: "snyk-dast:target-a:2", ExpiresAt: expires},
		"snyk-dast:target-a:3": {Fingerprint: "snyk-dast:target-a:3"},
	}); err != nil {
		t.Fatalf("SaveAcceptances() error = %v", err)
	}

	loaded, err := store.LoadAcceptances(ctx)
	if err != nil {
		t.Fatalf("LoadAcceptances() error = %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("LoadAcceptances() returned %d rows, want 2 (the row without an expiry is not stored): %+v", len(loaded), loaded)
	}
	first := loaded["snyk-dast:target-a:1"]
	if !first.ExpiresAt.Equal(expires) || !first.ActiveUntil.Equal(expires.AddDate(0, 0, 1)) || !first.ConfirmedAt.Equal(confirmed) || !first.ContradictedAt.Equal(confirmed.AddDate(0, 0, 2)) {
		t.Fatalf("row 1 = %+v, want expiry %v, active until %v, confirmed %v, contradicted %v", first, expires, expires.AddDate(0, 0, 1), confirmed, confirmed.AddDate(0, 0, 2))
	}
	second := loaded["snyk-dast:target-a:2"]
	if !second.ActiveUntil.Equal(expires) {
		t.Fatalf("row 2 ActiveUntil = %v, want the expiry when none was given", second.ActiveUntil)
	}
	if !second.ContradictedAt.IsZero() {
		t.Fatalf("row 2 ContradictedAt = %v, want zero (never contradicted)", second.ContradictedAt)
	}
	if second.ConfirmedAt.Before(before) {
		t.Fatalf("row 2 ConfirmedAt = %v, want stamped at save time (after %v)", second.ConfirmedAt, before)
	}

	if err := store.SaveAcceptances(ctx, map[string]AcceptanceMeta{
		"snyk-dast:target-b:4": {Fingerprint: "snyk-dast:target-b:4", ExpiresAt: expires},
	}); err != nil {
		t.Fatalf("SaveAcceptances() second error = %v", err)
	}
	loaded, err = store.LoadAcceptances(ctx)
	if err != nil {
		t.Fatalf("LoadAcceptances() error = %v", err)
	}
	if _, stale := loaded["snyk-dast:target-a:1"]; stale || len(loaded) != 1 {
		t.Fatalf("second save did not replace the rows: %+v", loaded)
	}
}

// TestLoadAcceptancesKeepsRowsNotConfirmedForWeeks pins that the cache does
// not age rows out on read: once Snyk DAST has reverted a finding to
// notfixed, the row is the only record of the expiry the due date is based
// on. Retention is the loader's decision.
func TestLoadAcceptancesKeepsRowsNotConfirmedForWeeks(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	expires := time.Now().UTC().AddDate(0, 0, -20).Truncate(time.Second)
	confirmed := time.Now().UTC().AddDate(0, 0, -30).Truncate(time.Second)
	if err := store.SaveAcceptances(ctx, map[string]AcceptanceMeta{
		"snyk-dast:target-a:1": {ExpiresAt: expires, ConfirmedAt: confirmed},
	}); err != nil {
		t.Fatalf("SaveAcceptances() error = %v", err)
	}
	loaded, err := store.LoadAcceptances(ctx)
	if err != nil {
		t.Fatalf("LoadAcceptances() error = %v", err)
	}
	row, ok := loaded["snyk-dast:target-a:1"]
	if !ok {
		t.Fatal("row not confirmed for 30 days was evicted on read")
	}
	if !row.ConfirmedAt.Equal(confirmed) {
		t.Fatalf("ConfirmedAt = %v, want %v (unchanged on read)", row.ConfirmedAt, confirmed)
	}
}

// TestLoadAcceptancesTreatsUnparsableConfirmationAsUnknown covers a row whose
// confirmed_at is corrupt: it is kept with an unknown confirmation time, and
// a row whose expiry is unreadable is skipped rather than failing the load.
func TestLoadAcceptancesTreatsUnparsableConfirmationAsUnknown(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	rows := []struct{ fingerprint, expires, confirmed string }{
		{"snyk-dast:target-a:1", "2026-02-01T00:00:00Z", "not-a-timestamp"},
		{"snyk-dast:target-a:2", "2026-02-01T00:00:00Z", ""},
		{"snyk-dast:target-a:3", "garbage", "2026-01-01T00:00:00Z"},
	}
	for _, row := range rows {
		if _, err := store.db.ExecContext(ctx,
			`INSERT INTO snyk_dast_acceptances (fingerprint, expires_at, active_until, confirmed_at) VALUES (?, ?, ?, ?)`,
			row.fingerprint, row.expires, row.expires, row.confirmed,
		); err != nil {
			t.Fatalf("insert %s: %v", row.fingerprint, err)
		}
	}
	loaded, err := store.LoadAcceptances(ctx)
	if err != nil {
		t.Fatalf("LoadAcceptances() error = %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("LoadAcceptances() returned %d rows, want 2: %+v", len(loaded), loaded)
	}
	for _, fingerprint := range []string{"snyk-dast:target-a:1", "snyk-dast:target-a:2"} {
		if !loaded[fingerprint].ConfirmedAt.IsZero() {
			t.Fatalf("%s ConfirmedAt = %v, want unknown (zero)", fingerprint, loaded[fingerprint].ConfirmedAt)
		}
	}
}

// TestAcceptanceRowsPresenceAndMeta covers the helpers the cold-start guard
// relies on: whether the memory holds any row, and the sync_meta round trip,
// which the snapshot save must not disturb.
func TestAcceptanceRowsPresenceAndMeta(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	present, err := store.HasAcceptanceRows(ctx)
	if err != nil || present {
		t.Fatalf("HasAcceptanceRows() on an empty cache = %v, %v; want false, nil", present, err)
	}
	if err := store.SaveAcceptances(ctx, map[string]AcceptanceMeta{
		"snyk-dast:target-a:1": {ExpiresAt: time.Now().UTC().AddDate(0, 0, 1)},
	}); err != nil {
		t.Fatalf("SaveAcceptances() error = %v", err)
	}
	present, err = store.HasAcceptanceRows(ctx)
	if err != nil || !present {
		t.Fatalf("HasAcceptanceRows() after a save = %v, %v; want true, nil", present, err)
	}

	if _, ok, err := store.GetMeta(ctx, "acceptances_cold_start_at"); err != nil || ok {
		t.Fatalf("GetMeta() before set = ok %v, err %v; want absent", ok, err)
	}
	if err := store.SetMeta(ctx, "acceptances_cold_start_at", "2026-03-01T12:00:00Z"); err != nil {
		t.Fatalf("SetMeta() error = %v", err)
	}
	value, ok, err := store.GetMeta(ctx, "acceptances_cold_start_at")
	if err != nil || !ok || value != "2026-03-01T12:00:00Z" {
		t.Fatalf("GetMeta() = %q, %v, %v; want the stored value", value, ok, err)
	}
	if err := store.Save(ctx, Snapshot{SchemaSignature: "sig", SnykDASTHashes: map[string]string{}, LinearHashes: map[string]string{}}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if _, ok, _ := store.GetMeta(ctx, "acceptances_cold_start_at"); !ok {
		t.Fatal("marker lost on snapshot save")
	}
	if present, _ := store.HasAcceptanceRows(ctx); !present {
		t.Fatal("acceptance rows lost on snapshot save")
	}
	if err := store.DeleteMeta(ctx, "acceptances_cold_start_at"); err != nil {
		t.Fatalf("DeleteMeta() error = %v", err)
	}
	if _, ok, _ := store.GetMeta(ctx, "acceptances_cold_start_at"); ok {
		t.Fatal("marker still present after delete")
	}
	if err := store.DeleteMeta(ctx, "acceptances_cold_start_at"); err != nil {
		t.Fatalf("DeleteMeta() of an absent key error = %v, want nil", err)
	}
}

// TestPrepareAcceptanceMemoryRecordsPendingEmptyStart pins the state machine
// behind the cold-start guard: an empty memory is recorded as pending before
// any loader seeds rows, stays pending once rows exist (a failed load may
// have seeded them), and is released only by an explicit trusted mark.
func TestPrepareAcceptanceMemoryRecordsPendingEmptyStart(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	pending, err := PrepareAcceptanceMemory(ctx, store)
	if err != nil || !pending {
		t.Fatalf("PrepareAcceptanceMemory() on an empty memory = %v, %v; want pending", pending, err)
	}
	if state, _, _ := store.GetMeta(ctx, AcceptanceMemoryStateKey); state != acceptanceMemoryPending {
		t.Fatalf("state = %q, want %q", state, acceptanceMemoryPending)
	}

	if err := store.SaveAcceptances(ctx, map[string]AcceptanceMeta{
		"snyk-dast:target-a:1": {ExpiresAt: time.Now().UTC().AddDate(0, 0, 1)},
	}); err != nil {
		t.Fatalf("SaveAcceptances() error = %v", err)
	}
	if pending, err := PrepareAcceptanceMemory(ctx, store); err != nil || !pending {
		t.Fatalf("PrepareAcceptanceMemory() after seeding = %v, %v; want still pending", pending, err)
	}

	if err := store.SetMeta(ctx, AcceptanceMemoryStateKey, AcceptanceMemoryTrusted); err != nil {
		t.Fatalf("SetMeta() error = %v", err)
	}
	if pending, err := PrepareAcceptanceMemory(ctx, store); err != nil || pending {
		t.Fatalf("PrepareAcceptanceMemory() once trusted = %v, %v; want not pending", pending, err)
	}

	// A memory that already holds rows on its first preparation is trusted.
	seeded := openTestStore(t)
	if err := seeded.SaveAcceptances(ctx, map[string]AcceptanceMeta{
		"snyk-dast:target-a:1": {ExpiresAt: time.Now().UTC().AddDate(0, 0, 1)},
	}); err != nil {
		t.Fatalf("SaveAcceptances() error = %v", err)
	}
	if pending, err := PrepareAcceptanceMemory(ctx, seeded); err != nil || pending {
		t.Fatalf("PrepareAcceptanceMemory() on a populated memory = %v, %v; want not pending", pending, err)
	}
	if state, _, _ := seeded.GetMeta(ctx, AcceptanceMemoryStateKey); state != AcceptanceMemoryTrusted {
		t.Fatalf("state = %q, want %q", state, AcceptanceMemoryTrusted)
	}
}

// TestPrepareAcceptanceMemoryTrustsUpgradedCache: a cache that a previous
// run wrote (the snapshot save records the schema signature and the hash
// rows) but that has no acceptance rows is an upgrade from a version without
// the memory. Nothing was lost, so the memory is trusted from the start and
// no cold start is recorded. A cache nothing has written stays pending.
func TestPrepareAcceptanceMemoryTrustsUpgradedCache(t *testing.T) {
	ctx := context.Background()

	upgraded := openTestStore(t)
	if err := upgraded.Save(ctx, Snapshot{
		SchemaSignature: "sig",
		SnykDASTHashes:  map[string]string{"snyk-dast:target-a:1": "hash-a"},
		LinearHashes:    map[string]string{"snyk-dast:target-a:1": "linear-a"},
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if prior, err := upgraded.HasPriorRunData(ctx); err != nil || !prior {
		t.Fatalf("HasPriorRunData() after a snapshot save = %v, %v; want true", prior, err)
	}
	if pending, err := PrepareAcceptanceMemory(ctx, upgraded); err != nil || pending {
		t.Fatalf("PrepareAcceptanceMemory() on an upgraded cache = %v, %v; want trusted", pending, err)
	}
	if state, _, _ := upgraded.GetMeta(ctx, AcceptanceMemoryStateKey); state != AcceptanceMemoryTrusted {
		t.Fatalf("state = %q, want %q", state, AcceptanceMemoryTrusted)
	}

	// Hash rows alone (a signature-less save) count as prior data too.
	hashesOnly := openTestStore(t)
	if _, err := hashesOnly.db.ExecContext(ctx, `INSERT INTO linear_issues (fingerprint, hash) VALUES (?, ?)`, "snyk-dast:target-a:1", "linear-a"); err != nil {
		t.Fatal(err)
	}
	if pending, err := PrepareAcceptanceMemory(ctx, hashesOnly); err != nil || pending {
		t.Fatalf("PrepareAcceptanceMemory() with only hash rows = %v, %v; want trusted", pending, err)
	}

	// A fresh database: Open writes schema_version, which is not prior run
	// data, so the memory is pending.
	fresh := openTestStore(t)
	if prior, err := fresh.HasPriorRunData(ctx); err != nil || prior {
		t.Fatalf("HasPriorRunData() on a fresh cache = %v, %v; want false", prior, err)
	}
	if pending, err := PrepareAcceptanceMemory(ctx, fresh); err != nil || !pending {
		t.Fatalf("PrepareAcceptanceMemory() on a fresh cache = %v, %v; want pending", pending, err)
	}
}

// TestOpenMigratesAcceptancesWithoutContradictedAt: a cache written by the
// first version of the acceptance table has no contradicted_at column. Open
// adds it; the existing rows read as never contradicted and are kept, and
// a later save can stamp them.
func TestOpenMigratesAcceptancesWithoutContradictedAt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	ctx := context.Background()
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE sync_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE snyk_dast_acceptances (fingerprint TEXT PRIMARY KEY, expires_at TEXT NOT NULL, active_until TEXT NOT NULL, confirmed_at TEXT)`,
		`INSERT INTO snyk_dast_acceptances (fingerprint, expires_at, active_until, confirmed_at) VALUES ('snyk-dast:target-a:1', '2026-02-01T00:00:00Z', '2026-02-02T00:00:00Z', '2026-01-20T00:00:00Z')`,
	} {
		if _, err := legacy.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open() on a legacy cache error = %v", err)
	}
	defer store.Close()
	loaded, err := store.LoadAcceptances(ctx)
	if err != nil {
		t.Fatalf("LoadAcceptances() error = %v", err)
	}
	row, ok := loaded["snyk-dast:target-a:1"]
	if !ok || row.ExpiresAt.IsZero() || !row.ContradictedAt.IsZero() {
		t.Fatalf("legacy row = %+v, %v; want kept and never contradicted", row, ok)
	}
	row.ContradictedAt = time.Date(2026, time.January, 25, 0, 0, 0, 0, time.UTC)
	if err := store.SaveAcceptances(ctx, map[string]AcceptanceMeta{row.Fingerprint: row}); err != nil {
		t.Fatalf("SaveAcceptances() after migration error = %v", err)
	}
	loaded, err = store.LoadAcceptances(ctx)
	if err != nil || !loaded[row.Fingerprint].ContradictedAt.Equal(row.ContradictedAt) {
		t.Fatalf("stamp after migration = %+v, %v; want %v", loaded[row.Fingerprint], err, row.ContradictedAt)
	}
	// Opening again is idempotent.
	if err := store.migrateAcceptances(ctx); err != nil {
		t.Fatalf("second migration error = %v", err)
	}
}

// TestSaveAcceptancesRollsBackFailedReplacement: a failed replacement must
// leave the previous rows in place rather than an emptied table, since the
// rows are the only record of lapsed expiries.
func TestSaveAcceptancesRollsBackFailedReplacement(t *testing.T) {
	store := openTestStore(t)
	store.db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	originalExpiry := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	if err := store.SaveAcceptances(ctx, map[string]AcceptanceMeta{
		"snyk-dast:target-a:1": {ExpiresAt: originalExpiry},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER fail_acceptance_write BEFORE INSERT ON snyk_dast_acceptances BEGIN SELECT RAISE(ABORT, 'fixture acceptance write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAcceptances(ctx, map[string]AcceptanceMeta{
		"snyk-dast:target-a:2": {ExpiresAt: originalExpiry.AddDate(0, 0, 1)},
	}); err == nil {
		t.Fatal("want failed replacement")
	}
	rows, err := store.LoadAcceptances(ctx)
	if err != nil {
		t.Fatalf("read after failed replacement: %v", err)
	}
	if len(rows) != 1 || !rows["snyk-dast:target-a:1"].ExpiresAt.Equal(originalExpiry) {
		t.Fatalf("failed replacement changed prior rows: %+v", rows)
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER fail_acceptance_write`); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAcceptances(ctx, map[string]AcceptanceMeta{
		"snyk-dast:target-a:2": {ExpiresAt: originalExpiry.AddDate(0, 0, 1)},
	}); err != nil {
		t.Fatalf("retry after removing fault: %v", err)
	}
}
