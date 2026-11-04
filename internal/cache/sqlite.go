package cache

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	_ "modernc.org/sqlite"
)

const schemaVersion = "v1"

// Snapshot is the persisted sync state: a schema signature plus the
// normalized hash of each Snyk DAST finding and each managed Linear issue.
type Snapshot struct {
	SchemaSignature string
	SnykDASTHashes  map[string]string
	LinearHashes    map[string]string
}

// AcceptanceMeta is the sync's memory of a finding's time-limited risk
// acceptance, keyed by fingerprint. Snyk DAST reverts an accepted finding to
// `notfixed` once its acceptance expires, and from then on the finding no
// longer carries the expiry the sync bases its due date on. The cache is the
// only record of that expiry afterwards, so rows are never aged out on read;
// the Snyk DAST loader decides, with the live finding in hand, which rows
// Snyk has contradicted (see the retention rule in internal/snykdast).
type AcceptanceMeta struct {
	Fingerprint string
	// ExpiresAt is the acceptance expiry as Snyk DAST reported it, and the
	// base of the SLA due date.
	ExpiresAt time.Time
	// ActiveUntil is the instant the acceptance actually stops applying. It
	// differs from ExpiresAt for a date-only expiry, which covers the whole
	// of its final day.
	ActiveUntil time.Time
	// ConfirmedAt is when Snyk DAST last reported the finding as accepted
	// with this expiry. Zero when unknown (a row whose value could not be
	// parsed): the next write stamps it with the time of that write.
	ConfirmedAt time.Time
}

type Store struct {
	db      *sql.DB
	builder sq.StatementBuilderType
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite cache: %w", err)
	}

	store := &Store{
		db:      db,
		builder: sq.StatementBuilder.PlaceholderFormat(sq.Question),
	}
	if err := store.init(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Load(ctx context.Context) (Snapshot, error) {
	snapshot := Snapshot{
		SnykDASTHashes: map[string]string{},
		LinearHashes:   map[string]string{},
	}

	query, args, err := s.builder.
		Select("value").
		From("sync_meta").
		Where(sq.Eq{"key": "schema_signature"}).
		ToSql()
	if err != nil {
		return Snapshot{}, fmt.Errorf("build cache schema signature query: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return Snapshot{}, fmt.Errorf("load cache schema signature: %w", err)
	}
	for rows.Next() {
		if err := rows.Scan(&snapshot.SchemaSignature); err != nil {
			_ = rows.Close()
			return Snapshot{}, fmt.Errorf("scan cache schema signature: %w", err)
		}
	}
	if err := rows.Close(); err != nil {
		return Snapshot{}, fmt.Errorf("close cache schema signature rows: %w", err)
	}

	query, args, err = s.builder.
		Select("fingerprint", "hash").
		From("snyk_dast_findings").
		ToSql()
	if err != nil {
		return Snapshot{}, fmt.Errorf("build Snyk DAST cache rows query: %w", err)
	}

	snykdastRows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return Snapshot{}, fmt.Errorf("load Snyk DAST cache rows: %w", err)
	}
	for snykdastRows.Next() {
		var fingerprint string
		var hash string
		if err := snykdastRows.Scan(&fingerprint, &hash); err != nil {
			_ = snykdastRows.Close()
			return Snapshot{}, fmt.Errorf("scan Snyk DAST cache row: %w", err)
		}
		snapshot.SnykDASTHashes[fingerprint] = hash
	}
	if err := snykdastRows.Close(); err != nil {
		return Snapshot{}, fmt.Errorf("close Snyk DAST cache rows: %w", err)
	}

	query, args, err = s.builder.
		Select("fingerprint", "hash").
		From("linear_issues").
		ToSql()
	if err != nil {
		return Snapshot{}, fmt.Errorf("build Linear cache rows query: %w", err)
	}

	linearRows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return Snapshot{}, fmt.Errorf("load Linear cache rows: %w", err)
	}
	for linearRows.Next() {
		var fingerprint string
		var hash string
		if err := linearRows.Scan(&fingerprint, &hash); err != nil {
			_ = linearRows.Close()
			return Snapshot{}, fmt.Errorf("scan Linear cache row: %w", err)
		}
		snapshot.LinearHashes[fingerprint] = hash
	}
	if err := linearRows.Close(); err != nil {
		return Snapshot{}, fmt.Errorf("close Linear cache rows: %w", err)
	}

	return snapshot, nil
}

func (s *Store) Save(ctx context.Context, snapshot Snapshot) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cache transaction: %w", err)
	}
	// Rollback also runs on shadowed error paths; after Commit it is a no-op.
	defer func() { _ = tx.Rollback() }()

	query, args, err := s.builder.
		Insert("sync_meta").
		Columns("key", "value").
		Values("schema_signature", snapshot.SchemaSignature).
		Suffix("ON CONFLICT(key) DO UPDATE SET value = excluded.value").
		ToSql()
	if err != nil {
		return fmt.Errorf("build cache schema signature upsert: %w", err)
	}
	if _, err = tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("save cache schema signature: %w", err)
	}

	query, args, err = s.builder.Delete("snyk_dast_findings").ToSql()
	if err != nil {
		return fmt.Errorf("build clear Snyk DAST cache rows query: %w", err)
	}
	if _, err = tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("clear Snyk DAST cache rows: %w", err)
	}
	for fingerprint, hash := range snapshot.SnykDASTHashes {
		query, args, err = s.builder.
			Insert("snyk_dast_findings").
			Columns("fingerprint", "hash").
			Values(fingerprint, hash).
			ToSql()
		if err != nil {
			return fmt.Errorf("build insert Snyk DAST cache row: %w", err)
		}
		if _, err = tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("insert Snyk DAST cache row: %w", err)
		}
	}

	query, args, err = s.builder.Delete("linear_issues").ToSql()
	if err != nil {
		return fmt.Errorf("build clear Linear cache rows query: %w", err)
	}
	if _, err = tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("clear Linear cache rows: %w", err)
	}
	for fingerprint, hash := range snapshot.LinearHashes {
		query, args, err = s.builder.
			Insert("linear_issues").
			Columns("fingerprint", "hash").
			Values(fingerprint, hash).
			ToSql()
		if err != nil {
			return fmt.Errorf("build insert Linear cache row: %w", err)
		}
		if _, err = tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("insert Linear cache row: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit cache transaction: %w", err)
	}

	return nil
}

func (s *Store) init(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS sync_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS snyk_dast_findings (
			fingerprint TEXT PRIMARY KEY,
			hash TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS linear_issues (
			fingerprint TEXT PRIMARY KEY,
			hash TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS snyk_dast_acceptances (
			fingerprint TEXT PRIMARY KEY,
			expires_at TEXT NOT NULL,
			active_until TEXT NOT NULL,
			confirmed_at TEXT
		)`,
	}

	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize sqlite cache: %w", err)
		}
	}

	query, args, err := s.builder.
		Insert("sync_meta").
		Columns("key", "value").
		Values("schema_version", schemaVersion).
		Suffix("ON CONFLICT(key) DO UPDATE SET value = excluded.value").
		ToSql()
	if err != nil {
		return fmt.Errorf("build initialize sqlite schema version upsert: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("initialize sqlite cache: %w", err)
	}

	return nil
}

// HasAcceptanceRows reports whether the cache holds any acceptance row. The
// sync reads it at the start of a run: an empty table means the sync has no
// memory of lapsed acceptances, so an earlier due date it computes may only
// reflect that gap (see the cold-start guard).
func (s *Store) HasAcceptanceRows(ctx context.Context) (bool, error) {
	query, args, err := s.builder.
		Select("1").
		From("snyk_dast_acceptances").
		Limit(1).
		ToSql()
	if err != nil {
		return false, fmt.Errorf("build cache acceptances presence query: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return false, fmt.Errorf("check cache acceptances presence: %w", err)
	}
	defer rows.Close()
	present := rows.Next()
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("check cache acceptances presence: %w", err)
	}
	return present, nil
}

// GetMeta returns the value stored under a sync_meta key, and whether the
// key exists.
func (s *Store) GetMeta(ctx context.Context, key string) (string, bool, error) {
	query, args, err := s.builder.
		Select("value").
		From("sync_meta").
		Where(sq.Eq{"key": key}).
		ToSql()
	if err != nil {
		return "", false, fmt.Errorf("build cache meta query: %w", err)
	}
	var value string
	switch err := s.db.QueryRowContext(ctx, query, args...).Scan(&value); {
	case err == nil:
		return value, true, nil
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	default:
		return "", false, fmt.Errorf("load cache meta %q: %w", key, err)
	}
}

// SetMeta stores a value under a sync_meta key, replacing any existing one.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	query, args, err := s.builder.
		Insert("sync_meta").
		Columns("key", "value").
		Values(key, value).
		Suffix("ON CONFLICT(key) DO UPDATE SET value = excluded.value").
		ToSql()
	if err != nil {
		return fmt.Errorf("build cache meta upsert: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("save cache meta %q: %w", key, err)
	}
	return nil
}

// DeleteMeta removes a sync_meta key. Removing an absent key is not an error.
func (s *Store) DeleteMeta(ctx context.Context, key string) error {
	query, args, err := s.builder.
		Delete("sync_meta").
		Where(sq.Eq{"key": key}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build cache meta delete: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("delete cache meta %q: %w", key, err)
	}
	return nil
}

// parseTimestamp parses a cache timestamp column value, normalised to UTC.
// An empty or unparsable value yields the zero time: the value is then
// unknown, never a reason to discard the row.
func parseTimestamp(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// LoadAcceptances returns every remembered acceptance, keyed by fingerprint.
// Rows are not aged out on read: for a lapsed acceptance the row is the only
// record of the expiry the due date is based on. Retention is decided by the
// Snyk DAST loader, which knows what the API currently says about each
// finding. A row whose expiry cannot be parsed is skipped, since it cannot
// serve as a due-date base.
func (s *Store) LoadAcceptances(ctx context.Context) (map[string]AcceptanceMeta, error) {
	out := make(map[string]AcceptanceMeta)

	query, args, err := s.builder.
		Select("fingerprint", "expires_at", "active_until", "confirmed_at").
		From("snyk_dast_acceptances").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build cache acceptances query: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("load cache acceptances: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var fingerprint, expiresAtRaw, activeUntilRaw string
		var confirmedAtRaw sql.NullString
		if err := rows.Scan(&fingerprint, &expiresAtRaw, &activeUntilRaw, &confirmedAtRaw); err != nil {
			return nil, fmt.Errorf("scan cache acceptance row: %w", err)
		}
		meta := AcceptanceMeta{
			Fingerprint: fingerprint,
			ExpiresAt:   parseTimestamp(expiresAtRaw),
			ActiveUntil: parseTimestamp(activeUntilRaw),
			ConfirmedAt: parseTimestamp(confirmedAtRaw.String),
		}
		if meta.ExpiresAt.IsZero() {
			continue
		}
		if meta.ActiveUntil.IsZero() {
			meta.ActiveUntil = meta.ExpiresAt
		}
		out[fingerprint] = meta
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cache acceptance rows: %w", err)
	}
	return out, nil
}

// SaveAcceptances replaces the remembered acceptances with the given set. A
// row with a zero ConfirmedAt is stamped with the time of the write. The
// replacement is one transaction, so a failed write leaves the previous rows
// in place.
func (s *Store) SaveAcceptances(ctx context.Context, acceptances map[string]AcceptanceMeta) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cache acceptances transaction: %w", err)
	}
	// Rollback also runs on shadowed error paths; after Commit it is a no-op.
	defer func() { _ = tx.Rollback() }()

	query, args, err := s.builder.Delete("snyk_dast_acceptances").ToSql()
	if err != nil {
		return fmt.Errorf("build clear cache acceptances query: %w", err)
	}
	if _, err = tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("clear cache acceptances: %w", err)
	}

	now := time.Now().UTC()
	for fingerprint, meta := range acceptances {
		if meta.ExpiresAt.IsZero() {
			continue
		}
		activeUntil := meta.ActiveUntil
		if activeUntil.IsZero() {
			activeUntil = meta.ExpiresAt
		}
		confirmedAt := meta.ConfirmedAt
		if confirmedAt.IsZero() {
			confirmedAt = now
		}
		query, args, err = s.builder.
			Insert("snyk_dast_acceptances").
			Columns("fingerprint", "expires_at", "active_until", "confirmed_at").
			Values(fingerprint, formatTimestamp(meta.ExpiresAt), formatTimestamp(activeUntil), formatTimestamp(confirmedAt)).
			ToSql()
		if err != nil {
			return fmt.Errorf("build insert cache acceptance row: %w", err)
		}
		if _, err = tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("insert cache acceptance row: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit cache acceptances transaction: %w", err)
	}
	return nil
}
