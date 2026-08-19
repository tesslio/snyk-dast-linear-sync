package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

const (
	defaultSnykDASTAppBase      = "https://app.probely.com"
	defaultSnykDASTAPIBase      = "https://api.probely.com"
	defaultManagedLabel         = "snyk-dast-automation"
	defaultLinearTodoState      = "Todo"
	defaultLinearBacklogState   = "Backlog"
	defaultLinearDoneState      = "Done"
	defaultLinearCancelledState = "Cancelled"
	defaultCriticalDueDays      = 15
	defaultHighDueDays          = 30
	defaultMediumDueDays        = 45
	defaultLowDueDays           = 90
	defaultWorkerCount          = 16
	defaultSnykDASTConcurrency  = 6
	defaultLinearConcurrency    = 8
	defaultErrorLogFile         = "logs/snyk-dast-linear-sync-errors.log"
	defaultCacheDBFile          = "data/snyk-dast-linear-sync-cache.db"

	// defaultArchiveLookbackDays bounds how long ago an issue may have been
	// auto-archived and still be pulled into the snapshot. Linear excludes
	// archived issues from the default issues query, so a closed managed ticket
	// that Linear has since auto-archived would otherwise look absent and be
	// recreated.
	//
	// Note what this window is and is not: it bounds the time elapsed SINCE
	// archiving, not the length of the team's auto-archive period (which Linear
	// expresses in months, via Team.autoArchivePeriod). The two are independent,
	// and a short window is not made safe by a short period.
	//
	// Because Snyk DAST retains fixed/accepted/invalid findings indefinitely,
	// every one of them keeps a live desired issue forever, so ANY finite window
	// eventually loses the ticket and mints a duplicate — and since the original
	// is no longer visible, duplicate cancellation cannot pair them up and the
	// copies accumulate. Correctness therefore wants the window to cover the
	// entire archived backlog, which is why the default is effectively
	// unbounded. It stays configurable purely as a size/latency escape hatch:
	// lowering it trades duplicate-freedom for a smaller snapshot on each run.
	defaultArchiveLookbackDays = 3650
)

type Config struct {
	DryRun  bool
	Verbose bool

	Log      LogConfig
	Cache    CacheConfig
	SnykDAST SnykDASTConfig
	Linear   LinearConfig
	Sync     SyncConfig
}

type LogConfig struct {
	ErrorFile string
}

type CacheConfig struct {
	DBFile      string
	BypassCache bool
}

type SnykDASTConfig struct {
	APIKey  string
	APIBase string
	AppBase string
	// Team optionally restricts the sync to targets belonging to a specific
	// Snyk DAST team id. When empty, all targets accessible to the API key are
	// synced.
	Team string
}

type LinearConfig struct {
	APIKey           string
	TeamID           string
	UnsubscribeActor bool
	CommentsEnabled  bool
	// ArchiveLookbackDays bounds how far back auto-archived Linear issues are
	// pulled into the snapshot. See defaultArchiveLookbackDays.
	ArchiveLookbackDays int
	States              StateConfig
	Labels              LabelConfig
	Due                 DueDateConfig
}

type StateConfig struct {
	Todo      string
	Backlog   string
	Done      string
	Cancelled string
}

type LabelConfig struct {
	Managed           string
	TargetType        map[string]string
	TargetTypeDefault string
	CheckType         map[string]string
	CheckTypeDefault  string
}

type DueDateConfig struct {
	CriticalDays int
	HighDays     int
	MediumDays   int
	LowDays      int
}

type SyncConfig struct {
	Workers             int
	SnykDASTConcurrency int
	LinearConcurrency   int
}

func Load(args []string) (Config, error) {
	fs := flag.NewFlagSet("snyk-dast-linear-sync", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	dryRun := fs.Bool("dry-run", false, "plan changes without mutating Linear")
	verbose := fs.Bool("verbose", false, "log each planned create/update/resolve with its title, state, due date, and labels")
	bypassCache := fs.Bool("bypass-cache", false, "ignore the SQLite sync cache and fetch/compare everything directly")
	envFile := fs.String("env-file", "", "load configuration from a dotenv-style file before reading the process environment")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(*envFile) != "" {
		path := strings.TrimSpace(*envFile)
		if err := godotenv.Overload(path); err != nil {
			return Config{}, fmt.Errorf("load env file %q: %w", path, err)
		}
	}

	targetTypeLabels, err := parseLabelMap("LINEAR_TARGET_TYPE_LABELS", os.Getenv("LINEAR_TARGET_TYPE_LABELS"))
	if err != nil {
		return Config{}, err
	}
	checkTypeLabels, err := parseLabelMap("LINEAR_CHECK_TYPE_LABELS", os.Getenv("LINEAR_CHECK_TYPE_LABELS"))
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		DryRun:  *dryRun,
		Verbose: *verbose,
		Log: LogConfig{
			ErrorFile: getEnv("ERROR_LOG_FILE", defaultErrorLogFile),
		},
		Cache: CacheConfig{
			DBFile:      getEnv("CACHE_DB_FILE", defaultCacheDBFile),
			BypassCache: *bypassCache,
		},
		SnykDAST: SnykDASTConfig{
			APIKey:  os.Getenv("SNYK_DAST_API_KEY"),
			APIBase: getEnv("SNYK_DAST_API_BASE", defaultSnykDASTAPIBase),
			AppBase: getEnv("SNYK_DAST_APP_BASE", defaultSnykDASTAppBase),
			Team:    strings.TrimSpace(os.Getenv("SNYK_DAST_TEAM")),
		},
		Linear: LinearConfig{
			APIKey:           os.Getenv("LINEAR_API_KEY"),
			TeamID:           os.Getenv("LINEAR_TEAM_ID"),
			UnsubscribeActor: getEnvBool("LINEAR_UNSUBSCRIBE_ACTOR", true),
			CommentsEnabled:  getEnvBool("LINEAR_COMMENTS", false),

			ArchiveLookbackDays: getEnvInt("LINEAR_ARCHIVE_LOOKBACK_DAYS", defaultArchiveLookbackDays),
			States: StateConfig{
				Todo:      getEnv("LINEAR_STATE_TODO", defaultLinearTodoState),
				Backlog:   getEnv("LINEAR_STATE_BACKLOG", defaultLinearBacklogState),
				Done:      getEnv("LINEAR_STATE_DONE", defaultLinearDoneState),
				Cancelled: getEnv("LINEAR_STATE_CANCELLED", defaultLinearCancelledState),
			},
			Labels: LabelConfig{
				Managed:           normalizeManagedLabel(getEnv("LINEAR_MANAGED_LABEL", defaultManagedLabel)),
				TargetType:        targetTypeLabels,
				TargetTypeDefault: normalizeManagedLabel(getEnv("LINEAR_TARGET_TYPE_LABEL_DEFAULT", "")),
				CheckType:         checkTypeLabels,
				CheckTypeDefault:  normalizeManagedLabel(getEnv("LINEAR_CHECK_TYPE_LABEL_DEFAULT", "")),
			},
			Due: DueDateConfig{
				CriticalDays: getEnvInt("LINEAR_DUE_DAYS_CRITICAL", defaultCriticalDueDays),
				HighDays:     getEnvInt("LINEAR_DUE_DAYS_HIGH", defaultHighDueDays),
				MediumDays:   getEnvInt("LINEAR_DUE_DAYS_MEDIUM", defaultMediumDueDays),
				LowDays:      getEnvInt("LINEAR_DUE_DAYS_LOW", defaultLowDueDays),
			},
		},
		Sync: SyncConfig{
			Workers:             getEnvInt("SYNC_WORKERS", defaultWorkerCount),
			SnykDASTConcurrency: getEnvInt("SNYK_DAST_HTTP_CONCURRENCY", defaultSnykDASTConcurrency),
			LinearConcurrency:   getEnvInt("LINEAR_HTTP_CONCURRENCY", defaultLinearConcurrency),
		},
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	var errs []error

	if c.SnykDAST.APIKey == "" {
		errs = append(errs, errors.New("SNYK_DAST_API_KEY is required"))
	}
	if strings.TrimSpace(c.SnykDAST.APIBase) == "" {
		errs = append(errs, errors.New("SNYK_DAST_API_BASE must not be empty"))
	}
	if strings.TrimSpace(c.SnykDAST.AppBase) == "" {
		errs = append(errs, errors.New("SNYK_DAST_APP_BASE must not be empty"))
	}
	if c.Linear.APIKey == "" {
		errs = append(errs, errors.New("LINEAR_API_KEY is required"))
	}
	if c.Linear.TeamID == "" {
		errs = append(errs, errors.New("LINEAR_TEAM_ID is required"))
	}
	if c.Linear.ArchiveLookbackDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_ARCHIVE_LOOKBACK_DAYS must be > 0, got %d", c.Linear.ArchiveLookbackDays))
	}
	if strings.TrimSpace(c.Log.ErrorFile) == "" {
		errs = append(errs, errors.New("ERROR_LOG_FILE must not be empty"))
	}
	if strings.TrimSpace(c.Cache.DBFile) == "" {
		errs = append(errs, errors.New("CACHE_DB_FILE must not be empty"))
	}
	if c.Sync.Workers <= 0 {
		errs = append(errs, fmt.Errorf("SYNC_WORKERS must be > 0, got %d", c.Sync.Workers))
	}
	if c.Sync.SnykDASTConcurrency <= 0 {
		errs = append(errs, fmt.Errorf("SNYK_DAST_HTTP_CONCURRENCY must be > 0, got %d", c.Sync.SnykDASTConcurrency))
	}
	if c.Sync.LinearConcurrency <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_HTTP_CONCURRENCY must be > 0, got %d", c.Sync.LinearConcurrency))
	}
	if c.Linear.Due.CriticalDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_CRITICAL must be > 0, got %d", c.Linear.Due.CriticalDays))
	}
	if c.Linear.Due.HighDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_HIGH must be > 0, got %d", c.Linear.Due.HighDays))
	}
	if c.Linear.Due.MediumDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_MEDIUM must be > 0, got %d", c.Linear.Due.MediumDays))
	}
	if c.Linear.Due.LowDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_LOW must be > 0, got %d", c.Linear.Due.LowDays))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func getEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}

	return n
}

func getEnvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}

	return v
}

func normalizeManagedLabel(raw string) string {
	value := strings.TrimSpace(raw)
	switch strings.ToLower(value) {
	case "", "off", "false", "disabled", "none":
		return ""
	default:
		return value
	}
}

func parseLabelMap(envName, raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	out := make(map[string]string)
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		key, label, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("%s entry %q must use key:label format", envName, part)
		}

		key = strings.ToLower(strings.TrimSpace(key))
		label = normalizeManagedLabel(label)
		if key == "" {
			return nil, fmt.Errorf("%s entry %q is missing the key", envName, part)
		}
		if label == "" {
			return nil, fmt.Errorf("%s entry %q is missing the label name", envName, part)
		}

		out[key] = label
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
