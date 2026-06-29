package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsAndValidation(t *testing.T) {
	t.Setenv("SNYK_DAST_API_KEY", "api-key")
	t.Setenv("LINEAR_API_KEY", "linear-key")
	t.Setenv("LINEAR_TEAM_ID", "team-id")
	t.Setenv("LINEAR_MANAGED_LABEL", "")
	t.Setenv("LINEAR_TARGET_TYPE_LABELS", "")
	t.Setenv("LINEAR_TARGET_TYPE_LABEL_DEFAULT", "")

	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.SnykDAST.APIBase != defaultSnykDASTAPIBase {
		t.Fatalf("APIBase = %q, want %q", cfg.SnykDAST.APIBase, defaultSnykDASTAPIBase)
	}
	if cfg.SnykDAST.AppBase != defaultSnykDASTAppBase {
		t.Fatalf("AppBase = %q, want %q", cfg.SnykDAST.AppBase, defaultSnykDASTAppBase)
	}
	if cfg.Linear.States.Todo != defaultLinearTodoState {
		t.Fatalf("Todo state = %q, want %q", cfg.Linear.States.Todo, defaultLinearTodoState)
	}
	if cfg.Linear.Labels.Managed != defaultManagedLabel {
		t.Fatalf("Managed label = %q, want %q", cfg.Linear.Labels.Managed, defaultManagedLabel)
	}
	if !cfg.Linear.UnsubscribeActor {
		t.Fatal("UnsubscribeActor = false, want true")
	}
	if cfg.Linear.Labels.TargetTypeDefault != "" {
		t.Fatalf("Target type default label = %q, want empty", cfg.Linear.Labels.TargetTypeDefault)
	}
	if len(cfg.Linear.Labels.TargetType) != 0 {
		t.Fatalf("Target type labels = %#v, want empty", cfg.Linear.Labels.TargetType)
	}
	if cfg.Linear.Due.CriticalDays != defaultCriticalDueDays {
		t.Fatalf("Critical due days = %d, want %d", cfg.Linear.Due.CriticalDays, defaultCriticalDueDays)
	}
	if cfg.Sync.Workers != defaultWorkerCount {
		t.Fatalf("Workers = %d, want %d", cfg.Sync.Workers, defaultWorkerCount)
	}
	if cfg.Cache.DBFile != defaultCacheDBFile {
		t.Fatalf("Cache DB file = %q, want %q", cfg.Cache.DBFile, defaultCacheDBFile)
	}
	if cfg.Cache.BypassCache {
		t.Fatal("BypassCache = true, want false")
	}
}

func TestLoadRequiresCredentials(t *testing.T) {
	for _, key := range []string{
		"SNYK_DAST_API_KEY",
		"LINEAR_API_KEY",
		"LINEAR_TEAM_ID",
	} {
		t.Setenv(key, "")
	}

	if _, err := Load(nil); err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
}

func TestLoadEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "export SNYK_DAST_API_KEY='api-key'\n" +
		"LINEAR_API_KEY=linear-key\n" +
		"LINEAR_TEAM_ID=team-id\n" +
		"LINEAR_MANAGED_LABEL=off\n" +
		"LINEAR_UNSUBSCRIBE_ACTOR=true\n" +
		"LINEAR_TARGET_TYPE_LABELS=single:snyk-dast-web,api:snyk-dast-api\n" +
		"LINEAR_TARGET_TYPE_LABEL_DEFAULT=off\n" +
		"LINEAR_DUE_DAYS_CRITICAL=20\n" +
		"SNYK_DAST_TEAM=team-abc\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := Load([]string{"--env-file", path})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.SnykDAST.APIKey != "api-key" {
		t.Fatalf("APIKey = %q, want %q", cfg.SnykDAST.APIKey, "api-key")
	}
	if cfg.SnykDAST.Team != "team-abc" {
		t.Fatalf("Team = %q, want %q", cfg.SnykDAST.Team, "team-abc")
	}
	if cfg.Linear.APIKey != "linear-key" {
		t.Fatalf("APIKey = %q, want %q", cfg.Linear.APIKey, "linear-key")
	}
	if cfg.Linear.TeamID != "team-id" {
		t.Fatalf("TeamID = %q, want %q", cfg.Linear.TeamID, "team-id")
	}
	if cfg.Linear.Labels.Managed != "" {
		t.Fatalf("Managed label = %q, want empty", cfg.Linear.Labels.Managed)
	}
	if !cfg.Linear.UnsubscribeActor {
		t.Fatal("UnsubscribeActor = false, want true")
	}
	if cfg.Linear.Labels.TargetTypeDefault != "" {
		t.Fatalf("Target type default label = %q, want empty", cfg.Linear.Labels.TargetTypeDefault)
	}
	if cfg.Linear.Labels.TargetType["single"] != "snyk-dast-web" || cfg.Linear.Labels.TargetType["api"] != "snyk-dast-api" {
		t.Fatalf("Target type labels = %#v, want single/api mappings", cfg.Linear.Labels.TargetType)
	}
	if cfg.Linear.Due.CriticalDays != 20 {
		t.Fatalf("Critical due days = %d, want %d", cfg.Linear.Due.CriticalDays, 20)
	}
}

func TestLoadRejectsMalformedTargetTypeLabels(t *testing.T) {
	t.Setenv("SNYK_DAST_API_KEY", "api-key")
	t.Setenv("LINEAR_API_KEY", "linear-key")
	t.Setenv("LINEAR_TEAM_ID", "team-id")
	t.Setenv("LINEAR_TARGET_TYPE_LABELS", "single")

	if _, err := Load(nil); err == nil {
		t.Fatal("Load() error = nil, want parse error")
	}
}
