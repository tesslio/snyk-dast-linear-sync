package snykdast

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tesslio/snyk-dast-linear-sync/internal/model"
)

func TestMapStatus(t *testing.T) {
	future := "2126-06-01"
	past := "2000-01-01"

	cases := []struct {
		name           string
		state          string
		expirationDate *string
		want           model.FindingStatus
		wantExpires    bool
	}{
		{"notfixed", "notfixed", nil, model.FindingOpen, false},
		{"retesting is open", "retesting", nil, model.FindingOpen, false},
		{"fixed", "fixed", nil, model.FindingFixed, false},
		{"invalid is ignored", "invalid", nil, model.FindingIgnored, false},
		{"accepted without expiry is ignored", "accepted", nil, model.FindingIgnored, false},
		{"accepted with past expiry is ignored", "accepted", &past, model.FindingIgnored, false},
		{"accepted with future expiry is snoozed", "accepted", &future, model.FindingSnoozed, true},
		{"unknown state defaults to open", "unknown", nil, model.FindingOpen, false},
		{"empty state defaults to open", "", nil, model.FindingOpen, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, expires := mapStatus(tc.state, tc.expirationDate)
			if got != tc.want {
				t.Fatalf("mapStatus() = %q, want %q", got, tc.want)
			}
			if tc.wantExpires && expires.IsZero() {
				t.Fatalf("mapStatus() expires = zero, want non-zero")
			}
			if !tc.wantExpires && !expires.IsZero() {
				t.Fatalf("mapStatus() expires = %v, want zero", expires)
			}
		})
	}
}

func TestMapStatusSnoozedParsesExpiry(t *testing.T) {
	expiry := "2126-06-01"
	_, expires := mapStatus("accepted", &expiry)
	want := time.Date(2126, time.June, 1, 0, 0, 0, 0, time.UTC)
	if !expires.Equal(want) {
		t.Fatalf("expires = %v, want %v", expires, want)
	}
}

func TestMapSeverity(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{40, "critical"},
		{30, "high"},
		{20, "medium"},
		{10, "low"},
		{0, "unknown"},
		{99, "unknown"},
	}
	for _, tc := range cases {
		if got := mapSeverity(tc.code); got != tc.want {
			t.Errorf("mapSeverity(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestEnrichCorrelationsFetchesAndAttachesMarkdown(t *testing.T) {
	// Stand up a fake Snyk DAST API that serves findings with snyk_sast=true
	// and correlation markdown for one finding.
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	base, _ := url.Parse(server.URL + "/")
	c := &Client{
		apiBase:     base,
		httpClient:  server.Client(),
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		concurrency: 2,
	}

	// correlation endpoint for finding 1 (numeric id "1") on target-a
	mux.HandleFunc("/targets/target-a/findings/1/integrations/snyk-sast/correlations/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(paginatedCorrelations{
			Count: 1, PageTotal: 1, Page: 1, Length: 100,
			Results: []correlationNode{
				{ID: "corr-1", Confirmed: true, Markdown: "**Snyk Code:** [SQLi in `db.go:42`](https://app.snyk.io/...)"},
			},
		})
	})

	findings := []model.Finding{
		{Fingerprint: "snyk-dast:target-a:1", SnykDASTFindingID: "1", TargetID: "target-a"},
		{Fingerprint: "snyk-dast:target-b:2", SnykDASTFindingID: "2", TargetID: "target-b"},
	}
	correlated := []bool{true, false}
	if err := c.enrichCorrelations(context.Background(), findings, correlated); err != nil {
		t.Fatalf("enrichCorrelations() error = %v", err)
	}
	if len(findings[0].CorrelationMarkdown) != 1 || !strings.Contains(findings[0].CorrelationMarkdown[0], "db.go:42") {
		t.Fatalf("finding 0 correlation markdown = %#v", findings[0].CorrelationMarkdown)
	}
	if len(findings[1].CorrelationMarkdown) != 0 {
		t.Fatalf("finding 1 should have no correlation markdown, got %#v", findings[1].CorrelationMarkdown)
	}
}

func TestNumericFindingID(t *testing.T) {
	cases := []struct {
		composite string
		want      string
	}{
		{"su2d3k-123", "123"},
		{"abc-456", "456"},
		{"123", "123"},
		{"", ""},
		{"abc-", ""},
	}
	for _, tc := range cases {
		if got := numericFindingID(tc.composite); got != tc.want {
			t.Errorf("numericFindingID(%q) = %q, want %q", tc.composite, got, tc.want)
		}
	}
}
