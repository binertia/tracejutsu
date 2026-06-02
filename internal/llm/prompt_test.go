package llm_test

import (
	"strings"
	"testing"
	"time"

	"runtime-guard/internal/compress"
	"runtime-guard/internal/llm"
)

func TestBuildPromptRedactsSensitiveIncidentFields(t *testing.T) {
	incident := compress.Incident{
		IncidentID: "inc-secret",
		StartTime:  time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC),
		EndTime:    time.Date(2026, time.June, 2, 12, 1, 0, 0, time.UTC),
		RootProcess: compress.RootProcess{
			ProcessName:    "curl",
			ExecutablePath: "/usr/bin/curl?token=abc123",
		},
		ProcessTree: []string{"curl -> sh token=abc123"},
		Timeline:    []string{"curl fetched https://example.com/?password=supersecret"},
		Summary:     "secret=abc123",
	}

	prompt, err := llm.BuildPrompt(incident)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"abc123", "supersecret"} {
		if strings.Contains(prompt, forbidden) {
			t.Fatalf("prompt leaked %q: %s", forbidden, prompt)
		}
	}
	if !strings.Contains(prompt, "[REDACTED]") {
		t.Fatal("prompt did not include redacted markers")
	}
	if !strings.Contains(prompt, "must be JSON arrays of strings") {
		t.Fatal("prompt did not describe required list field types")
	}
}
