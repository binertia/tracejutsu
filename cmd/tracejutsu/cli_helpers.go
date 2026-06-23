package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	formatText = "text"
	formatJSON = "json"
)

func defaultDatabasePath() string {
	if path := os.Getenv("TRACEJUTSU_DB"); path != "" {
		return path
	}
	if stateHome := os.Getenv("XDG_STATE_HOME"); stateHome != "" {
		return filepath.Join(stateHome, "tracejutsu", "tracejutsu.db")
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".local", "state", "tracejutsu", "tracejutsu.db")
	}
	return defaultDB
}

func ensureDatabaseParent(path string) error {
	if path == ":memory:" {
		return errors.New("init requires a filesystem SQLite database")
	}
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("SQLite parent path must be a directory: %q", parent)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect SQLite parent directory: %w", err)
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create SQLite parent directory %q: %w", parent, err)
	}
	return nil
}

func withSQLitePathHint(err error, path string) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "does not exist"):
		return fmt.Errorf("%w (hint: run `tracejutsu init --db %s` to create a private database)", err, path)
	case strings.Contains(message, "parent directory permissions") ||
		strings.Contains(message, "parent directory owner") ||
		strings.Contains(message, "permissions") ||
		strings.Contains(message, "sidecar"):
		return fmt.Errorf("%w (hint: use `tracejutsu init --db %s` or move the database under a 0700 private state directory)", err, path)
	default:
		return err
	}
}

func parseOutputFormat(value string) (string, error) {
	switch value {
	case formatText, formatJSON:
		return value, nil
	default:
		return "", fmt.Errorf("format must be %q or %q", formatText, formatJSON)
	}
}

func writeJSON(out io.Writer, payload any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func parseOptionalTime(value string, flagName string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339 time: %w", flagName, err)
	}
	return parsed.UTC(), nil
}
