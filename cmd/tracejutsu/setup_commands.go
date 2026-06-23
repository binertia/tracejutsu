package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"tracejutsu/internal/report"
	"tracejutsu/internal/store"
)

func runInit(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", defaultDatabasePath(), "SQLite database path")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New("usage: tracejutsu init [--db path]")
	}

	if err := ensureDatabaseParent(*databasePath); err != nil {
		return err
	}
	database, err := store.OpenSQLite(*databasePath)
	if err != nil {
		return withSQLitePathHint(err, *databasePath)
	}
	defer database.Close()

	fmt.Fprintf(out, "initialized tracejutsu database: %s\n", report.TerminalText(*databasePath))
	return nil
}

type doctorCheck struct {
	Status string
	Name   string
	Detail string
}

func runDoctor(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", defaultDatabasePath(), "SQLite database path")
	service := flags.Bool("service", false, "check tracejutsu.service with systemctl when available")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New("usage: tracejutsu doctor [--db path] [--service]")
	}

	checks := []doctorCheck{
		{Status: "OK", Name: "os", Detail: runtime.GOOS},
		{Status: "OK", Name: "arch", Detail: runtime.GOARCH},
		{Status: "OK", Name: "db_path", Detail: *databasePath},
	}
	checks = append(checks, checkDatabasePath(*databasePath)...)
	if *service {
		checks = append(checks, checkSystemdService())
	}

	fmt.Fprintln(out, "tracejutsu doctor")
	failures := 0
	for _, check := range checks {
		if check.Status == "FAIL" {
			failures++
		}
		fmt.Fprintf(out, "%-4s %-16s %s\n", check.Status, check.Name, report.TerminalText(check.Detail))
	}
	if failures > 0 {
		return fmt.Errorf("doctor found %d failed check(s)", failures)
	}
	return nil
}

func checkDatabasePath(path string) []doctorCheck {
	if path == ":memory:" {
		return []doctorCheck{{Status: "FAIL", Name: "database", Detail: "doctor requires a filesystem SQLite database"}}
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return []doctorCheck{{Status: "FAIL", Name: "db_path", Detail: err.Error()}}
	}
	parent := filepath.Dir(absolutePath)
	checks := make([]doctorCheck, 0, 5)
	parentInfo, err := os.Stat(parent)
	if err != nil {
		checks = append(checks, doctorCheck{
			Status: "WARN",
			Name:   "db_parent",
			Detail: fmt.Sprintf("%s missing; run `tracejutsu init --db %s`", parent, path),
		})
		return checks
	}
	if !parentInfo.IsDir() {
		checks = append(checks, doctorCheck{Status: "FAIL", Name: "db_parent", Detail: parent + " is not a directory"})
		return checks
	}
	if parentInfo.Mode().Perm()&0o022 != 0 {
		checks = append(checks, doctorCheck{
			Status: "FAIL",
			Name:   "db_parent",
			Detail: fmt.Sprintf("%s permissions %04o permit group or other writes", parent, parentInfo.Mode().Perm()),
		})
	} else {
		checks = append(checks, doctorCheck{Status: "OK", Name: "db_parent", Detail: parent + " is private"})
	}
	if stat, ok := parentInfo.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Geteuid()) {
		checks = append(checks, doctorCheck{
			Status: "FAIL",
			Name:   "db_owner",
			Detail: fmt.Sprintf("parent UID %d does not match process UID %d", stat.Uid, os.Geteuid()),
		})
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		checks = append(checks, doctorCheck{
			Status: "WARN",
			Name:   "database",
			Detail: fmt.Sprintf("%s does not exist; run `tracejutsu init --db %s`", path, path),
		})
		return checks
	}
	if err != nil {
		checks = append(checks, doctorCheck{Status: "FAIL", Name: "database", Detail: err.Error()})
		return checks
	}
	if !info.Mode().IsRegular() {
		checks = append(checks, doctorCheck{Status: "FAIL", Name: "database", Detail: path + " is not a regular file"})
	} else if info.Mode().Perm()&0o077 != 0 {
		checks = append(checks, doctorCheck{
			Status: "FAIL",
			Name:   "database",
			Detail: fmt.Sprintf("%s permissions %04o grant group or other access", path, info.Mode().Perm()),
		})
	} else {
		checks = append(checks, doctorCheck{Status: "OK", Name: "database", Detail: path + " is private"})
	}
	checks = append(checks, checkSQLiteSidecar(path, "-wal"))
	checks = append(checks, checkSQLiteSidecar(path, "-shm"))
	checks = append(checks, checkReadOnlyJournalMode(path))
	return checks
}

func checkSQLiteSidecar(path string, suffix string) doctorCheck {
	sidecar := path + suffix
	info, err := os.Lstat(sidecar)
	if errors.Is(err, os.ErrNotExist) {
		return doctorCheck{Status: "OK", Name: "sqlite" + suffix, Detail: "not present"}
	}
	if err != nil {
		return doctorCheck{Status: "FAIL", Name: "sqlite" + suffix, Detail: err.Error()}
	}
	if !info.Mode().IsRegular() {
		return doctorCheck{Status: "FAIL", Name: "sqlite" + suffix, Detail: sidecar + " is not a regular file"}
	}
	if info.Mode().Perm()&0o077 != 0 {
		return doctorCheck{
			Status: "FAIL",
			Name:   "sqlite" + suffix,
			Detail: fmt.Sprintf("%s permissions %04o grant group or other access", sidecar, info.Mode().Perm()),
		}
	}
	return doctorCheck{Status: "OK", Name: "sqlite" + suffix, Detail: sidecar + " is private"}
}

func checkReadOnlyJournalMode(path string) doctorCheck {
	uri := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	database, err := sql.Open("sqlite3", uri.String())
	if err != nil {
		return doctorCheck{Status: "WARN", Name: "journal_mode", Detail: err.Error()}
	}
	defer database.Close()

	var mode string
	if err := database.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		return doctorCheck{Status: "WARN", Name: "journal_mode", Detail: err.Error()}
	}
	if mode != "wal" {
		return doctorCheck{Status: "WARN", Name: "journal_mode", Detail: mode + " (expected wal after initialization)"}
	}
	return doctorCheck{Status: "OK", Name: "journal_mode", Detail: mode}
}

func checkSystemdService() doctorCheck {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return doctorCheck{Status: "WARN", Name: "service", Detail: "systemctl not found"}
	}
	output, err := exec.Command("systemctl", "is-active", "tracejutsu.service").CombinedOutput()
	status := string(output)
	if len(status) > 0 && status[len(status)-1] == '\n' {
		status = status[:len(status)-1]
	}
	if err != nil {
		if status == "" {
			status = err.Error()
		}
		return doctorCheck{Status: "WARN", Name: "service", Detail: status}
	}
	return doctorCheck{Status: "OK", Name: "service", Detail: status}
}
