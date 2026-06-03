package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func prepareSQLitePath(path string) error {
	if path == ":memory:" {
		return nil
	}
	if strings.HasPrefix(path, "file:") || strings.Contains(path, "?") {
		return errors.New("SQLite URI and option paths are not supported")
	}
	if err := validateSQLiteParent(path); err != nil {
		return err
	}

	info, err := os.Lstat(path)
	if err == nil {
		if err := validateSQLiteSidecars(path); err != nil {
			return err
		}
		return validateSQLiteFileInfo(path, info)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect SQLite database path: %w", err)
	}
	if err := rejectSQLiteSidecars(path); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private SQLite database: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close new SQLite database: %w", err)
	}
	return nil
}

func validateSQLiteParent(path string) error {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve SQLite database path: %w", err)
	}
	parent := filepath.Dir(absolutePath)
	info, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("inspect SQLite parent directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("SQLite parent path must be a directory: %q", parent)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("SQLite parent directory permissions %04o permit group or other writes: %q",
			info.Mode().Perm(), parent)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect SQLite parent directory owner: %q", parent)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("SQLite parent directory owner UID %d does not match process UID %d: %q",
			stat.Uid, os.Geteuid(), parent)
	}
	return nil
}

func validateSQLiteFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect SQLite database path after open: %w", err)
	}
	if err := validateSQLiteFileInfo(path, info); err != nil {
		return err
	}
	return validateSQLiteSidecars(path)
}

func validateSQLiteFileInfo(path string, info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("SQLite database must be a regular file: %q", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("SQLite database permissions %04o grant group or other access; run chmod 0600 %q",
			info.Mode().Perm(), path)
	}
	return nil
}

func validateSQLiteSidecars(path string) error {
	for _, sidecar := range sqliteSidecarPaths(path) {
		info, err := os.Lstat(sidecar)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect SQLite sidecar path: %w", err)
		}
		if err := validateSQLiteFileInfo(sidecar, info); err != nil {
			return err
		}
	}
	return nil
}

func rejectSQLiteSidecars(path string) error {
	for _, sidecar := range sqliteSidecarPaths(path) {
		_, err := os.Lstat(sidecar)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect SQLite sidecar path: %w", err)
		}
		return fmt.Errorf("SQLite sidecar exists without database: %q", sidecar)
	}
	return nil
}

func sqliteSidecarPaths(path string) []string {
	return []string{path + "-wal", path + "-shm"}
}
