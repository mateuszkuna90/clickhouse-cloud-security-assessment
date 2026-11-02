package cli

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// OutputFile is the part of *os.File the report writer uses.
type OutputFile interface {
	io.Writer
	Sync() error
	Close() error
}

// createExclusive creates a new file for the report (DESIGN.md 5.9). It
// fails if anything already exists at path, including a symlink, so an
// existing file is never overwritten or truncated.
//
// On Unix-like systems the mode is 0600 (the umask can only remove bits).
// On Windows the mode only controls the read-only attribute: the file
// inherits the ACL of its directory.
func createExclusive(path string) (OutputFile, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// Output errors. Their text is fixed; the OS error is not shown, and the
// path is printed separately by the caller.
var (
	errOutputExists    = errors.New("output file already exists; it is never overwritten")
	errOutputDir       = errors.New("the output file's directory does not exist or is not a directory")
	errOutputCheck     = errors.New("the output path could not be checked")
	errOutputCreate    = errors.New("the output file could not be created")
	errOutputWrite     = errors.New("the report could not be written completely; the partial file was removed")
	errOutputRemove    = errors.New("the report could not be written completely, and the partial file could not be removed")
	errStdoutWrite     = errors.New("the report could not be written to stdout")
	errOutputSyncClose = errors.New("the report could not be flushed to disk; the partial file was removed")
)

// checkOutputPath is the startup check (exit 3): nothing may exist at the
// path, and its directory must exist. The exclusive create at the end of
// the run is the authoritative check.
func checkOutputPath(path string, lstat func(string) (fs.FileInfo, error)) error {
	if _, err := lstat(path); err == nil {
		return errOutputExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return errOutputCheck
	}
	dir := filepath.Dir(path)
	info, err := lstat(dir)
	if err != nil {
		return errOutputDir
	}
	if !info.IsDir() {
		// A symlink to a directory is followed with Stat.
		if info.Mode()&fs.ModeSymlink == 0 {
			return errOutputDir
		}
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return errOutputDir
		}
	}
	return nil
}

// writeFile writes data to a new file. On any write, sync or close error
// the partial file is removed, so a truncated report is never left behind.
func writeFile(path string, data []byte, create func(string) (OutputFile, error),
	remove func(string) error) error {
	f, err := create(path)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errOutputExists
		}
		return errOutputCreate
	}
	_, werr := f.Write(data)
	var serr error
	if werr == nil {
		serr = f.Sync()
	}
	cerr := f.Close()
	if werr == nil && serr == nil && cerr == nil {
		return nil
	}
	if rerr := remove(path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return errOutputRemove
	}
	if werr != nil {
		return errOutputWrite
	}
	return errOutputSyncClose
}

// writeStdout writes the whole report to w.
func writeStdout(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil || n != len(data) {
		return errStdoutWrite
	}
	return nil
}
