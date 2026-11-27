package backup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// cleanRel validates one slash-separated managed relative path. Absolute paths,
// backslashes, "." / ".." components and non-canonical forms are all refused.
func cleanRel(rel string) (string, error) {
	if rel == "" || strings.Contains(rel, "\\") || strings.HasPrefix(rel, "/") {
		return "", fmt.Errorf("unsafe archive path %q", rel)
	}
	clean := path.Clean(rel)
	if clean != rel || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe archive path %q", rel)
	}
	return clean, nil
}

// securePath resolves rel under root and rejects any symlink component. A
// missing final component is allowed when forWrite is set; missing parents are
// only tolerated while creating (secureMkdirAll).
func securePath(root, rel string, forWrite bool) (string, error) {
	clean, err := cleanRel(rel)
	if err != nil {
		return "", err
	}
	parts := strings.Split(clean, "/")
	cur := root
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		last := i == len(parts)-1
		fi, statErr := os.Lstat(cur)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				if forWrite || last {
					return cur, nil
				}
				return "", statErr
			}
			return "", statErr
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink refused: %s", cur)
		}
		if !last && !fi.IsDir() {
			return "", fmt.Errorf("unsafe parent: %s", cur)
		}
		if last && forWrite && !fi.Mode().IsRegular() {
			return "", fmt.Errorf("target is not a regular file: %s", cur)
		}
	}
	return cur, nil
}

// secureMkdirAll creates rel under root one component at a time, refusing to
// pass through an existing symlink.
func secureMkdirAll(root, rel string, mode os.FileMode) (string, error) {
	clean, err := cleanRel(rel)
	if err != nil {
		return "", err
	}
	cur := root
	for _, part := range strings.Split(clean, "/") {
		cur = filepath.Join(cur, part)
		fi, statErr := os.Lstat(cur)
		switch {
		case statErr == nil:
			if fi.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("symlink refused: %s", cur)
			}
			if !fi.IsDir() {
				return "", fmt.Errorf("not a directory: %s", cur)
			}
		case errors.Is(statErr, os.ErrNotExist):
			if err := os.Mkdir(cur, mode); err != nil {
				return "", err
			}
		default:
			return "", statErr
		}
	}
	return cur, nil
}

// readNoFollow reads a regular file without following a final symlink.
func readNoFollow(p string) ([]byte, os.FileMode, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !fi.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("not a regular file: %s", p)
	}
	if fi.Size() > maxManagedFileBytes {
		return nil, 0, fmt.Errorf("managed file exceeds the size limit: %s", p)
	}
	body, err := io.ReadAll(io.LimitReader(f, maxManagedFileBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(body)) > maxManagedFileBytes {
		return nil, 0, fmt.Errorf("managed file exceeds the size limit: %s", p)
	}
	return body, fi.Mode().Perm(), nil
}

// writeAtomicFile writes through a sibling temp file and renames it into place.
// The rename replaces the directory entry, so an existing symlink at dst is
// replaced rather than followed.
func writeAtomicFile(dst string, body []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(dst)
	f, err := os.CreateTemp(dir, ".idleleo-restore-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if uid >= 0 && gid >= 0 && (uid != os.Getuid() || gid != os.Getgid()) {
		if err := f.Chown(uid, gid); err != nil && !errors.Is(err, os.ErrPermission) {
			f.Close()
			return err
		}
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// writeFileSync writes a small file and fsyncs it. Used for journals.
func writeFileSync(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".idleleo-journal-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// archiveInsideManaged reports whether archive is inside a managed tree, which
// would make a backup archive include itself.
func archiveInsideManaged(root, archive string) bool {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absArchive, err := filepath.Abs(archive)
	if err != nil {
		return false
	}
	for _, rel := range append(append([]string{}, managedDirs...), geodataDir) {
		dir := filepath.Join(absRoot, filepath.FromSlash(rel))
		if absArchive == dir || strings.HasPrefix(absArchive, dir+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// ensureRoot returns the resolved root and refuses a missing directory.
func ensureRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", errors.New("root is not a directory")
	}
	return abs, nil
}

// managedRelativeRoots is a small helper for traversal tests.
func managedRelativeRoots() []string { return managedDirs }

// lockFileFor mirrors host.Paths.LockFile without requiring the caller to
// build a Paths value.
func lockFileFor(root string) string {
	return host.Paths{Root: root}.LockFile()
}
