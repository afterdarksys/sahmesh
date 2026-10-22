// Package secfile opens and checks the small private files sahconnect trusts
// (the config file and the token file) without following symlinks.
//
// Threats: another local user swapping a symlink or a file of their own into
// a path sahconnect reads, writes, or deletes. Files are opened with
// O_NOFOLLOW and checked by fstat on the open descriptor, so a swap between
// check and use is caught. Ownership is the current uid (root is allowed only
// where the caller says so). Does NOT defend against the user's own account
// or root, and on non-unix systems ownership checks are not available and
// only the mode and symlink checks apply.
package secfile

import (
	"fmt"
	"os"
)

// CurrentUID is the uid files must belong to. Tests replace it to simulate a
// file owned by another user.
var CurrentUID = os.Getuid

// OwnedBy reports whether fi belongs to CurrentUID (or to root when
// allowRoot). Where ownership is unknown (non-unix) it reports true.
func OwnedBy(fi os.FileInfo, allowRoot bool) bool {
	uid, ok := ownerUID(fi)
	if !ok {
		return true
	}
	return uid == CurrentUID() || (allowRoot && uid == 0)
}

// OpenNoFollow opens path read-only, refusing a symlink at the final
// component, and returns the file with its fstat. The file must be a regular
// file owned per OwnedBy.
func OpenNoFollow(path string, allowRoot bool) (*os.File, os.FileInfo, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s is not a regular file", path)
	}
	if !OwnedBy(fi, allowRoot) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s is owned by another user", path)
	}
	return f, fi, nil
}

// CheckDir requires dir to be a real directory (not a symlink), owned per
// OwnedBy, and not group- or world-writable.
func CheckDir(dir string, allowRoot bool) (os.FileInfo, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (symlinks are refused)", dir)
	}
	if !OwnedBy(fi, allowRoot) {
		return nil, fmt.Errorf("directory %s is owned by another user", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("directory %s is group- or world-writable", dir)
	}
	return fi, nil
}
