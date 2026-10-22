//go:build !unix

package secfile

import (
	"fmt"
	"os"
)

// openNoFollow has no O_NOFOLLOW here: Lstat first, then open. This leaves a
// check-to-use window that unix builds do not have.
func openNoFollow(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink; refused", path)
	}
	return os.Open(path)
}

func ownerUID(os.FileInfo) (int, bool) { return 0, false }
