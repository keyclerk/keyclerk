// SPDX-License-Identifier: EUPL-1.2

//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

func pidAlive(pid int) bool {
	return pid > 0 && syscall.Kill(pid, 0) == nil
}

// harden keeps the key out of core dumps and makes every file and socket this process creates its user's only
// (review 2026-11-07 exposure-5, exposure-6).
func harden() {
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	syscall.Umask(0o077)
}

// keyPerms refuses a key file any other user can read or write, as ssh refuses a private key (exposure-2).
func keyPerms(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("the key file %s is open to other users (mode %o): make it the custodian's user's only "+
			"(chmod 600)", path, fi.Mode().Perm())
	}
	return nil
}
