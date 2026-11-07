// SPDX-License-Identifier: EUPL-1.2

//go:build windows

package main

import (
	"os"
	"syscall"
)

const stillActive = 259 // STILL_ACTIVE

// pidAlive asks for the process's exit code: an exited process can still be opened while another process holds a
// handle to it, so opening it says nothing.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}

// harden: Windows keeps no core dump by default; file access there is the directory's ACL (install.md: a directory
// only the custodian's account may read).
func harden() {}

// keyPerms cannot read NTFS ACLs with the standard library: the install guide names the ACL to set
// (review 2026-11-07 exposure-2).
func keyPerms(path string) error {
	_, err := os.Stat(path)
	return err
}
