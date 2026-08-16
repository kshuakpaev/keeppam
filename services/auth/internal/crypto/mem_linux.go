//go:build linux

package crypto

import (
	"os"
	"syscall"
)

const prSetDumpable = 4

func Harden() MemStatus {
	st := LastMemStatus()
	st.Wipe = true
	if os.Getenv("KEEPPAM_ALLOW_COREDUMP") == "true" || os.Getenv("KEEPPAM_ALLOW_COREDUMP") == "1" {
		st.CoreDump = "allowed"
		st.Dumpable = true
		storeMem(st)
		return st
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	st.CoreDump = "disabled"
	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
	if errno != 0 {
		st.Dumpable = true
	} else {
		st.Dumpable = false
	}
	storeMem(st)
	return LastMemStatus()
}

func Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return syscall.Mlock(b)
}

func Unlock(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = syscall.Munlock(b)
}
