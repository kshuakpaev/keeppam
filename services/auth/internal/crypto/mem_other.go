//go:build !linux

package crypto

func Harden() MemStatus {
	st := LastMemStatus()
	st.Wipe = true
	st.CoreDump = "unsupported"
	st.Dumpable = true
	storeMem(st)
	return st
}

func Lock(b []byte) error {
	return nil
}

func Unlock(b []byte) {}
