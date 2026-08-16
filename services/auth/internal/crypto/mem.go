package crypto

import (
	"runtime"
	"sync/atomic"
	"unsafe"
)

type MemStatus struct {
	Wipe         bool   `json:"wipe"`
	CoreDump     string `json:"coredump"` // disabled | allowed | unsupported
	Dumpable     bool   `json:"dumpable"`
	DataKeyMlock bool   `json:"data_key_mlock"`
	MlockError   string `json:"mlock_error,omitempty"`
}

var memStatus atomic.Pointer[MemStatus]

func init() {
	memStatus.Store(&MemStatus{Wipe: true, CoreDump: "unknown", Dumpable: true})
}

func LastMemStatus() MemStatus {
	p := memStatus.Load()
	if p == nil {
		return MemStatus{Wipe: true}
	}
	return *p
}

func storeMem(st MemStatus) {
	st.Wipe = true
	cp := st
	memStatus.Store(&cp)
}

func setKeyMlock(ok bool, err error) {
	st := LastMemStatus()
	st.DataKeyMlock = ok
	st.MlockError = ""
	if err != nil {
		st.MlockError = err.Error()
	}
	storeMem(st)
}

// Wipe overwrites b in place (best-effort; copies may remain until GC).
func Wipe(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	runtime.KeepAlive(b)
}

// WipeString best-effort zeroizes a unique string backing (from string([]byte)).
func WipeString(s *string) {
	if s == nil || *s == "" {
		return
	}
	n := len(*s)
	p := unsafe.StringData(*s)
	b := unsafe.Slice(p, n)
	clear(b)
	runtime.KeepAlive(b)
	*s = ""
}
