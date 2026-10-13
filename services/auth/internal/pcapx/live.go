package pcapx

import (
	"io"
	"sync"
	"time"
)

// LiveWriter appends bidirectional TCP packets to a pcap (Ethernet + IPv4).
type LiveWriter struct {
	mu      sync.Mutex
	w       io.Writer
	seqC    uint32
	seqS    uint32
	srcPort uint16
	dstPort uint16
	origin  time.Time
}

// NewLiveWriter writes a pcap global header. Concurrent WriteClient/WriteServer are safe.
func NewLiveWriter(w io.Writer, srcPort, dstPort uint16) (*LiveWriter, error) {
	if srcPort == 0 {
		srcPort = 4822
	}
	if dstPort == 0 {
		dstPort = 3389
	}
	if err := writeGlobal(w); err != nil {
		return nil, err
	}
	return &LiveWriter{w: w, seqC: 1, seqS: 1, srcPort: srcPort, dstPort: dstPort, origin: time.Now()}, nil
}

func (l *LiveWriter) WriteClient(p []byte) error { return l.write(p, true) }
func (l *LiveWriter) WriteServer(p []byte) error { return l.write(p, false) }

// Client is an io.Writer toward the target (ICA/CGP uplink).
func (l *LiveWriter) Client() io.Writer { return dirWriter{l: l, c2s: true} }

// Server is an io.Writer toward the client (downlink).
func (l *LiveWriter) Server() io.Writer { return dirWriter{l: l, c2s: false} }

func (l *LiveWriter) write(p []byte, c2s bool) error {
	if l == nil || len(p) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := uint32(time.Since(l.origin).Seconds())
	for off := 0; off < len(p); off += maxPayload {
		end := off + maxPayload
		if end > len(p) {
			end = len(p)
		}
		chunk := p[off:end]
		seq := l.seqS
		if c2s {
			seq = l.seqC
		}
		if err := writePacket(l.w, ts, dummyFrameEx(chunk, seq, false, c2s, l.srcPort, l.dstPort)); err != nil {
			return err
		}
		if c2s {
			l.seqC += uint32(len(chunk))
		} else {
			l.seqS += uint32(len(chunk))
		}
	}
	return nil
}

type dirWriter struct {
	l   *LiveWriter
	c2s bool
}

func (d dirWriter) Write(p []byte) (int, error) {
	if d.l == nil {
		return len(p), nil
	}
	var err error
	if d.c2s {
		err = d.l.WriteClient(p)
	} else {
		err = d.l.WriteServer(p)
	}
	// Never fail the session relay because pcap I/O failed.
	_ = err
	return len(p), nil
}
