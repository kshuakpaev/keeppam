package filexfer

import (
	"bytes"
	"encoding/binary"
	"io"
	"path"
	"sync"
)

const (
	fxpInit    = 1
	fxpVersion = 2
	fxpOpen    = 3
	fxpClose   = 4
	fxpRead    = 5
	fxpWrite   = 6
	fxpHandle  = 102
	fxpData    = 103
	fxpStatus  = 101

	fxfWrite = 0x00000002
)

type sftpCap struct {
	mu       sync.Mutex
	opens    map[uint32]openReq // reqID → open
	handles  map[string]*xfer   // handle → file
	reads    map[uint32]string  // reqID → handle
	onFile   func(name, path string, body io.Reader, size int64, upload bool) error
	capture  bool
	pendingW map[string]*bytes.Buffer
}

type openReq struct {
	path  string
	write bool
}

type xfer struct {
	path  string
	write bool
	buf   *bytes.Buffer
}

func newSFTPCap(onFile func(name, path string, body io.Reader, size int64, upload bool) error) *sftpCap {
	return &sftpCap{
		opens:    map[uint32]openReq{},
		handles:  map[string]*xfer{},
		reads:    map[uint32]string{},
		onFile:   onFile,
		pendingW: map[string]*bytes.Buffer{},
	}
}

func (c *sftpCap) clientPacket(p []byte) {
	if len(p) < 1 {
		return
	}
	typ := p[0]
	if typ == fxpInit || typ == fxpVersion {
		return
	}
	if len(p) < 5 {
		return
	}
	id := binary.BigEndian.Uint32(p[1:5])
	rest := p[5:]
	c.mu.Lock()
	defer c.mu.Unlock()
	switch typ {
	case fxpOpen:
		path, rest2, ok := sshString(rest)
		if !ok || len(rest2) < 4 {
			return
		}
		flags := binary.BigEndian.Uint32(rest2[:4])
		c.opens[id] = openReq{path: path, write: flags&fxfWrite != 0}
	case fxpWrite:
		h, rest2, ok := sshString(rest)
		if !ok || len(rest2) < 8 {
			return
		}
		data, _, ok := sshString(rest2[8:])
		if !ok {
			return
		}
		x := c.handles[h]
		if x == nil || !x.write {
			return
		}
		_, _ = x.buf.Write([]byte(data))
	case fxpRead:
		h, _, ok := sshString(rest)
		if !ok {
			return
		}
		c.reads[id] = h
	case fxpClose:
		h, _, ok := sshString(rest)
		if !ok {
			return
		}
		x := c.handles[h]
		delete(c.handles, h)
		if x == nil || c.onFile == nil {
			return
		}
		if x.write {
			b := x.buf.Bytes()
			_ = c.onFile(path.Base(x.path), x.path, bytes.NewReader(b), int64(len(b)), true)
		}
	}
}

func (c *sftpCap) serverPacket(p []byte) {
	if len(p) < 5 {
		return
	}
	typ := p[0]
	id := binary.BigEndian.Uint32(p[1:5])
	rest := p[5:]
	c.mu.Lock()
	defer c.mu.Unlock()
	switch typ {
	case fxpHandle:
		h, _, ok := sshString(rest)
		if !ok {
			return
		}
		op, ok := c.opens[id]
		delete(c.opens, id)
		if !ok {
			return
		}
		c.handles[h] = &xfer{path: op.path, write: op.write, buf: &bytes.Buffer{}}
	case fxpData:
		h := c.reads[id]
		delete(c.reads, id)
		data, _, ok := sshString(rest)
		if !ok {
			return
		}
		x := c.handles[h]
		if x == nil || x.write {
			return
		}
		_, _ = x.buf.Write([]byte(data))
	case fxpStatus:
		// CLOSE status: if download still buffered, flush on close already handled
	}
}

func (c *sftpCap) flushDownloads() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for h, x := range c.handles {
		if x.write || c.onFile == nil {
			continue
		}
		b := x.buf.Bytes()
		if len(b) == 0 {
			continue
		}
		_ = c.onFile(path.Base(x.path), x.path, bytes.NewReader(b), int64(len(b)), false)
		delete(c.handles, h)
	}
}

func sshString(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", b, false
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if n < 0 || len(b) < 4+n {
		return "", b, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}

type pktSniff struct {
	w   io.Writer
	fn  func([]byte)
	buf []byte
}

func (p *pktSniff) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.buf = append(p.buf, b[:n]...)
	for len(p.buf) >= 4 {
		ln := int(binary.BigEndian.Uint32(p.buf[:4]))
		if ln < 1 || ln > 8<<20 {
			p.buf = p.buf[:0]
			break
		}
		if len(p.buf) < 4+ln {
			break
		}
		pkt := p.buf[4 : 4+ln]
		p.fn(append([]byte(nil), pkt...))
		p.buf = p.buf[4+ln:]
	}
	return n, err
}

func copySFTP(client io.ReadWriter, remote io.ReadWriter, cap *sftpCap) error {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(&pktSniff{w: remote, fn: cap.clientPacket}, client)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(&pktSniff{w: client, fn: cap.serverPacket}, remote)
		errCh <- err
	}()
	err := <-errCh
	cap.flushDownloads()
	return err
}

func sftpStatusMessage(msg string) []byte {
	// SSH_FXP_STATUS id=0 code=4 (Failure) message
	m := []byte(msg)
	lang := []byte("en")
	payload := make([]byte, 0, 9+4+len(m)+4+len(lang))
	payload = append(payload, fxpStatus)
	payload = binary.BigEndian.AppendUint32(payload, 0)
	payload = binary.BigEndian.AppendUint32(payload, 4)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(m)))
	payload = append(payload, m...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(lang)))
	payload = append(payload, lang...)
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

func sftpVersionReply() []byte {
	payload := []byte{fxpVersion, 0, 0, 0, 3}
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out
}
