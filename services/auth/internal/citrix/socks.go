package citrix

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// SOCKS5 (RFC 1928) + username/password (RFC 1929).

const (
	socksVer5       = 0x05
	socksAuthNone   = 0x00
	socksAuthUser   = 0x02
	socksAuthNoAcc  = 0xFF
	socksCmdConnect = 0x01
	socksATYPIPv4   = 0x01
	socksATYPDomain = 0x03
	socksATYPIPv6   = 0x04
	socksRepOK      = 0x00
)

// AuthFunc validates proxy username/password; returns ok.
type AuthFunc func(user, pass string) bool

// AllowFunc returns whether CONNECT to host:port is permitted for this auth.
type AllowFunc func(user, host string, port int) bool

// CloseFunc is called after the relay ends (bytes are best-effort counts).
type CloseFunc func(user, host string, port int, bytesUp, bytesDown int64)

// ServeSOCKS handles one client connection (already Accepted).
func ServeSOCKS(client net.Conn, auth AuthFunc, allow AllowFunc, onConnect func(user, host string, port int), onClose CloseFunc) error {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(60 * time.Second))

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return err
	}
	if hdr[0] != socksVer5 {
		return fmt.Errorf("not socks5")
	}
	nmethods := int(hdr[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return err
	}
	wantUser := false
	for _, m := range methods {
		if m == socksAuthUser {
			wantUser = true
			break
		}
	}
	if !wantUser {
		_, _ = client.Write([]byte{socksVer5, socksAuthNoAcc})
		return fmt.Errorf("username/password auth required")
	}
	if _, err := client.Write([]byte{socksVer5, socksAuthUser}); err != nil {
		return err
	}

	// RFC 1929
	ah := make([]byte, 2)
	if _, err := io.ReadFull(client, ah); err != nil {
		return err
	}
	if ah[0] != 0x01 {
		return fmt.Errorf("bad auth ver")
	}
	ulen := int(ah[1])
	ubuf := make([]byte, ulen)
	if _, err := io.ReadFull(client, ubuf); err != nil {
		return err
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(client, plenBuf); err != nil {
		return err
	}
	pbuf := make([]byte, int(plenBuf[0]))
	if _, err := io.ReadFull(client, pbuf); err != nil {
		return err
	}
	user, pass := string(ubuf), string(pbuf)
	if auth == nil || !auth(user, pass) {
		_, _ = client.Write([]byte{0x01, 0x01})
		return fmt.Errorf("auth failed")
	}
	if _, err := client.Write([]byte{0x01, 0x00}); err != nil {
		return err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return err
	}
	if req[0] != socksVer5 || req[1] != socksCmdConnect {
		_ = socksFail(client, 0x07)
		return fmt.Errorf("only CONNECT supported")
	}
	host, port, err := readAddr(client, req[3])
	if err != nil {
		_ = socksFail(client, 0x01)
		return err
	}
	if allow != nil && !allow(user, host, port) {
		_ = socksFail(client, 0x02)
		return fmt.Errorf("destination not allowed")
	}

	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconvPort(port)), 15*time.Second)
	if err != nil {
		_ = socksFail(client, 0x05)
		return err
	}
	defer up.Close()

	// success reply bind 0.0.0.0:0
	reply := []byte{socksVer5, socksRepOK, 0x00, socksATYPIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := client.Write(reply); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	if onConnect != nil {
		onConnect(user, host, port)
	}

	var bytesUp, bytesDown atomic.Int64
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(up, client)
		bytesUp.Store(n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(client, up)
		bytesDown.Store(n)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = up.Close()
	<-done
	if onClose != nil {
		onClose(user, host, port, bytesUp.Load(), bytesDown.Load())
	}
	return nil
}

func readAddr(r io.Reader, atyp byte) (host string, port int, err error) {
	switch atyp {
	case socksATYPIPv4:
		b := make([]byte, 4)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case socksATYPDomain:
		lb := make([]byte, 1)
		if _, err = io.ReadFull(r, lb); err != nil {
			return
		}
		b := make([]byte, int(lb[0]))
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = string(b)
	case socksATYPIPv6:
		b := make([]byte, 16)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		err = fmt.Errorf("bad atyp")
		return
	}
	pb := make([]byte, 2)
	if _, err = io.ReadFull(r, pb); err != nil {
		return
	}
	port = int(binary.BigEndian.Uint16(pb))
	return
}

func socksFail(c net.Conn, code byte) error {
	_, err := c.Write([]byte{socksVer5, code, 0x00, socksATYPIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func strconvPort(p int) string {
	return fmt.Sprintf("%d", p)
}
