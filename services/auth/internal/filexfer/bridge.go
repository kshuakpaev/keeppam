package filexfer

import (
	"context"
	"io"
	"strings"
	"sync"

	"github.com/google/uuid"
)

func (s *Service) CaptureSCP(ctx context.Context, sessionID uuid.UUID, capture bool, direction string, r io.Reader) error {
	return ParseSCPStream(r, func(name, rel string, body io.Reader, size int64) error {
		return s.SaveReader(ctx, SaveMeta{
			SessionID:  sessionID,
			Filename:   name,
			RemotePath: rel,
			Protocol:   "scp",
			Direction:  direction,
			Capture:    capture,
		}, body, size)
	})
}

func (s *Service) CopySFTP(ctx context.Context, sessionID uuid.UUID, capture bool, client, remote io.ReadWriter) error {
	cap := newSFTPCap(func(name, pth string, body io.Reader, size int64, upload bool) error {
		dir := "download"
		if upload {
			dir = "upload"
		}
		return s.SaveReader(ctx, SaveMeta{
			SessionID:  sessionID,
			Filename:   name,
			RemotePath: pth,
			Protocol:   "sftp",
			Direction:  dir,
			Capture:    capture,
		}, body, size)
	})
	return copySFTP(client, remote, cap)
}

func RemoteSCPCommand(sink bool, remotePath string) string {
	flag := "-f"
	if sink {
		flag = "-t"
	}
	if remotePath == "" {
		remotePath = "."
	}
	return "scp " + flag + " -- " + shellQuote(remotePath)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func CopySCP(client io.ReadWriteCloser, remoteIn io.WriteCloser, remoteOut io.Reader, parseClient, parseRemote io.Writer) error {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		src := io.Reader(client)
		if parseClient != nil {
			src = io.TeeReader(client, parseClient)
		}
		_, _ = io.Copy(remoteIn, src)
		_ = remoteIn.Close()
	}()
	go func() {
		defer wg.Done()
		src := io.Reader(remoteOut)
		if parseRemote != nil {
			src = io.TeeReader(remoteOut, parseRemote)
		}
		_, _ = io.Copy(client, src)
	}()
	wg.Wait()
	return nil
}
