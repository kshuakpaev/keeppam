package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/store"
)

const (
	dialTimeout  = 800 * time.Millisecond
	scanWorkers  = 64
	pollInterval = 2 * time.Second
)

// Run polls pending discovery jobs and executes TCP port scans.
func (s *Service) Run(ctx context.Context) {
	for {
		job, err := s.claimPending(ctx)
		if err != nil {
			slog.Warn("discovery claim", "err", err)
		} else if job != nil {
			slog.Info("discovery job start", "job", job.ID, "kind", job.Kind, "cidr", job.CIDR)
			var runErr error
			if job.Kind == "accounts" {
				runErr = s.runAccountsJob(ctx, *job)
			} else if job.Kind == "ad_accounts" {
				runErr = s.runADAccountsJob(ctx, *job)
			} else if job.Kind == "winrm_accounts" {
				runErr = s.runWinRMAccountsJob(ctx, *job)
			} else {
				runErr = s.runJob(ctx, *job)
			}
			if runErr != nil {
				slog.Warn("discovery job failed", "job", job.ID, "err", runErr)
				_, _ = s.db.Pool.Exec(ctx, `
					UPDATE discovery_jobs SET status='failed', error=$2, finished_at=NOW() WHERE id=$1`,
					job.ID, truncateErr(runErr.Error()))
			} else {
				slog.Info("discovery job done", "job", job.ID)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

func (s *Service) claimPending(ctx context.Context) (*Job, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var j Job
	err = tx.QueryRow(ctx, `
		SELECT id, kind, cidr, ports, status, total_hosts, scanned_hosts, open_ports, error,
			created_at, started_at, finished_at, created_by
		FROM discovery_jobs
		WHERE status='pending'
		ORDER BY created_at ASC
		LIMIT 1
		FOR UPDATE SKIP LOCKED`).Scan(
		&j.ID, &j.Kind, &j.CIDR, &j.Ports, &j.Status, &j.TotalHosts, &j.ScannedHosts, &j.OpenPorts, &j.Error,
		&j.CreatedAt, &j.StartedAt, &j.FinishedAt, &j.CreatedBy)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	_, err = tx.Exec(ctx, `
		UPDATE discovery_jobs SET status='running', started_at=NOW(), scanned_hosts=0, open_ports=0, error='' WHERE id=$1`, j.ID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	j.Status = "running"
	return &j, nil
}

func (s *Service) runJob(ctx context.Context, job Job) error {
	hosts, err := expandCIDR(job.CIDR)
	if err != nil {
		return err
	}
	ports := normalizePorts(job.Ports)
	if len(ports) == 0 {
		return fmt.Errorf("no ports")
	}
	_, _ = s.db.Pool.Exec(ctx, `UPDATE discovery_jobs SET total_hosts=$2 WHERE id=$1`, job.ID, len(hosts))

	type workItem struct {
		addr string
		port int
	}
	jobs := make(chan workItem, scanWorkers*2)
	var wg sync.WaitGroup
	var hostsDone atomic.Int64
	var openCount atomic.Int64

	// Per-host completion tracking
	hostPortsLeft := make([]atomic.Int32, len(hosts))
	hostIndex := map[string]int{}
	for i, h := range hosts {
		hostIndex[h] = i
		hostPortsLeft[i].Store(int32(len(ports)))
	}

	worker := func() {
		defer wg.Done()
		for item := range jobs {
			if ctx.Err() != nil {
				return
			}
			if probeTCP(item.addr, item.port) {
				openCount.Add(1)
				proto := protocolForPort(item.port)
				_, _ = s.db.Pool.Exec(context.Background(), `
					INSERT INTO discovery_candidates (id, job_id, address, port, protocol, created_at)
					VALUES ($1,$2,$3,$4,$5,NOW())
					ON CONFLICT (job_id, address, port) DO NOTHING`,
					store.NewID(), job.ID, item.addr, item.port, proto)
			}
			idx := hostIndex[item.addr]
			if hostPortsLeft[idx].Add(-1) == 0 {
				done := hostsDone.Add(1)
				_, _ = s.db.Pool.Exec(context.Background(), `
					UPDATE discovery_jobs SET scanned_hosts=$2, open_ports=$3 WHERE id=$1`,
					job.ID, int(done), int(openCount.Load()))
			}
		}
	}

	nWorkers := scanWorkers
	totalWork := len(hosts) * len(ports)
	if nWorkers > totalWork && totalWork > 0 {
		nWorkers = totalWork
	}
	wg.Add(nWorkers)
	for i := 0; i < nWorkers; i++ {
		go worker()
	}
	for _, h := range hosts {
		for _, p := range ports {
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return ctx.Err()
			case jobs <- workItem{addr: h, port: p}:
			}
		}
	}
	close(jobs)
	wg.Wait()

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE discovery_jobs SET status='done', scanned_hosts=$2, open_ports=$3, finished_at=NOW(), error='' WHERE id=$1`,
		job.ID, len(hosts), int(openCount.Load()))
	return err
}

func probeTCP(addr string, port int) bool {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(addr, fmt.Sprintf("%d", port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func truncateErr(s string) string {
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}
