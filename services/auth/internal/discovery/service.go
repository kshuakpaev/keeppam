package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/store"
)

const maxHosts = 1024

type Job struct {
	ID           uuid.UUID  `json:"id"`
	Kind         string     `json:"kind"` // network | accounts
	CIDR         string     `json:"cidr"`
	Ports        string     `json:"ports"`
	Status       string     `json:"status"`
	TotalHosts   int        `json:"total_hosts"`
	ScannedHosts int        `json:"scanned_hosts"`
	OpenPorts    int        `json:"open_ports"`
	Error        string     `json:"error,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
}

type Candidate struct {
	ID                 uuid.UUID       `json:"id"`
	JobID              uuid.UUID       `json:"job_id"`
	Address            string          `json:"address"`
	Port               int             `json:"port"`
	Protocol           string          `json:"protocol"`
	Username           string          `json:"username,omitempty"`
	SourceAssetID      *uuid.UUID      `json:"source_asset_id,omitempty"`
	ImportedAssetID    *uuid.UUID      `json:"imported_asset_id,omitempty"`
	ImportedAccountID  *uuid.UUID      `json:"imported_account_id,omitempty"`
	Details            json.RawMessage `json:"details,omitempty"`
	Privileged         bool            `json:"privileged"`
	CreatedAt          time.Time       `json:"created_at"`
	AlreadyKnown       bool            `json:"already_known"`
}

type CreateJobInput struct {
	Kind     string   `json:"kind"` // network (default) | accounts
	CIDR     string   `json:"cidr"`
	Ports    string   `json:"ports"`
	AssetIDs []string `json:"asset_ids"` // optional filter for accounts kind
}

type ImportResult struct {
	Kind    string          `json:"kind"` // asset | account
	Asset   *assets.Asset   `json:"asset,omitempty"`
	Account *assets.Account `json:"account,omitempty"`
}

type Service struct {
	db     *store.DB
	aud    *audit.Service
	assets *assets.Service
}

func New(db *store.DB, aud *audit.Service, assetsSvc *assets.Service) *Service {
	return &Service{db: db, aud: aud, assets: assetsSvc}
}

func (s *Service) CreateJob(ctx context.Context, actorID uuid.UUID, in CreateJobInput, ip, ua string) (Job, error) {
	kind := strings.TrimSpace(in.Kind)
	if kind == "" {
		kind = "network"
	}
	switch kind {
	case "network":
		return s.createNetworkJob(ctx, actorID, in, ip, ua)
	case "accounts":
		return s.createAccountsJob(ctx, actorID, in, ip, ua)
	default:
		return Job{}, fmt.Errorf("invalid kind (network|accounts)")
	}
}

func (s *Service) createNetworkJob(ctx context.Context, actorID uuid.UUID, in CreateJobInput, ip, ua string) (Job, error) {
	cidr := strings.TrimSpace(in.CIDR)
	if cidr == "" {
		return Job{}, fmt.Errorf("cidr required")
	}
	hosts, err := expandCIDR(cidr)
	if err != nil {
		return Job{}, err
	}
	if len(hosts) == 0 {
		return Job{}, fmt.Errorf("no hosts in range")
	}
	if len(hosts) > maxHosts {
		return Job{}, fmt.Errorf("range too large (%d hosts, max %d)", len(hosts), maxHosts)
	}
	ports := normalizePorts(in.Ports)
	if len(ports) == 0 {
		return Job{}, fmt.Errorf("no ports to scan")
	}
	id := store.NewID()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO discovery_jobs (id, kind, cidr, ports, status, total_hosts, created_at, created_by)
		VALUES ($1,'network',$2,$3,'pending',$4,NOW(),$5)`,
		id, cidr, joinPorts(ports), len(hosts), actorID)
	if err != nil {
		return Job{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "discovery.job.created", "discovery_job", id.String(), ip, ua, map[string]any{
		"kind": "network", "cidr": cidr, "ports": ports, "total_hosts": len(hosts),
	})
	return s.GetJob(ctx, id)
}

func (s *Service) ListJobs(ctx context.Context, limit int) ([]Job, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, kind, cidr, ports, status, total_hosts, scanned_hosts, open_ports, error,
			created_at, started_at, finished_at, created_by
		FROM discovery_jobs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Service) GetJob(ctx context.Context, id uuid.UUID) (Job, error) {
	row := s.db.Pool.QueryRow(ctx, `
		SELECT id, kind, cidr, ports, status, total_hosts, scanned_hosts, open_ports, error,
			created_at, started_at, finished_at, created_by
		FROM discovery_jobs WHERE id=$1`, id)
	return scanJob(row)
}

func (s *Service) ListCandidates(ctx context.Context, jobID uuid.UUID) ([]Candidate, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT c.id, c.job_id, c.address, c.port, c.protocol, COALESCE(c.username,''), c.source_asset_id,
			c.imported_asset_id, c.imported_account_id, c.details, COALESCE(c.privileged,false), c.created_at,
			CASE
				WHEN COALESCE(c.username,'') <> '' AND c.source_asset_id IS NOT NULL THEN EXISTS(
					SELECT 1 FROM asset_accounts a
					WHERE a.asset_id = c.source_asset_id AND a.username = c.username
				)
				ELSE EXISTS(
					SELECT 1 FROM assets a
					WHERE a.address = c.address AND a.port = c.port AND a.protocol = c.protocol
				)
			END
		FROM discovery_candidates c
		WHERE c.job_id=$1
		ORDER BY c.privileged DESC, c.address, c.username, c.port`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Candidate
	for rows.Next() {
		var c Candidate
		if err := rows.Scan(&c.ID, &c.JobID, &c.Address, &c.Port, &c.Protocol, &c.Username, &c.SourceAssetID,
			&c.ImportedAssetID, &c.ImportedAccountID, &c.Details, &c.Privileged, &c.CreatedAt, &c.AlreadyKnown); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) ImportCandidate(ctx context.Context, actorID, candidateID uuid.UUID, ip, ua string) (ImportResult, error) {
	var c Candidate
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, job_id, address, port, protocol, COALESCE(username,''), source_asset_id,
			imported_asset_id, imported_account_id, details, COALESCE(privileged,false), created_at
		FROM discovery_candidates WHERE id=$1`, candidateID).Scan(
		&c.ID, &c.JobID, &c.Address, &c.Port, &c.Protocol, &c.Username, &c.SourceAssetID,
		&c.ImportedAssetID, &c.ImportedAccountID, &c.Details, &c.Privileged, &c.CreatedAt)
	if err != nil {
		return ImportResult{}, err
	}
	if c.Username != "" {
		return s.importAccountCandidate(ctx, actorID, c, ip, ua)
	}
	return s.importHostCandidate(ctx, actorID, c, ip, ua)
}

func (s *Service) importHostCandidate(ctx context.Context, actorID uuid.UUID, c Candidate, ip, ua string) (ImportResult, error) {
	if c.ImportedAssetID != nil {
		a, err := s.assets.Get(ctx, *c.ImportedAssetID)
		if err != nil {
			return ImportResult{}, err
		}
		return ImportResult{Kind: "asset", Asset: &a}, nil
	}

	name := fmt.Sprintf("%s-%s-%d", c.Address, c.Protocol, c.Port)
	name = strings.ReplaceAll(name, ":", "-")
	asset, err := s.assets.Create(ctx, actorID, assets.CreateAssetInput{
		Name:      name,
		AssetType: "host",
		Hostname:  c.Address,
		Address:   c.Address,
		Port:      c.Port,
		Protocol:  c.Protocol,
		Description: fmt.Sprintf("Imported from discovery job %s", c.JobID.String()[:8]),
		Tags:      []string{"discovered"},
	}, ip, ua)
	if err != nil {
		name2 := fmt.Sprintf("%s-%s", name, store.NewID().String()[:8])
		asset, err = s.assets.Create(ctx, actorID, assets.CreateAssetInput{
			Name: name2, AssetType: "host", Hostname: c.Address, Address: c.Address,
			Port: c.Port, Protocol: c.Protocol,
			Description: fmt.Sprintf("Imported from discovery job %s", c.JobID.String()[:8]),
			Tags:        []string{"discovered"},
		}, ip, ua)
		if err != nil {
			return ImportResult{}, err
		}
	}
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE discovery_candidates SET imported_asset_id=$2 WHERE id=$1`, c.ID, asset.ID)
	_ = s.aud.Record(ctx, &actorID, "discovery.candidate.imported", "asset", asset.ID.String(), ip, ua, map[string]any{
		"candidate_id": c.ID.String(), "address": c.Address, "port": c.Port, "protocol": c.Protocol,
	})
	return ImportResult{Kind: "asset", Asset: &asset}, nil
}

func scanJob(row interface{ Scan(dest ...any) error }) (Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.Kind, &j.CIDR, &j.Ports, &j.Status, &j.TotalHosts, &j.ScannedHosts, &j.OpenPorts, &j.Error,
		&j.CreatedAt, &j.StartedAt, &j.FinishedAt, &j.CreatedBy)
	if j.Kind == "" {
		j.Kind = "network"
	}
	return j, err
}

func IsNotFound(err error) bool { return err == pgx.ErrNoRows }

func normalizePorts(s string) []int {
	if strings.TrimSpace(s) == "" {
		s = "22,3389,5900"
	}
	seen := map[int]struct{}{}
	var out []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

func protocolForPort(port int) string {
	switch port {
	case 22:
		return "ssh"
	case 3389:
		return "rdp"
	case 5900, 5901, 5902:
		return "vnc"
	case 5432:
		return "postgres"
	case 3306:
		return "mysql"
	case 443:
		return "https"
	default:
		return "ssh"
	}
}

func expandCIDR(cidr string) ([]string, error) {
	cidr = strings.TrimSpace(cidr)
	// Single IP
	if ip := net.ParseIP(cidr); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []string{v4.String()}, nil
		}
		return nil, fmt.Errorf("only IPv4 supported")
	}
	// Range a.b.c.d-e
	if strings.Count(cidr, "-") == 1 && !strings.Contains(cidr, "/") {
		parts := strings.SplitN(cidr, "-", 2)
		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))
		if start == nil || end == nil || start.To4() == nil || end.To4() == nil {
			// allow 192.168.1.1-50 short form
			start = net.ParseIP(strings.TrimSpace(parts[0]))
			if start == nil || start.To4() == nil {
				return nil, fmt.Errorf("invalid range")
			}
			lastOctet, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || lastOctet < 0 || lastOctet > 255 {
				return nil, fmt.Errorf("invalid range end")
			}
			base := start.To4()
			endIP := net.IPv4(base[0], base[1], base[2], byte(lastOctet))
			return expandIPRange(start.To4(), endIP.To4())
		}
		return expandIPRange(start.To4(), end.To4())
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr: %w", err)
	}
	if ipnet.IP.To4() == nil {
		return nil, fmt.Errorf("only IPv4 supported")
	}
	var hosts []string
	for ip := ipnet.IP.Mask(ipnet.Mask).To4(); ipnet.Contains(ip); incIP(ip) {
		// skip network / broadcast for typical masks
		hosts = append(hosts, ip.String())
		if len(hosts) > maxHosts {
			return nil, fmt.Errorf("range too large (max %d hosts)", maxHosts)
		}
	}
	// drop network and broadcast if /24-style and >2 hosts
	if len(hosts) > 2 {
		ones, bits := ipnet.Mask.Size()
		if bits == 32 && ones < 31 {
			hosts = hosts[1 : len(hosts)-1]
		}
	}
	return hosts, nil
}

func expandIPRange(start, end net.IP) ([]string, error) {
	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid range")
	}
	s := ipToUint(start)
	e := ipToUint(end)
	if e < s {
		return nil, fmt.Errorf("range end before start")
	}
	if e-s+1 > uint32(maxHosts) {
		return nil, fmt.Errorf("range too large (max %d hosts)", maxHosts)
	}
	var hosts []string
	for n := s; n <= e; n++ {
		hosts = append(hosts, uintToIP(n).String())
	}
	return hosts, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

func ipToUint(ip net.IP) uint32 {
	v := ip.To4()
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func uintToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
