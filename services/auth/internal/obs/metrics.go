package obs

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var Default = NewRegistry()

var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type Registry struct {
	mu sync.Mutex

	httpCount map[string]uint64 // route|code
	httpHist  map[string]*hist  // route
	authHist  map[string]*hist  // method
	authRing  *sampleRing
	sessHist  *hist
	sessRing  *sampleRing
	auditN    uint64
	active    int64
	auditLag  float64
	hasLag    bool
}

func NewRegistry() *Registry {
	return &Registry{
		httpCount: map[string]uint64{},
		httpHist:  map[string]*hist{},
		authHist:  map[string]*hist{},
		authRing:  newRing(1024),
		sessHist:  newHist(),
		sessRing:  newRing(1024),
	}
}

func (r *Registry) ObserveHTTP(route string, code int, d time.Duration) {
	if route == "" {
		route = "unknown"
	}
	sec := d.Seconds()
	key := route + "|" + strconv.Itoa(code)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.httpCount[key]++
	h := r.httpHist[route]
	if h == nil {
		h = newHist()
		r.httpHist[route] = h
	}
	h.observe(sec)
}

func (r *Registry) ObserveAuth(method string, d time.Duration) {
	if method == "" {
		method = "unknown"
	}
	sec := d.Seconds()
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.authHist[method]
	if h == nil {
		h = newHist()
		r.authHist[method] = h
	}
	h.observe(sec)
	r.authRing.add(sec)
}

func (r *Registry) ObserveSessionSetup(d time.Duration) {
	if d < 0 {
		d = 0
	}
	sec := d.Seconds()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessHist.observe(sec)
	r.sessRing.add(sec)
}

func (r *Registry) IncAudit() {
	r.mu.Lock()
	r.auditN++
	r.mu.Unlock()
}

func (r *Registry) SetActiveSessions(n int64) {
	r.mu.Lock()
	r.active = n
	r.mu.Unlock()
}

func (r *Registry) SetAuditLag(seconds float64, ok bool) {
	r.mu.Lock()
	r.auditLag = seconds
	r.hasLag = ok
	r.mu.Unlock()
}

func (r *Registry) AuthP95() (p95 float64, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.authRing.snapshot()
	if len(s) == 0 {
		return 0, 0
	}
	return Quantile(s, 0.95), len(s)
}

func (r *Registry) SessionP95() (p95 float64, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.sessRing.snapshot()
	if len(s) == 0 {
		return 0, 0
	}
	return Quantile(s, 0.95), len(s)
}

func (r *Registry) WritePrometheus(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fmt.Fprintln(w, "# HELP keeppam_http_requests_total HTTP requests")
	fmt.Fprintln(w, "# TYPE keeppam_http_requests_total counter")
	keys := make([]string, 0, len(r.httpCount))
	for k := range r.httpCount {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		route, code, _ := strings.Cut(k, "|")
		fmt.Fprintf(w, "keeppam_http_requests_total{route=%q,code=%q} %d\n", route, code, r.httpCount[k])
	}

	fmt.Fprintln(w, "# HELP keeppam_http_request_duration_seconds HTTP request duration")
	fmt.Fprintln(w, "# TYPE keeppam_http_request_duration_seconds histogram")
	routes := make([]string, 0, len(r.httpHist))
	for k := range r.httpHist {
		routes = append(routes, k)
	}
	sort.Strings(routes)
	for _, route := range routes {
		writeHist(w, "keeppam_http_request_duration_seconds", map[string]string{"route": route}, r.httpHist[route])
	}

	fmt.Fprintln(w, "# HELP keeppam_auth_login_seconds Auth handler duration")
	fmt.Fprintln(w, "# TYPE keeppam_auth_login_seconds histogram")
	methods := make([]string, 0, len(r.authHist))
	for k := range r.authHist {
		methods = append(methods, k)
	}
	sort.Strings(methods)
	for _, m := range methods {
		writeHist(w, "keeppam_auth_login_seconds", map[string]string{"method": m}, r.authHist[m])
	}

	fmt.Fprintln(w, "# HELP keeppam_session_setup_seconds Session create-to-active seconds")
	fmt.Fprintln(w, "# TYPE keeppam_session_setup_seconds histogram")
	writeHist(w, "keeppam_session_setup_seconds", nil, r.sessHist)

	fmt.Fprintln(w, "# HELP keeppam_audit_events_total Audit events recorded in this process")
	fmt.Fprintln(w, "# TYPE keeppam_audit_events_total counter")
	fmt.Fprintf(w, "keeppam_audit_events_total %d\n", r.auditN)

	fmt.Fprintln(w, "# HELP keeppam_active_sessions Active PAM sessions")
	fmt.Fprintln(w, "# TYPE keeppam_active_sessions gauge")
	fmt.Fprintf(w, "keeppam_active_sessions %d\n", r.active)

	fmt.Fprintln(w, "# HELP keeppam_audit_export_lag_seconds SIEM export cursor lag")
	fmt.Fprintln(w, "# TYPE keeppam_audit_export_lag_seconds gauge")
	if r.hasLag {
		fmt.Fprintf(w, "keeppam_audit_export_lag_seconds %g\n", r.auditLag)
	}
}

type hist struct {
	buckets []float64
	counts  []uint64
	sum     float64
	n       uint64
}

func newHist() *hist {
	return &hist{buckets: latencyBuckets, counts: make([]uint64, len(latencyBuckets)+1)}
}

func (h *hist) observe(v float64) {
	h.sum += v
	h.n++
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
			return
		}
	}
	h.counts[len(h.buckets)]++
}

func writeHist(w io.Writer, name string, labels map[string]string, h *hist) {
	if h == nil {
		return
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	base := ""
	if len(keys) > 0 {
		var b strings.Builder
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "%s=%q", k, labels[k])
		}
		base = b.String()
	}
	var cum uint64
	for i, ub := range h.buckets {
		cum += h.counts[i]
		le := strconv.FormatFloat(ub, 'f', -1, 64)
		fmt.Fprintf(w, "%s_bucket{%s} %d\n", name, withLe(base, le), cum)
	}
	cum += h.counts[len(h.buckets)]
	fmt.Fprintf(w, "%s_bucket{%s} %d\n", name, withLe(base, "+Inf"), cum)
	fmt.Fprintf(w, "%s_sum{%s} %g\n", name, base, h.sum)
	fmt.Fprintf(w, "%s_count{%s} %d\n", name, base, h.n)
}

func withLe(base, le string) string {
	if base == "" {
		return fmt.Sprintf("le=%q", le)
	}
	return base + fmt.Sprintf(",le=%q", le)
}

type sampleRing struct {
	v []float64
	i int
	n int
}

func newRing(cap int) *sampleRing {
	return &sampleRing{v: make([]float64, cap)}
}

func (r *sampleRing) add(x float64) {
	r.v[r.i] = x
	r.i = (r.i + 1) % len(r.v)
	if r.n < len(r.v) {
		r.n++
	}
}

func (r *sampleRing) snapshot() []float64 {
	if r.n == 0 {
		return nil
	}
	out := make([]float64, r.n)
	start := 0
	if r.n == len(r.v) {
		start = r.i
	}
	for i := 0; i < r.n; i++ {
		out[i] = r.v[(start+i)%len(r.v)]
	}
	return out
}
