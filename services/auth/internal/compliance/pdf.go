package compliance

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	pdfPageW  = 595.0
	pdfPageH  = 842.0
	pdfMargin = 48.0
	pdfBottom = 40.0
)

// WriteReportPDF renders the same compliance report as a simple multi-page PDF
// (Helvetica, no extra fonts). Non-ASCII is transliterated. Signature is applied
// separately (PAdES-B-B/B-T) when a signer is configured.
func WriteReportPDF(w io.Writer, rep Report) error {
	return writeReportPDF(w, rep, "")
}

func writeReportPDF(w io.Writer, rep Report, signatureLabel string) error {
	pages := renderReportPDF(rep, signatureLabel)
	return encodePDF(w, pages)
}

type pdfBuf struct {
	pages []string
	body  strings.Builder
	y     float64
}

func renderReportPDF(rep Report, signatureLabel string) []string {
	b := &pdfBuf{y: pdfPageH - pdfMargin}
	b.heading("KeepPAM Compliance Report")
	b.kv("Generated (UTC)", rep.GeneratedAt.UTC().Format(time.RFC3339))
	b.kv("Period", fmt.Sprintf("%s  ..  %s",
		rep.From.UTC().Format(time.RFC3339), rep.To.UTC().Format(time.RFC3339)))
	b.kv("Framework", rep.Framework)
	if signatureLabel != "" {
		b.kv("Signature", signatureLabel)
	}
	if rep.Truncated {
		b.kv("Evidence", fmt.Sprintf("%d of %d (truncated)", len(rep.Evidence), rep.EvidenceTotal))
	} else {
		b.kv("Evidence", strconv.Itoa(rep.EvidenceTotal))
	}
	b.gap(8)

	b.sub("Live snapshot (at generation, not the period)")
	b.kv("ACL live", strconv.Itoa(rep.Snapshot.ACLLive))
	b.kv("Sessions active", strconv.Itoa(rep.Snapshot.SessionsActive))
	b.kv("JIT pending", strconv.Itoa(rep.Snapshot.JITPending))
	b.kv("Break-glass active", strconv.Itoa(rep.Snapshot.BreakGlassActive))
	b.kv("Legal holds", strconv.Itoa(rep.Snapshot.LegalHolds))
	b.gap(8)

	b.sub("Summary")
	b.kv("access", strconv.Itoa(rep.Summary.Access))
	b.kv("privileged", strconv.Itoa(rep.Summary.Privileged))
	b.kv("approvals", strconv.Itoa(rep.Summary.Approvals))
	b.kv("connections", strconv.Itoa(rep.Summary.Connections))
	b.kv("commands", strconv.Itoa(rep.Summary.Commands))
	b.kv("sql", strconv.Itoa(rep.Summary.SQL))
	b.kv("downloads", strconv.Itoa(rep.Summary.Downloads))
	b.kv("changes", strconv.Itoa(rep.Summary.Changes))
	b.kv("revoked", strconv.Itoa(rep.Summary.Revoked))
	b.gap(8)

	if len(rep.Controls) > 0 {
		b.sub("Controls")
		for _, c := range rep.Controls {
			b.line(9, false, fmt.Sprintf("%s  %s  [%s]", c.ID, c.Title, strings.Join(c.Categories, ", ")))
		}
		b.gap(8)
	}

	b.sub("Evidence")
	if len(rep.Evidence) == 0 {
		b.line(9, false, "(none in window)")
	}
	for _, e := range rep.Evidence {
		head := fmt.Sprintf("%s  %s  %s  %s",
			e.TS.UTC().Format("2006-01-02 15:04:05"),
			e.Category, nz(e.Actor, "-"), e.Action)
		b.line(8, true, head)
		if d := strings.TrimSpace(e.Detail); d != "" {
			b.line(8, false, "  "+d)
		}
	}
	b.gap(8)

	b.sub("Notes")
	for _, n := range pdfNotes(signatureLabel) {
		b.line(8, false, "- "+n)
	}

	b.flushPage()
	n := len(b.pages)
	if n == 0 {
		n = 1
		b.pages = []string{""}
	}
	for i := range b.pages {
		b.pages[i] += fmt.Sprintf("BT /F1 8 Tf %.1f 24 Td (%s) Tj ET\n",
			pdfMargin, pdfEsc(fmt.Sprintf("KeepPAM  %d/%d  confidential", i+1, n)))
	}
	return b.pages
}

func pdfNotes(signatureLabel string) []string {
	notes := []string{
		"SSH commands: PTY journal and asciicast stdin index. Terminal stdout is event type output (not in this report).",
		"SQL: allowed and denied statements from session_events.",
		"Framework labels controls (ISO A.9 / PCI 7-10 / SOC2 CC6-CC7 / NIST AC,AU,CM); same evidence query.",
		"Snapshot is live ACL/sessions/JIT/break-glass at generation time, not the selected period.",
		"Non-ASCII in evidence is transliterated (Helvetica core font).",
	}
	switch {
	case strings.Contains(signatureLabel, "qualified electronic signature"):
		notes = append(notes, signatureLabel+". Validation depends on trust service and HSM policy configured by the operator.")
	case strings.HasPrefix(signatureLabel, "PAdES-B-LTA"):
		notes = append(notes, "This PDF is signed PAdES-B-LTA (CAdES + DSS + archive document timestamp). Not a qualified signature unless QES label is present.")
	case strings.HasPrefix(signatureLabel, "PAdES-B-LT"):
		notes = append(notes, "This PDF is signed PAdES-B-LT (ETSI.CAdES.detached + RFC3161 + DSS). Not a qualified signature.")
	case strings.HasPrefix(signatureLabel, "PAdES-B-T"):
		notes = append(notes, "This PDF is signed PAdES-B-T (ETSI.CAdES.detached + RFC3161). Not a qualified signature; no LTV/OCSP.")
	case signatureLabel != "":
		notes = append(notes, "This PDF is signed PAdES-B-B (ETSI.CAdES.detached). Not a qualified signature; no timestamp or LTV.")
	default:
		notes = append(notes, "This PDF is an export of the JSON report. It is not a signed auditor package.")
	}
	return notes
}

func (b *pdfBuf) heading(s string) {
	b.line(16, true, s)
	b.rule()
}

func (b *pdfBuf) sub(s string) {
	b.gap(4)
	b.line(11, true, s)
	b.rule()
}

func (b *pdfBuf) kv(k, v string) {
	b.line(9, false, k+":  "+v)
}

func (b *pdfBuf) gap(h float64) {
	b.ensure(h)
	b.y -= h
}

func (b *pdfBuf) rule() {
	b.ensure(6)
	b.body.WriteString(fmt.Sprintf("%.1f %.1f m %.1f %.1f l S\n", pdfMargin, b.y, pdfPageW-pdfMargin, b.y))
	b.y -= 8
}

func (b *pdfBuf) line(size float64, bold bool, s string) {
	width := 92
	if size <= 8 {
		width = 108
	} else if size >= 14 {
		width = 62
	}
	for _, part := range wrapPDF(pdfLatin(s), width) {
		lh := size + 3
		b.ensure(lh)
		font := "F1"
		if bold {
			font = "F2"
		}
		b.body.WriteString(fmt.Sprintf("BT /%s %.1f Tf %.1f %.1f Td (%s) Tj ET\n",
			font, size, pdfMargin, b.y, pdfEsc(part)))
		b.y -= lh
	}
}

func (b *pdfBuf) ensure(h float64) {
	if b.y-h >= pdfBottom {
		return
	}
	b.flushPage()
}

func (b *pdfBuf) flushPage() {
	if b.body.Len() == 0 && len(b.pages) > 0 {
		b.y = pdfPageH - pdfMargin
		return
	}
	b.pages = append(b.pages, b.body.String())
	b.body.Reset()
	b.y = pdfPageH - pdfMargin
}

func wrapPDF(s string, width int) []string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return []string{""}
	}
	if width < 8 {
		width = 8
	}
	var out []string
	for len(s) > width {
		cut := strings.LastIndex(s[:width], " ")
		if cut < width/3 {
			cut = width
		}
		out = append(out, strings.TrimSpace(s[:cut]))
		s = strings.TrimSpace(s[cut:])
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

func pdfEsc(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	return s
}

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func pdfLatin(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 32 {
			b.WriteByte(' ')
			continue
		}
		if r < 127 {
			b.WriteRune(r)
			continue
		}
		if t, ok := cyrLat[unicode.ToLower(r)]; ok {
			if unicode.IsUpper(r) && t != "" {
				t = strings.ToUpper(t[:1]) + t[1:]
			}
			b.WriteString(t)
			continue
		}
		b.WriteByte('?')
	}
	return b.String()
}

var cyrLat = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "e",
	'ж': "zh", 'з': "z", 'и': "i", 'й': "y", 'к': "k", 'л': "l", 'м': "m",
	'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u",
	'ф': "f", 'х': "kh", 'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "shch",
	'ъ': "", 'ы': "y", 'ь': "", 'э': "e", 'ю': "yu", 'я': "ya",
}

func encodePDF(w io.Writer, streams []string) error {
	if len(streams) == 0 {
		streams = []string{""}
	}
	n := len(streams)
	pageIDs := make([]int, n)
	contentIDs := make([]int, n)
	for i := 0; i < n; i++ {
		pageIDs[i] = 5 + 2*i
		contentIDs[i] = 6 + 2*i
	}
	kids := make([]string, n)
	for i, id := range pageIDs {
		kids[i] = fmt.Sprintf("%d 0 R", id)
	}

	type obj struct {
		id   int
		body string
	}
	objs := []obj{
		{1, "<< /Type /Catalog /Pages 2 0 R >>\n"},
		{2, fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>\n", n, strings.Join(kids, " "))},
		{3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\n"},
		{4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\n"},
	}
	for i := 0; i < n; i++ {
		raw := streams[i]
		if !strings.HasSuffix(raw, "\n") {
			raw += "\n"
		}
		objs = append(objs, obj{pageIDs[i], fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>\n",
			pdfPageW, pdfPageH, contentIDs[i])})
		objs = append(objs, obj{contentIDs[i], fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream\n", len(raw), raw)})
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].id < objs[j].id })

	var buf strings.Builder
	buf.WriteString("%PDF-1.4\n%\x80\x80\x80\x80\n")
	offsets := make([]int, objs[len(objs)-1].id+1)
	for _, o := range objs {
		offsets[o.id] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%sendobj\n", o.id, o.body)
	}
	startxref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(offsets))
	buf.WriteString("0000000000 65535 f \n")
	for id := 1; id < len(offsets); id++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[id])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets), startxref)
	_, err := io.WriteString(w, buf.String())
	return err
}
