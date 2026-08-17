package pades

import (
	"bytes"
	"fmt"
	"strings"
)

type signMeta struct {
	catalogID int
	fieldID   int
	dssID     int
}

func appendDSS(pdf []byte, meta signMeta, ltv ltvBundle) ([]byte, signMeta, error) {
	if len(ltv.Certs) == 0 && len(ltv.OCSPs) == 0 && len(ltv.CRLs) == 0 {
		return nil, signMeta{}, fmt.Errorf("pades: empty ltv bundle")
	}
	startxref, size, err := parseTrailer(pdf)
	if err != nil {
		return nil, signMeta{}, err
	}
	nextID := size
	var b bytes.Buffer
	b.Write(pdf)
	if !bytes.HasSuffix(pdf, []byte("\n")) {
		b.WriteByte('\n')
	}
	offsets := map[int]int{}
	writeStream := func(data []byte) int {
		id := nextID
		nextID++
		offsets[id] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n<< /Length %d >>\nstream\n", id, len(data))
		b.Write(data)
		b.WriteString("\nendstream\nendobj\n")
		return id
	}
	certIDs := make([]int, 0, len(ltv.Certs))
	for _, der := range ltv.Certs {
		certIDs = append(certIDs, writeStream(der))
	}
	ocspIDs := make([]int, 0, len(ltv.OCSPs))
	for _, der := range ltv.OCSPs {
		ocspIDs = append(ocspIDs, writeStream(der))
	}
	crlIDs := make([]int, 0, len(ltv.CRLs))
	for _, der := range ltv.CRLs {
		crlIDs = append(crlIDs, writeStream(der))
	}
	dssID := nextID
	nextID++
	var dssParts []string
	dssParts = append(dssParts, "/Type /DSS")
	if len(certIDs) > 0 {
		dssParts = append(dssParts, "/Certs ["+pdfRefs(certIDs)+"]")
	}
	if len(ocspIDs) > 0 {
		dssParts = append(dssParts, "/OCSPs ["+pdfRefs(ocspIDs)+"]")
	}
	if len(crlIDs) > 0 {
		dssParts = append(dssParts, "/CRLs ["+pdfRefs(crlIDs)+"]")
	}
	dssBody := "<< " + strings.Join(dssParts, " ") + " >>\n"
	offsets[dssID] = b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n%sendobj\n", dssID, dssBody)
	catalogID := nextID
	catalogBody := fmt.Sprintf(
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [%d 0 R] /SigFlags 3 >> /DSS %d 0 R >>\n",
		meta.fieldID, dssID)
	offsets[catalogID] = b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n%sendobj\n", catalogID, catalogBody)

	xrefAt := b.Len()
	first := dssID
	if len(certIDs) > 0 {
		first = certIDs[0]
	} else if len(ocspIDs) > 0 {
		first = ocspIDs[0]
	} else if len(crlIDs) > 0 {
		first = crlIDs[0]
	}
	count := catalogID - first + 1
	fmt.Fprintf(&b, "xref\n%d %d\n", first, count)
	for id := first; id <= catalogID; id++ {
		off, ok := offsets[id]
		if !ok {
			return nil, signMeta{}, fmt.Errorf("pades: dss offset %d", id)
		}
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
		catalogID+1, catalogID, startxref, xrefAt)
	return b.Bytes(), signMeta{catalogID: catalogID, fieldID: meta.fieldID, dssID: dssID}, nil
}

func pdfRefs(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%d 0 R", id)
	}
	return strings.Join(parts, " ")
}
