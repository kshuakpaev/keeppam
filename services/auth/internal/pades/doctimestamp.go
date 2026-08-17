package pades

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const subFilterDocTS = "ETSI.RFC3161"

func appendDocTimestamp(pdf []byte, s *Signer, meta signMeta, at time.Time, reserve int) ([]byte, error) {
	if s == nil || strings.TrimSpace(s.TSAURL) == "" {
		return nil, fmt.Errorf("pades: empty TSA for document timestamp")
	}
	startxref, size, err := parseTrailer(pdf)
	if err != nil {
		return nil, err
	}
	tsSigID := size
	tsFieldID := size + 1
	catalogID := size + 2

	var b bytes.Buffer
	b.Write(pdf)
	if !bytes.HasSuffix(pdf, []byte("\n")) {
		b.WriteByte('\n')
	}

	hexZeros := strings.Repeat("0", reserve*2)
	m := at.Format("D:20060102150405Z")
	tsSigBody := fmt.Sprintf(
		"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /%s /ByteRange [0 0000000000 0000000000 0000000000] /Contents <%s> /M (%s) >>\n",
		subFilterDocTS, hexZeros, m)
	tsFieldBody := fmt.Sprintf(
		"<< /Type /Annot /Subtype /Widget /FT /Sig /T (KeepPAM-ArchiveTS) /F 132 /P 5 0 R /Rect [0 0 0 0] /V %d 0 R >>\n",
		tsSigID)

	catalogParts := fmt.Sprintf("/Type /Catalog /Pages 2 0 R /AcroForm << /Fields [%d 0 R %d 0 R] /SigFlags 3 >>",
		meta.fieldID, tsFieldID)
	if meta.dssID > 0 {
		catalogParts += fmt.Sprintf(" /DSS %d 0 R", meta.dssID)
	}
	catalogBody := "<< " + catalogParts + " >>\n"

	offSig := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n%sendobj\n", tsSigID, tsSigBody)
	offField := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n%sendobj\n", tsFieldID, tsFieldBody)
	offCat := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n%sendobj\n", catalogID, catalogBody)

	xrefAt := b.Len()
	fmt.Fprintf(&b, "xref\n%d 3\n%010d 00000 n \n%010d 00000 n \n%010d 00000 n \n",
		tsSigID, offSig, offField, offCat)
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
		catalogID+1, catalogID, startxref, xrefAt)

	out := b.Bytes()
	brStart, contentsOpen, contentsClose, err := locateSigPlaceholders(out)
	if err != nil {
		return nil, err
	}
	if contentsClose-contentsOpen-1 != reserve*2 {
		return nil, fmt.Errorf("pades: docts contents width")
	}
	a := contentsOpen
	c := contentsClose + 1
	d := len(out) - c
	br := fmt.Sprintf("/ByteRange [0 %010d %010d %010d]", a, c, d)
	if len(br) != len("/ByteRange [0 0000000000 0000000000 0000000000]") {
		return nil, fmt.Errorf("pades: docts byterange width")
	}
	copy(out[brStart:brStart+len(br)], []byte(br))

	toStamp := make([]byte, 0, a+d)
	toStamp = append(toStamp, out[:a]...)
	toStamp = append(toStamp, out[c:]...)
	token, err := fetchTimestamp(s.TSAURL, toStamp)
	if err != nil {
		return nil, err
	}
	if len(token) > reserve {
		return nil, fmt.Errorf("pades: docts token too large (%d > %d)", len(token), reserve)
	}
	hx := strings.ToUpper(hex.EncodeToString(token))
	if len(hx)%2 != 0 {
		return nil, fmt.Errorf("pades: docts odd hex")
	}
	padded := hx + strings.Repeat("0", reserve*2-len(hx))
	copy(out[contentsOpen+1:contentsClose], []byte(padded))
	return out, nil
}
