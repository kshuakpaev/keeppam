package policy

import (
	"fmt"
	"strings"
)

const (
	OCRDefaultLang     = "rus+eng"
	OCRDefaultInterval = 15
	OCRDefaultFrames   = 60
	OCRMaxFramesCap    = 3600
	OCRMinInterval     = 5
	OCRMaxInterval     = 120
)

type OCROpts struct {
	Lang        string `json:"ocr_lang,omitempty"`
	IntervalSec int    `json:"ocr_interval_sec,omitempty"`
	MaxFrames   int    `json:"ocr_max_frames,omitempty"`
	EveryFrame  bool   `json:"ocr_every_frame,omitempty"`
	Live        bool   `json:"ocr_live,omitempty"`
	SSHStdout   bool   `json:"ocr_ssh_stdout,omitempty"`
}

func NormalizeOCRLang(s string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	v = strings.ReplaceAll(v, " ", "")
	v = strings.ReplaceAll(v, ",", "+")
	if v == "" {
		return OCRDefaultLang, nil
	}
	parts := strings.Split(v, "+")
	seen := map[string]bool{}
	var out []string
	for _, p := range parts {
		switch p {
		case "eng", "rus":
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		case "":
			continue
		default:
			return "", fmt.Errorf("ocr_lang must be eng, rus, or rus+eng")
		}
	}
	if len(out) == 0 {
		return OCRDefaultLang, nil
	}
	return strings.Join(out, "+"), nil
}

func NormalizeOCRInterval(n int) (int, error) {
	if n == 0 {
		return OCRDefaultInterval, nil
	}
	if n < OCRMinInterval || n > OCRMaxInterval {
		return 0, fmt.Errorf("ocr_interval_sec must be %d..%d", OCRMinInterval, OCRMaxInterval)
	}
	return n, nil
}

func NormalizeOCRMaxFrames(n int) (int, error) {
	if n == 0 {
		return OCRDefaultFrames, nil
	}
	if n < 1 || n > OCRMaxFramesCap {
		return 0, fmt.Errorf("ocr_max_frames must be 1..%d", OCRMaxFramesCap)
	}
	return n, nil
}

func (sn *Snapshot) OCR() OCROpts {
	if sn == nil {
		return OCROpts{
			Lang: OCRDefaultLang, IntervalSec: OCRDefaultInterval, MaxFrames: OCRDefaultFrames,
			SSHStdout: true,
		}
	}
	lang := sn.OCRLang
	if lang == "" {
		lang = OCRDefaultLang
	}
	iv := sn.OCRIntervalSec
	if iv == 0 {
		iv = OCRDefaultInterval
	}
	n := sn.OCRMaxFrames
	if n == 0 {
		n = OCRDefaultFrames
	}
	if n > OCRMaxFramesCap {
		n = OCRMaxFramesCap
	}
	ssh := true
	if sn.AccessPolicyID != nil {
		ssh = sn.OCRSSHStdout
	}
	return OCROpts{
		Lang: lang, IntervalSec: iv, MaxFrames: n,
		EveryFrame: sn.OCREveryFrame, Live: sn.OCRLive, SSHStdout: ssh,
	}
}
