package policy

import "testing"

func TestNormalizeOCRLang(t *testing.T) {
	v, err := NormalizeOCRLang("")
	if err != nil || v != OCRDefaultLang {
		t.Fatalf("empty %q %v", v, err)
	}
	v, err = NormalizeOCRLang("ENG")
	if err != nil || v != "eng" {
		t.Fatalf("eng %q %v", v, err)
	}
	v, err = NormalizeOCRLang("rus,eng")
	if err != nil || v != "rus+eng" {
		t.Fatalf("combo %q %v", v, err)
	}
	if _, err := NormalizeOCRLang("deu"); err == nil {
		t.Fatal("deu")
	}
}

func TestNormalizeOCRBounds(t *testing.T) {
	if _, err := NormalizeOCRInterval(3); err == nil {
		t.Fatal("interval")
	}
	n, err := NormalizeOCRMaxFrames(0)
	if err != nil || n != OCRDefaultFrames {
		t.Fatalf("frames %d %v", n, err)
	}
	n, err = NormalizeOCRMaxFrames(3600)
	if err != nil || n != 3600 {
		t.Fatalf("cap ok %d %v", n, err)
	}
	if _, err := NormalizeOCRMaxFrames(3601); err == nil {
		t.Fatal("over cap")
	}
}
