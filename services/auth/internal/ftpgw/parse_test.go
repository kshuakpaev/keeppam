package ftpgw

import "testing"

func TestParsePASV(t *testing.T) {
	host, port, err := parsePASV("Entering Passive Mode (192,168,1,10,20,5)")
	if err != nil {
		t.Fatal(err)
	}
	if host != "192.168.1.10" || port != 20*256+5 {
		t.Fatalf("%s %d", host, port)
	}
}

func TestSplitFTP(t *testing.T) {
	c, a := splitFTP("USER alice+ftp-prod")
	if c != "USER" || a != "alice+ftp-prod" {
		t.Fatalf("%q %q", c, a)
	}
}

func TestFormatPASV(t *testing.T) {
	got := formatPASV("10.0.0.1", 2121)
	if got != "227 Entering Passive Mode (10,0,0,1,8,73)" {
		t.Fatal(got)
	}
}
