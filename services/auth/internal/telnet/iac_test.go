package telnet

import (
	"bytes"
	"testing"
)

func TestStripIACEscapedFF(t *testing.T) {
	in := []byte{1, iac, iac, 2}
	out, rest := stripIAC(in, nil, nil, nil)
	if len(rest) != 0 {
		t.Fatalf("rest=%v", rest)
	}
	if !bytes.Equal(out, []byte{1, 255, 2}) {
		t.Fatalf("out=%v", out)
	}
}

func TestStripIACWill(t *testing.T) {
	var gotCmd, gotOpt byte
	in := []byte{'a', iac, will, optEcho, 'b'}
	out, rest := stripIAC(in, nil, func(cmd, opt byte) {
		gotCmd, gotOpt = cmd, opt
	}, nil)
	if len(rest) != 0 || !bytes.Equal(out, []byte{'a', 'b'}) {
		t.Fatalf("out=%v rest=%v", out, rest)
	}
	if gotCmd != will || gotOpt != optEcho {
		t.Fatalf("opt %d %d", gotCmd, gotOpt)
	}
}

func TestStripIACPartial(t *testing.T) {
	out, rest := stripIAC([]byte{'x', iac, will}, nil, nil, nil)
	if !bytes.Equal(out, []byte{'x'}) || !bytes.Equal(rest, []byte{iac, will}) {
		t.Fatalf("out=%v rest=%v", out, rest)
	}
	out2, rest2 := stripIAC([]byte{optSGA, 'y'}, rest, nil, nil)
	if len(rest2) != 0 || !bytes.Equal(out2, []byte{'y'}) {
		t.Fatalf("out2=%v rest2=%v", out2, rest2)
	}
}

func TestNAWSSub(t *testing.T) {
	b := nawsSub(120, 40)
	if len(b) != 9 || b[0] != iac || b[2] != optNAWS {
		t.Fatalf("%v", b)
	}
	if b[3] != 0 || b[4] != 120 || b[5] != 0 || b[6] != 40 {
		t.Fatalf("dims %v", b)
	}
}
