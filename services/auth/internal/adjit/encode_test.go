package adjit

import (
	"encoding/binary"
	"fmt"
	"testing"
	"unicode/utf16"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestEncodeUnicodePwd(t *testing.T) {
	b := encodeUnicodePwd("Secret1!")
	want := utf16.Encode([]rune(`"Secret1!"`))
	if len(b) != len(want)*2 {
		t.Fatalf("len %d", len(b))
	}
	for i, c := range want {
		got := binary.LittleEndian.Uint16(b[i*2:])
		if got != c {
			t.Fatalf("idx %d got %d want %d", i, got, c)
		}
	}
}

func TestLDAPIdempotentCodes(t *testing.T) {
	exists := ldap.NewError(ldap.LDAPResultAttributeOrValueExists, fmt.Errorf("exists"))
	if !ldap.IsErrorWithCode(exists, ldap.LDAPResultAttributeOrValueExists) {
		t.Fatal("expected AttributeOrValueExists")
	}
	missing := ldap.NewError(ldap.LDAPResultNoSuchAttribute, fmt.Errorf("missing"))
	if !ldap.IsErrorWithCode(missing, ldap.LDAPResultNoSuchAttribute) {
		t.Fatal("expected NoSuchAttribute")
	}
}
