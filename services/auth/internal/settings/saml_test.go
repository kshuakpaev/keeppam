package settings

import (
	"strings"
	"testing"

	"github.com/crewjam/saml"
)

func TestMapSAMLRoles(t *testing.T) {
	known := map[string]struct{}{"admin": {}, "operator": {}, "auditor": {}}
	got := MapSAMLRoles(
		[]string{"keeppam-admins", "unknown-group"},
		map[string]string{"keeppam-admins": "admin", "ops": "operator"},
		[]string{"operator"},
		"operator",
		known,
	)
	if strings.Join(got, ",") != "admin" {
		t.Fatalf("got %v", got)
	}

	keepAdmin := MapSAMLRoles(
		[]string{"ops"},
		map[string]string{"ops": "operator"},
		[]string{"admin", "operator"},
		"operator",
		known,
	)
	if strings.Join(keepAdmin, ",") != "admin,operator" {
		t.Fatalf("keep admin: %v", keepAdmin)
	}

	fallback := MapSAMLRoles(nil, map[string]string{"x": "admin"}, nil, "operator", known)
	if strings.Join(fallback, ",") != "operator" {
		t.Fatalf("fallback %v", fallback)
	}

	skipUnknown := MapSAMLRoles([]string{"g"}, map[string]string{"g": "nope"}, nil, "operator", known)
	if strings.Join(skipUnknown, ",") != "operator" {
		t.Fatalf("unknown role %v", skipUnknown)
	}
}

func TestParseGroupRoleMap(t *testing.T) {
	m := ParseGroupRoleMap("keeppam-admins=admin\n# c\nops = operator\n")
	if m["keeppam-admins"] != "admin" || m["ops"] != "operator" {
		t.Fatalf("%v", m)
	}
}

func TestNormalizeSAMLSlug(t *testing.T) {
	ok, err := NormalizeSAMLSlug(" Entra-Prod ")
	if err != nil || ok != "entra-prod" {
		t.Fatalf("%q %v", ok, err)
	}
	if _, err := NormalizeSAMLSlug("default"); err == nil {
		t.Fatal("default reserved")
	}
	if _, err := NormalizeSAMLSlug("-bad"); err == nil {
		t.Fatal("leading dash")
	}
}

func TestIdPConfigured(t *testing.T) {
	if IdPConfigured(SAMLIdP{}) {
		t.Fatal("empty")
	}
	if !IdPConfigured(SAMLIdP{MetadataURL: "https://idp/meta"}) {
		t.Fatal("metadata")
	}
	if !IdPConfigured(SAMLIdP{EntityID: "e", SSOURL: "https://sso", CertPEM: "cert"}) {
		t.Fatal("manual")
	}
}

func TestOverlaySAMLACS(t *testing.T) {
	s := &Service{}
	cfg := AuthSettings{PublicBaseURL: "http://localhost:5173", SAMLSPEntityID: "sp"}
	ov := s.OverlaySAML(cfg, SAMLIdP{Slug: "okta", MetadataURL: "https://okta/meta"})
	if ov.SAMLACSURL != "http://localhost:5173/api/v1/auth/saml/idp/okta/acs" {
		t.Fatalf("acs %s", ov.SAMLACSURL)
	}
	def := s.OverlaySAML(cfg, SAMLIdP{Slug: "default", MetadataURL: "https://a"})
	if def.SAMLACSURL != "http://localhost:5173/api/v1/auth/saml/acs" {
		t.Fatalf("default acs %s", def.SAMLACSURL)
	}
}

func TestMapSAMLClaimsGroups(t *testing.T) {
	a := &saml.Assertion{
		AttributeStatements: []saml.AttributeStatement{{
			Attributes: []saml.Attribute{
				{
					Name: "uid",
					Values: []saml.AttributeValue{{Value: "alice"}},
				},
				{
					Name:         "groups",
					FriendlyName: "memberOf",
					Values: []saml.AttributeValue{
						{Value: "keeppam-admins"},
						{Value: "ops"},
					},
				},
			},
		}},
		Subject: &saml.Subject{NameID: &saml.NameID{Value: "alice@example.com"}},
	}
	c := mapSAMLClaims(AuthSettings{SAMLAttrUsername: "uid", SAMLGroupAttr: "groups"}, a)
	if c.Username != "alice" {
		t.Fatalf("username %s", c.Username)
	}
	if len(c.Groups) != 2 {
		t.Fatalf("groups %v", c.Groups)
	}
}
