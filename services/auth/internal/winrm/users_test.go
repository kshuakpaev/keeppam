package winrm

import (
	"testing"
)

func TestParseDiscoverJSON(t *testing.T) {
	raw := `{"users":[{"Name":"Administrator","Enabled":true,"SID":"S-1-5-21-1-500"},{"Name":"Guest","Enabled":false,"SID":"S-1-5-21-2"}],"admins":["Administrator","BUILTIN\\Administrators"]}`
	users, err := ParseDiscoverJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Name != "Administrator" || !users[0].Privileged {
		t.Fatalf("got %+v", users)
	}
}

func TestParseSAMNetUser(t *testing.T) {
	netUser := `
User accounts for \\HOST

Administrator            Guest                    svc-app
The command completed successfully.
`
	admins := `
Alias name     administrators
Members

Administrator
svc-admin
The command completed successfully.
`
	users, err := ParseSAMNetUser(netUser, admins)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]LocalUser{}
	for _, u := range users {
		found[u.Name] = u
	}
	if !found["Administrator"].Privileged {
		t.Fatal("admin")
	}
	if found["Guest"].Privileged {
		t.Fatal("guest")
	}
	if users[0].Source != "sam_ssh" {
		t.Fatal("source")
	}
}
