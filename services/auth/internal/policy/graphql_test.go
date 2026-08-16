package policy

import (
	"encoding/json"
	"testing"
)

func TestExtractGraphQLFieldsJSON(t *testing.T) {
	f, ok := ExtractGraphQLFields("application/json", []byte(`{"query":"query { user { id } posts }"}`))
	if !ok || len(f) != 2 || f[0] != "user" || f[1] != "posts" {
		t.Fatalf("%v %v", f, ok)
	}
}

func TestExtractGraphQLMutationAndAlias(t *testing.T) {
	f, ok := ExtractGraphQLFields("application/graphql", []byte(`mutation { gone: deleteCustomer(id: "1") { id } }`))
	if !ok || len(f) != 1 || f[0] != "deleteCustomer" {
		t.Fatalf("%v %v", f, ok)
	}
}

func TestExtractGraphQLOperationName(t *testing.T) {
	src := `query A { a } mutation B { deleteCustomer }`
	f, ok := ExtractGraphQLFields("application/json", []byte(`{"operationName":"B","query":`+jsonQuote(src)+`}`))
	if !ok || len(f) != 1 || f[0] != "deleteCustomer" {
		t.Fatalf("%v %v", f, ok)
	}
}

func TestExtractGraphQLIntrospection(t *testing.T) {
	f, ok := ExtractGraphQLFields("application/graphql", []byte(`query { __schema { types { name } } }`))
	if !ok || len(f) != 1 || f[0] != "__schema" {
		t.Fatalf("%v %v", f, ok)
	}
}

func TestExtractGraphQLNotGraphQL(t *testing.T) {
	if _, ok := ExtractGraphQLFields("application/json", []byte(`{"foo":1}`)); ok {
		t.Fatal("not graphql")
	}
}

func TestExtractGraphQLBatch(t *testing.T) {
	f, ok := ExtractGraphQLFields("application/json", []byte(`[{"query":"query { a }"},{"query":"query { b }"}]`))
	if !ok || len(f) != 2 {
		t.Fatalf("%v %v", f, ok)
	}
}

func TestMatchAppObjectGraphQLSmuggle(t *testing.T) {
	pack := AppObjectPack{
		Name: "gql", Unmatched: "deny",
		Rules: []string{
			"POST /graphql delete* deny",
			"POST /graphql * allow",
		},
	}
	d := MatchAppObjectFields(pack, "POST", "/graphql", []string{"listCustomers", "deleteCustomer"})
	if d.Allowed || d.Object != "deleteCustomer" {
		t.Fatalf("smuggle: %+v", d)
	}
	d = MatchAppObjectFields(pack, "POST", "/graphql", []string{"listCustomers"})
	if !d.Allowed {
		t.Fatalf("allow: %+v", d)
	}
}

func TestMatchAppObjectRESTUnchanged(t *testing.T) {
	pack := AppObjectPack{
		Unmatched: "deny",
		Rules:     []string{"GET /api/customers* customer.view allow"},
	}
	d := MatchAppObject(pack, "GET", "/api/customers/1")
	if !d.Allowed || d.Object != "customer.view" {
		t.Fatalf("%+v", d)
	}
}

func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
