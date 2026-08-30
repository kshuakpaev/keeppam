package residency

import "testing"

func TestCloudS3(t *testing.T) {
	if CloudS3("") {
		t.Fatal("empty")
	}
	if CloudS3("http://minio:9000") {
		t.Fatal("minio on-prem")
	}
	if CloudS3("https://ceph.corp.kz") {
		t.Fatal("on-prem host")
	}
	if !CloudS3("https://s3.eu-central-1.amazonaws.com") {
		t.Fatal("aws")
	}
	if !CloudS3("keeppam.blob.core.windows.net") {
		t.Fatal("azure host without scheme")
	}
}

func TestCompliantKZ(t *testing.T) {
	if !Compliant("KZ", true, "env", "") {
		t.Fatal("on-prem env")
	}
	if !Compliant("kz", true, "vault", "http://minio:9000") {
		t.Fatal("vault+minio")
	}
	if Compliant("KZ", false, "env", "") {
		t.Fatal("saas")
	}
	if Compliant("DE", true, "env", "") {
		t.Fatal("not kz")
	}
	if Compliant("KZ", true, "aws", "") {
		t.Fatal("cloud kms")
	}
	if Compliant("KZ", true, "env", "https://storage.googleapis.com") {
		t.Fatal("cloud s3")
	}
}

func TestRisks(t *testing.T) {
	r := Risks("US", false, "gcp", "https://s3.amazonaws.com/b")
	if len(r) != 4 {
		t.Fatalf("got %v", r)
	}
}
