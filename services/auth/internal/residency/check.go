package residency

import (
	"net/url"
	"strings"
)

const (
	RegionKZ  = "KZ"
	CountryKZ = "Kazakhstan"
)

// CloudKeySources are KMS backends that send key material off-prem.
var CloudKeySources = map[string]struct{}{
	"aws":   {},
	"gcp":   {},
	"azure": {},
}

var cloudS3Host = []string{
	"amazonaws.com",
	"amazonaws.com.cn",
	"googleapis.com",
	"storage.cloud.google.com",
	"blob.core.windows.net",
	"digitaloceanspaces.com",
	"r2.cloudflarestorage.com",
}

// CloudS3 reports whether the recordings endpoint is a public-cloud object store.
func CloudS3(endpoint string) bool {
	ep := strings.ToLower(strings.TrimSpace(endpoint))
	if ep == "" {
		return false
	}
	if !strings.Contains(ep, "://") {
		ep = "https://" + ep
	}
	u, err := url.Parse(ep)
	host := ep
	if err == nil && u.Host != "" {
		host = strings.ToLower(u.Host)
	}
	for _, s := range cloudS3Host {
		if strings.Contains(host, s) {
			return true
		}
	}
	return false
}

// CloudDataKey is true when envelope KEK lives in a public-cloud KMS.
func CloudDataKey(source string) bool {
	_, ok := CloudKeySources[strings.ToLower(strings.TrimSpace(source))]
	return ok
}

// Compliant is true for on-prem KZ residency without public-cloud key/object stores.
func Compliant(region string, onPrem bool, dataKeySource, s3Endpoint string) bool {
	if !onPrem {
		return false
	}
	if strings.ToUpper(strings.TrimSpace(region)) != RegionKZ {
		return false
	}
	if CloudDataKey(dataKeySource) {
		return false
	}
	if CloudS3(s3Endpoint) {
		return false
	}
	return true
}

func Risks(region string, onPrem bool, dataKeySource, s3Endpoint string) []string {
	var out []string
	if !onPrem {
		out = append(out, "not_on_prem")
	}
	if strings.ToUpper(strings.TrimSpace(region)) != RegionKZ {
		out = append(out, "region_not_kz")
	}
	if CloudDataKey(dataKeySource) {
		out = append(out, "cloud_kms")
	}
	if CloudS3(s3Endpoint) {
		out = append(out, "cloud_s3")
	}
	return out
}
