package firewall

import "errors"

var ErrNotPamOnly = errors.New("asset is not pam_only or not found")
