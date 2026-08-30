package rbac

// HasRole reports whether roles contains name (exact).
func HasRole(roles []string, name string) bool {
	for _, r := range roles {
		if r == name {
			return true
		}
	}
	return false
}

// SeesFullAssetCatalog is true for inventory/ACL/platform admins and auditors.
// Operators see only assets they were assigned (ACL) or that they own.
func SeesFullAssetCatalog(perms []string) bool {
	return HasPermission(perms, "assets.write") ||
		HasPermission(perms, "assets.acl") ||
		HasPermission(perms, "users.write") ||
		HasPermission(perms, "audit.read")
}

// RestrictToOwnedAssets is true when the user is an asset owner and not a
// platform-wide role (admin/operator/auditor/security). Owners only see and
// manage assets where assets.owner_user_id = themselves.
func RestrictToOwnedAssets(roles []string) bool {
	if HasRole(roles, "admin") || HasRole(roles, "operator") || HasRole(roles, "auditor") || HasRole(roles, "security") {
		return false
	}
	return HasRole(roles, "owner")
}

// OwnsAsset is true if ownerUserID is the given user.
func OwnsAsset(ownerUserID *string, userID string) bool {
	if ownerUserID == nil || userID == "" {
		return false
	}
	return *ownerUserID == userID
}
