package rbac

func HasPermission(perms []string, need string) bool {
	for _, p := range perms {
		if p == need {
			return true
		}
	}
	return false
}
