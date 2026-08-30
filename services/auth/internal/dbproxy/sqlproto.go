package dbproxy

func IsSQLProtocol(protocol string) bool {
	switch protocol {
	case "postgres", "mysql", "mssql", "oracle":
		return true
	default:
		return false
	}
}

func UsesEphemeralDBRole(protocol string) bool {
	return protocol == "postgres" || protocol == "mysql"
}
