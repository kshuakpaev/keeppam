package policy

import "strings"

var semanticCategories = map[string][]string{
	"nlp_sem_salary": {
		"salary", "зарплат", "оклад", "compensation", "bonus", "преми",
	},
	"nlp_sem_dump": {
		"pg_dump", "mysqldump", "sqlcmd", "expdp", "дамп", "dump database", "backup database",
	},
	"nlp_sem_schema_drop": {
		"drop table", "drop database", "drop schema", "удаление схемы", "удалить таблиц",
	},
}

// ScanSemantic returns audit-only kinds. Never used for mask/deny.
func ScanSemantic(text string) []string {
	low := strings.ToLower(text)
	if low == "" {
		return nil
	}
	var kinds []string
	for kind, kws := range semanticCategories {
		for _, kw := range kws {
			if strings.Contains(low, kw) {
				kinds = append(kinds, kind)
				break
			}
		}
	}
	return kinds
}
