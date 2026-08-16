package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Error struct {
	Status int
	Type   string
	Detail string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Detail
}

func errNotFound(what string) *Error {
	return &Error{Status: http.StatusNotFound, Type: "invalidValue", Detail: what + " not found"}
}

func errConflict(detail string) *Error {
	return &Error{Status: http.StatusConflict, Type: "uniqueness", Detail: detail}
}

func errBad(detail string) *Error {
	return &Error{Status: http.StatusBadRequest, Type: "invalidValue", Detail: detail}
}

func errFilter() *Error {
	return &Error{Status: http.StatusBadRequest, Type: "invalidFilter", Detail: "unsupported filter"}
}

func errForbidden(detail string) *Error {
	return &Error{Status: http.StatusForbidden, Type: "invalidValue", Detail: detail}
}

func asError(err error) *Error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		return e
	}
	msg := err.Error()
	if strings.Contains(msg, "duplicate") || strings.Contains(msg, "unique") {
		return errConflict(msg)
	}
	return &Error{Status: http.StatusBadRequest, Type: "invalidValue", Detail: msg}
}

func errorBody(e *Error) map[string]any {
	if e == nil {
		e = &Error{Status: 500, Detail: "internal error"}
	}
	out := map[string]any{
		"schemas": []string{schemaErr},
		"detail":  e.Detail,
		"status":  fmt.Sprintf("%d", e.Status),
	}
	if e.Type != "" {
		out["scimType"] = e.Type
	}
	return out
}

func Write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	if v == nil || code == http.StatusNoContent {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func WriteErr(w http.ResponseWriter, err error) {
	e, ok := err.(*Error)
	if !ok {
		e = asError(err)
	}
	if e == nil {
		e = &Error{Status: http.StatusInternalServerError, Detail: "internal error"}
	}
	if e.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="keeppam-scim"`)
	}
	Write(w, e.Status, errorBody(e))
}

func ErrUnauthorized() *Error {
	return &Error{Status: http.StatusUnauthorized, Type: "invalidValue", Detail: "unauthorized"}
}
