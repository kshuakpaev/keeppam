package scim

import (
	"time"
)

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaErr   = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

type UserResource struct {
	Schemas     []string      `json:"schemas"`
	ID          string        `json:"id"`
	ExternalID  string        `json:"externalId,omitempty"`
	UserName    string        `json:"userName"`
	Name        *Name         `json:"name,omitempty"`
	DisplayName string        `json:"displayName,omitempty"`
	Emails      []Email       `json:"emails,omitempty"`
	Active      *bool         `json:"active,omitempty"`
	Meta        Meta          `json:"meta"`
}

type Name struct {
	Formatted string `json:"formatted,omitempty"`
}

type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

type GroupResource struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Member `json:"members,omitempty"`
	Meta        Meta     `json:"meta"`
}

type Member struct {
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}

type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

type PatchOp struct {
	Schemas       []string         `json:"schemas"`
	Operations    []PatchOperation `json:"Operations"`
	OperationsAlt []PatchOperation `json:"operations"`
}

type PatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func meta(kind, id string, created, updated time.Time) Meta {
	loc := "/scim/v2/Users/" + id
	if kind == "Group" {
		loc = "/scim/v2/Groups/" + id
	}
	return Meta{
		ResourceType: kind,
		Created:      created.UTC().Format(time.RFC3339),
		LastModified: updated.UTC().Format(time.RFC3339),
		Location:     loc,
	}
}

func (p *PatchOp) Ops() []PatchOperation {
	if len(p.Operations) > 0 {
		return p.Operations
	}
	return p.OperationsAlt
}
