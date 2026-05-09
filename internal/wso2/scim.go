package wso2

type SCIMUserSearch struct {
	Schemas    []string `json:"schemas"`
	Attributes []string `json:"attributes"`
	Domain     string   `json:"domain"`
	Filter     string   `json:"filter"`
	StartIndex int      `json:"startIndex"`
	Count      int      `json:"count"`
}

type SCIMGroupMember struct {
	Display string `json:"display"`
	Value   string `json:"value"`
	Ref     string `json:"$ref"`
}

type SCIMGroup struct {
	ID          string            `json:"id"`
	DisplayName string            `json:"displayName"`
	Members     []SCIMGroupMember `json:"members"`
}

type SCIMUser struct {
	ID       string `json:"id"`
	Username string `json:"userName"`
}

type SCIMListResponse[T any] struct {
	TotalResults int `json:"totalResults"`
	StartIndex   int `json:"startIndex"`
	ItemsPerPage int `json:"itemsPerPage"`
	Resources    []T `json:"Resources"`
}

type SCIMGroupSearch struct {
	Schemas    []string `json:"schemas"`
	StartIndex int      `json:"startIndex"`
	Filter     string   `json:"filter"`
}
type SCIMPatchMember struct {
	Display string `json:"display"`
	Value   string `json:"value"`
}
type SCIMPatchMembers struct {
	Members []SCIMPatchMember `json:"members"`
}
type SCIMPatchOperation struct {
	Op    string           `json:"op"`
	Value SCIMPatchMembers `json:"value"`
}

type SCIMGroupPatch struct {
	Schemas    []string             `json:"schemas"`
	Operations []SCIMPatchOperation `json:"Operations"`
}
