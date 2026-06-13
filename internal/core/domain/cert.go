package domain

type CertChain struct {
	Submaster string `json:"submaster"`
	Project   string `json:"project"`
	Daily     string `json:"daily"`
}
