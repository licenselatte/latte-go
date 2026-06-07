package ports

type Validator interface {
	Validate(token string, machineID string) (map[string]interface{}, error)
}
