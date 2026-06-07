package ports

type Storage interface {
	SaveToken(token string) error
	LoadToken() (string, error)
}
