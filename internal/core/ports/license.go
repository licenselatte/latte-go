package ports

import "context"

type Activator interface {
	Activate(ctx context.Context, key string, machineID string) (string, error)
}
