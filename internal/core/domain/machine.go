package domain

import "time"

// Machine is one machine holding a seat on a licence, as the API lists it.
// It identifies a machine for a person to recognise and is never a handle
// for acting on one.
type Machine struct {
	// Name is the machine's name, empty when it has none.
	Name string `json:"machine_name"`
	// Fingerprint is the first 12 characters of the machine id hash.
	Fingerprint string    `json:"machine_fingerprint"`
	ActivatedAt time.Time `json:"activated_at"`
	// LastSeenAt is the machine's last activation or renewal.
	LastSeenAt time.Time `json:"last_seen_at"`
	// SeatFreeAt is set on a released machine whose seat the seller's policy
	// still holds, and is when that seat frees.
	SeatFreeAt *time.Time `json:"seat_free_at"`
	// Current marks the machine the SDK is running on.
	Current bool `json:"current"`
}
