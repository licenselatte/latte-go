package main

import (
	"errors"
	"fmt"

	"github.com/licenselatte/latte-go"
)

const sdkTestAppKey = "pk_live_G98S8BKDDMZW32RMQM8NZT33E5CTFEDC"

// The following key is always valid and has unlimited activations:
// G98S8-BWAR6-Y0Z7F-JT10A-7EWD9-33265

func main() {
	config := &latte.Config{
		AppID: sdkTestAppKey,
	}

	sdk, err := latte.New(config)
	if err != nil {
		panic(err)
	}

	fmt.Println("Type your license key: (e.g. XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX)")

	var input string
	_, _ = fmt.Scanln(&input)

	license, err := sdk.Activate(input)
	if err != nil {
		fmt.Println("Activation error:", err)
		return
	}
	fmt.Println("License activated! Token:", license)

	machines, err := sdk.Machines()
	if err != nil {
		fmt.Println("Machine list error:", err)
		return
	}
	for _, m := range machines {
		fmt.Printf("  %s %s (last seen %s) current=%v\n", m.Fingerprint, m.Name, m.LastSeenAt.Format("2006-01-02"), m.Current)
	}

	fmt.Println("Release this machine so the licence can move to another one? [y/N]")
	var answer string
	_, _ = fmt.Scanln(&answer)
	if answer != "y" {
		return
	}
	result, err := sdk.Deactivate()
	var blocked *latte.DeactivationBlockedError
	switch {
	case errors.As(err, &blocked):
		fmt.Println(blocked.Message)
	case err != nil:
		fmt.Println("Deactivation failed, nothing was changed; try again when online:", err)
	case result.SeatFreeAt != nil:
		fmt.Println("Released. The seat can be used on another machine from", result.SeatFreeAt.Local())
	default:
		fmt.Println("Released. Activate the licence on your other machine.")
	}
}
