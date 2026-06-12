package main

import (
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
	} else {
		fmt.Println("License activated! Token:", license)
	}
}
