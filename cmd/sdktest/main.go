package main

import (
	"context"
	"fmt"
	"time"

	latte "github.com/licenselatte/sdk-go"
)

const latteAppId = "pk_local_AHAK85389VQYXYB6S4BW66SKE53TWVTS"

func main() {
	sdk, err := latte.New(&latte.Config{
		AppID: latteAppId,
	})
	if err != nil {
		panic(err)
	}

	const licenseKey = "AHAK856T8PQS0245KDB1FEC9VXA998"

	token, err := sdk.Activate(licenseKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(token)

	for {
		ticker := time.NewTicker(time.Second * 1)
		select {
		case <-context.Background().Done():
			return
		case <-ticker.C:
			continue
		}
	}
}
