package main

import (
	"log"

	"github.com/ElecTwix/passmaster/pkg/chrome"
)

func main() {
	err := chrome.Start()
	log.Fatal(err)
}
