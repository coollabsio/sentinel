package main

import (
	"log"

	"github.com/coollabsio/sentinel/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
