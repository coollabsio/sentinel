package main

import (
	"fmt"
	"log"
	"time"
)

func getUnixTimeInMilliUTC() string {
	queryTimeInUnix := time.Now().UTC().UnixMilli()
	queryTimeInUnixString := fmt.Sprintf("%d", queryTimeInUnix)
	return queryTimeInUnixString
}

func vacuum() {
	go func() {
		_, err := db.Exec("VACUUM")
		if err != nil {
			log.Printf("Error vacuuming: %v", err)
		}
	}()
}
func checkpoint() {
	go func() {
		_, err := db.Exec("CHECKPOINT")
		if err != nil {
			log.Printf("Error checkpointing: %v", err)
		}
	}()
}
