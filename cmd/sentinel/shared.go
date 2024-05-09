package main

import (
	"fmt"
	"time"
)

func getUnixTimeInNanoUTC() string {
	queryTimeInUnix := time.Now().UTC().UnixNano()
	queryTimeInUnixString := fmt.Sprintf("%d", queryTimeInUnix)
	return queryTimeInUnixString
}
