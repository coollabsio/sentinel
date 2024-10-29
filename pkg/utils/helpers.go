package utils

import (
	"fmt"
	"time"
)

func GetUnixTimeInMilliUTC() string {
	queryTimeInUnix := time.Now().UTC().UnixMilli()
	queryTimeInUnixString := fmt.Sprintf("%d", queryTimeInUnix)
	return queryTimeInUnixString
}
