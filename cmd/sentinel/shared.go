package main

import (
	"fmt"
	"strconv"
	"time"
)

func getUnixTimeInNanoUTC() string {
	queryTimeInUnix := time.Now().UTC().UnixNano()
	queryTimeInUnixString := fmt.Sprintf("%d", queryTimeInUnix)
	return queryTimeInUnixString
}

func getUnixTimeInMilliUTC() string {
	queryTimeInUnix := time.Now().UTC().UnixMilli()
	queryTimeInUnixString := fmt.Sprintf("%d", queryTimeInUnix)
	return queryTimeInUnixString
}

func ParseFromTo(tmpfrom, tmpto string) (int, int, error) {

	if tmpfrom == "" {
		tmpfrom = "0"
	}
	if tmpto == "" {
		tmpto = fmt.Sprintf("%d", time.Now().Unix())
	}
	from, errFrom := strconv.Atoi(tmpfrom)
	to, errTo := strconv.Atoi(tmpto)
	if errFrom != nil || errTo != nil {
		return 0, 0, fmt.Errorf("invalid from or to")
	}
	return from, to, nil
}
