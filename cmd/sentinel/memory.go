package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/mem"
)

var memoryCsvHeader = "time,used,free,used_percent\n"

type MemUsage struct {
	Time        string  `json:"time"`
	Total       uint64  `json:"total"`
	Available   uint64  `json:"available"`
	Used        uint64  `json:"used"`
	UsedPercent float64 `json:"usedPercent"`
	Free        uint64  `json:"free"`
}

func getMemUsage(csv bool) (string, error) {
	memory, err := mem.VirtualMemory()
	if err != nil {
		fmt.Println("Failed to get memory usage:", err)
		return "", err
	}
	queryTimeInUnixString := getUnixTimeInMilliUTC()
	usages := MemUsage{
		Time:        queryTimeInUnixString,
		Total:       memory.Total,
		Available:   memory.Available,
		Used:        memory.Used,
		UsedPercent: memory.UsedPercent,
		Free:        memory.Free,
	}
	jsonData, err := json.MarshalIndent(usages, "", "    ")
	if err != nil {
		return "", err
	}
	if csv {
		return fmt.Sprintf("%s,%d,%d,%.2f\n", queryTimeInUnixString, memory.Used, memory.Free, memory.UsedPercent), nil
	}

	return string(jsonData), nil

}

func getHistoryMemoryUsage(from string, to string) (string, error) {
	if from == "" && to == "" {
		// return everything
		file, err := os.ReadFile(memoryMetricsFile)
		if err != nil {
			fmt.Println("Failed to read file:", err)
			return "", err
		}
		return string(file), nil
	}
	if from == "" {
		from = "1970-01-01T00:00:00Z"
	}
	if to == "" {
		to = time.Now().UTC().Format(time.RFC3339)
	}
	fromTime, err := time.Parse(time.RFC3339, from)
	if err != nil {
		fmt.Println("Failed to parse from time:", err)
		return "", err
	}
	toTime, err := time.Parse(time.RFC3339, to)
	if err != nil {
		fmt.Println("Failed to parse to time:", err)
		return "", err
	}

	fromTimeUnix := fromTime.UnixMilli()
	toTimeUnix := toTime.UnixMilli()
	file, err := os.ReadFile(memoryMetricsFile)
	if err != nil {
		fmt.Println("Failed to read file:", err)
		return "", err
	}
	lines := string(file)
	var result string
	lines = lines[strings.Index(lines, "\n")+1:]
	for _, line := range strings.Split(lines, "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 4 {
			fmt.Println("Invalid line:", line)
			continue
		}
		time, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			fmt.Println("Failed to parse time:", err)
			continue
		}
		if time >= fromTimeUnix && time <= toTimeUnix {
			result += line + "\n"
		}
	}
	result = memoryCsvHeader + result
	return result, nil

}
