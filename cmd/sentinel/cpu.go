package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/cpu"
)

var cpuCsvHeader = "time,percent\n"

type CpuUsage struct {
	Time string `json:"time"`
	// Cpu  string `json:"cpu"`
	// Usage   float64 `json:"usage"`
	// Idle    float64 `json:"idle"`
	// System  float64 `json:"system"`
	// User    float64 `json:"user"`
	Percent string `json:"percent"`
}

func getCpuUsage(csv bool) (string, error) {
	usages := make([]CpuUsage, 0)
	queryTimeInUnixString := getUnixTimeInMilliUTC()
	overallPercentage, err := cpu.Percent(0, false)
	if err != nil {
		fmt.Println("Failed to get overall CPU percentage:", err)
		return "", err
	}
	usages = append(usages, CpuUsage{
		Time: queryTimeInUnixString,
		// Cpu:     "Overall",
		Percent: fmt.Sprintf("%.2f", overallPercentage[0]),
	})

	jsonData, err := json.MarshalIndent(usages, "", "    ")
	if err != nil {
		return "", err
	}

	if csv {
		var csvData string
		for _, usage := range usages {
			// csvData += fmt.Sprintf("%s,%s,%f,%f,%f,%f,%s\n", usage.Time, usage.Cpu, usage.Usage, usage.Idle, usage.System, usage.User, usage.Percent)
			csvData += fmt.Sprintf("%s,%s\n", usage.Time, usage.Percent)
		}
		return csvData, nil
	}
	return string(jsonData), nil

}

func getHistoryCpuUsage(from string, to string) (string, error) {
	if from == "" && to == "" {
		// return everything
		file, err := os.ReadFile(cpuMetricsFile)
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
	file, err := os.ReadFile(cpuMetricsFile)
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
		if len(parts) != 2 {
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
	result = cpuCsvHeader + result
	return result, nil

}
