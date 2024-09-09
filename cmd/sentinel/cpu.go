package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sentinel/pkg/db"
	"time"

	"github.com/shirou/gopsutil/cpu"
)

var cpuCsvHeader = "time,usage_percent\n"

type CpuUsage struct {
	Time string `json:"time"`
	// Cpu  string `json:"cpu"`
	// Usage   float64 `json:"usage"`
	// Idle    float64 `json:"idle"`
	// System  float64 `json:"system"`
	// User    float64 `json:"user"`
	Percent string `json:"percent"`
}

func CollectCpuUsage() {
	queryTimeInUnixString := getUnixTimeInMilliUTC()

	overallPercentage, err := cpu.Percent(0, false)
	if err != nil {
		log.Printf("%v", err)
	}
	cpuUsage := CpuUsage{
		Time:    queryTimeInUnixString,
		Percent: fmt.Sprintf("%.2f", overallPercentage[0]),
	}
	db.Write("cpu", int(time.Now().Unix()), cpuUsage)
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
