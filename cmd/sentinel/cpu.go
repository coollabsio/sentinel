package main

import (
	"encoding/json"
	"fmt"

	"github.com/shirou/gopsutil/cpu"
)

type CpuUsage struct {
	Cpu     string  `json:"cpu"`
	Usage   float64 `json:"usage"`
	Idle    float64 `json:"idle"`
	System  float64 `json:"system"`
	User    float64 `json:"user"`
	Percent string  `json:"percent"`
}

func getCpuUsage() (string, error) {
	times, err := cpu.Times(true)
	if err != nil {
		fmt.Println("Failed to get CPU times:", err)
		return "", err
	}
	percentage, err := cpu.Percent(0, true)
	if err != nil {
		fmt.Println("Failed to get CPU percentage:", err)
		return "", err
	}

	usages := make([]CpuUsage, len(times))
	for i, time := range times {
		usages[i] = CpuUsage{
			Cpu:     fmt.Sprintf("%d", i),
			Usage:   time.Total(),
			Idle:    time.Idle,
			System:  time.System,
			User:    time.User,
			Percent: fmt.Sprintf("%.2f%%", percentage[i]),
		}
	}
	overallPercentage, err := cpu.Percent(0, false)
	if err != nil {
		fmt.Println("Failed to get overall CPU percentage:", err)
		return "", err
	}
	usages = append(usages, CpuUsage{
		Cpu:     "Overall",
		Percent: fmt.Sprintf("%.2f%%", overallPercentage[0]),
	})

	jsonData, err := json.MarshalIndent(usages, "", "    ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil

}
