package main

import (
	"fmt"
	"os"
	"time"

	"github.com/go-co-op/gocron/v2"
)

func scheduler() {
	s, err := gocron.NewScheduler()
	if err != nil {
		fmt.Printf("Error creating scheduler: %s", err)
		return
	}

	_, err = s.NewJob(
		gocron.DurationJob(
			time.Duration(refreshRateSeconds)*time.Second,
		),
		gocron.NewTask(
			func() {
				cpuMetrics()
				filesystemMetrics()
				memoryMetrics()
			},
		),
	)
	if err != nil {
		fmt.Printf("Error creating scheduler: %s", err)
		return
	}
	s.Start()
}

func cpuMetrics() {
	out, err := getCpuUsage(true)
	if err != nil {
		fmt.Printf("Error getting containers: %s", err)
		return
	}
	filepath := fmt.Sprintf("%s/cpu.csv", metricsDir)
	_, err = os.Stat(filepath)
	if err != nil {
		err := os.WriteFile(filepath, []byte(cpuCsvHeader), 0644)
		if err != nil {
			fmt.Printf("Error writing file: %s", err)
			return
		}
	}

	f, err := os.OpenFile(filepath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %s", err)
		return
	}
	defer f.Close()
	_, err = f.WriteString(out)
	if err != nil {
		fmt.Printf("Error writing to file: %s", err)
		return
	}
}
func filesystemMetrics() {
	out, err := getCpuUsage(true)
	if err != nil {
		fmt.Printf("Error getting filesystem usage: %s", err)
		return
	}
	filepath := fmt.Sprintf("%s/filesystem.csv", metricsDir)
	_, err = os.Stat(filepath)
	if err != nil {
		err := os.WriteFile(filepath, []byte(cpuCsvHeader), 0644)
		if err != nil {
			fmt.Printf("Error writing file: %s", err)
			return
		}
	}

	// open file in append mode and write out to it
	f, err := os.OpenFile(filepath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %s", err)
		return
	}
	defer f.Close()
	_, err = f.WriteString(out)
	if err != nil {
		fmt.Printf("Error writing to file: %s", err)
		return
	}
}
func memoryMetrics() {
	out, err := getMemUsage(true)
	if err != nil {
		fmt.Printf("Error getting memory usage: %s", err)
		return
	}
	filepath := fmt.Sprintf("%s/memory.csv", metricsDir)
	_, err = os.Stat(filepath)
	if err != nil {
		err := os.WriteFile(filepath, []byte(memoryCsvHeader), 0644)
		if err != nil {
			fmt.Printf("Error writing file: %s", err)
			return
		}
	}

	// open file in append mode and write out to it
	f, err := os.OpenFile(filepath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %s", err)
		return
	}
	defer f.Close()
	_, err = f.WriteString(out)
	if err != nil {
		fmt.Printf("Error writing to file: %s", err)
		return
	}
}
