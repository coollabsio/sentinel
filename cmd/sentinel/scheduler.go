package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
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
				// filesystemMetrics()
				memoryMetrics()
				cleanupMetricsData()
				// cleanupLogsData()
			},
		),
	)
	if err != nil {
		fmt.Printf("Error creating scheduler: %s", err)
		return
	}
	s.Start()
}

func cleanupLogsData() {
	// If the files are too big, we can remove old logs

	// currentTime := time.Now()
	// minutesAgo := currentTime.Add(-1440 * time.Minute)
	// files, err := os.ReadDir(logsDir)
	// if err != nil {
	// 	fmt.Printf("Error reading directory: %s", err)
	// 	return
	// }
	// for _, file := range files {
	// 	lines, err := os.ReadFile(fmt.Sprintf("%s/%s", logsDir, file.Name()))
	// 	if err != nil {
	// 		fmt.Printf("Error reading file: %s", err)
	// 		return
	// 	}
	// 	for _, line := range strings.Split(string(lines), "\n") {
	// 		stringTime := strings.Split(line, " ")[0]
	// 		if stringTime == "" {
	// 			continue
	// 		}
	// 		timeRfc, err := time.Parse(time.RFC3339, stringTime)
	// 		if err != nil {
	// 			fmt.Printf("Error parsing time: %s", err)
	// 			continue
	// 		}
	// 		timeInt := timeRfc.UnixNano() / int64(time.Millisecond)
	// 		if time.UnixMilli(timeInt).Before(minutesAgo) {
	// 			lines = []byte(strings.ReplaceAll(string(lines), line, ""))
	// 			lines = []byte(strings.ReplaceAll(string(lines), "\n\n", "\n"))
	// 			err := os.WriteFile(fmt.Sprintf("%s/%s", logsDir, file.Name()), lines, 0644)
	// 			if err != nil {
	// 				fmt.Printf("Error writing file: %s", err)
	// 				continue
	// 			}
	// 		}
	// 	}
	// }
}

func cleanupMetricsData() {
	currentTime := time.Now()
	minutesAgo := currentTime.Add(time.Duration(-metricsHistoryInMinutes) * time.Minute)
	files, err := os.ReadDir(metricsDir)
	if err != nil {
		fmt.Printf("Error reading directory: %s", err)
		return
	}
	for _, file := range files {
		lines, err := os.ReadFile(fmt.Sprintf("%s/%s", metricsDir, file.Name()))
		if err != nil {
			fmt.Printf("Error reading file: %s", err)
			return
		}
		for _, line := range strings.Split(string(lines), "\n") {
			if strings.Contains(line, "time") {
				continue
			}
			if line == "" {
				continue
			}
			timeString := strings.Split(line, ",")[0]
			timeInt, err := strconv.ParseInt(timeString, 10, 64)
			if err != nil {
				fmt.Printf("Error parsing time: %s", err)
				return
			}
			if time.UnixMilli(timeInt).Before(minutesAgo) {
				// fmt.Println("removing line")
				// fmt.Println(line)
				lines = []byte(strings.ReplaceAll(string(lines), line, ""))
				lines = []byte(strings.ReplaceAll(string(lines), "\n\n", "\n"))
				err := os.WriteFile(fmt.Sprintf("%s/%s", metricsDir, file.Name()), lines, 0644)
				if err != nil {
					fmt.Printf("Error writing file: %s", err)
					return
				}
			}
		}
	}
}

func cpuMetrics() {
	out, err := getCpuUsage(true)
	if err != nil {
		fmt.Printf("Error getting containers: %s", err)
		return
	}
	filepath := fmt.Sprintf(cpuMetricsFile)
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
