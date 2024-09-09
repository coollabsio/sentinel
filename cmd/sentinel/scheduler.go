package main

import (
	"context"
	"fmt"
	"os"
	"sentinel/pkg/db"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/go-co-op/gocron/v2"
)

func scheduler() {
	s, err := gocron.NewScheduler()
	if err != nil {
		fmt.Printf("Error creating scheduler: %s", err)
		return
	}
	disk, err := gocron.NewScheduler()
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
				CollectCpuUsage()
				CollectDiskUsage()
				CollectMemoryUsage()
				// cpuMetrics()
				// memoryMetrics()
				cleanupMetricsData()
				containerMetrics()
			},
		),
	)
	if err != nil {
		fmt.Printf("Error creating scheduler: %s", err)
		return
	}
	_, err = disk.NewJob(
		gocron.DurationJob(
			time.Duration(1)*time.Minute,
		),
		gocron.NewTask(
			func() {
				diskMetrics()
			},
		),
	)
	if err != nil {
		fmt.Printf("Error creating scheduler: %s", err)
		return
	}
	s.Start()
	disk.Start()
}

func cleanupMetricsData() {
	currentTime := time.Now()
	minutesAgo := currentTime.Add(time.Duration(-metricsHistoryInDays) * time.Hour * 24).Unix()

	db.DeleteOlderThan("cpu", int(minutesAgo))
	db.DeleteOlderThan("memory", int(minutesAgo))
	db.DeleteOlderThan("disk", int(minutesAgo))
}

func containerMetrics() {
	ctx := context.Background()
	apiClient, err := client.NewClientWithOpts()
	if err != nil {
		return
	}
	apiClient.NegotiateAPIVersion(ctx)
	defer apiClient.Close()

	containers, err := apiClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		fmt.Printf("Error getting containers: %s", err)
		return
	}

	for _, container := range containers {
		if container.Image == "ghcr.io/coollabsio/coolify-helper:latest" {
			continue
		}
		go func(cont types.Container) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("Recovered from panic: %v\n", r)
				}
			}()

			metrics, err := getOneContainerMetrics(container.ID, true)
			if err != nil {
				fmt.Printf("Error getting container metrics: %s\n", err)
				return
			}

			containerNameFromLabel := container.Labels["coolify.name"]
			if containerNameFromLabel == "" {
				containerNameFromLabel = container.Names[0][1:]
			}
			containerName := "container-" + containerNameFromLabel
			containerMetricsFile := fmt.Sprintf("%s/%s.csv", metricsDir, containerName)

			_, err = os.Stat(containerMetricsFile)
			if err != nil && os.IsNotExist(err) {
				err := os.WriteFile(containerMetricsFile, []byte(containerMetricsCsvHeader), 0644)
				if err != nil {
					fmt.Printf("Error writing file: %s\n", err)
					return
				}
			}

			f, err := os.OpenFile(containerMetricsFile, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Printf("Error opening file: %s\n", err)
				return
			}
			defer f.Close()

			_, err = f.WriteString(metrics)
			if err != nil {
				fmt.Printf("Error writing to file: %s\n", err)
				return
			}
		}(container)
	}

}
func cpuMetrics() {
	out, err := getCpuUsage(true)
	if err != nil {
		fmt.Printf("Error getting containers: %s", err)
		return
	}
	_, err = os.Stat(cpuMetricsFile)
	if err != nil {
		err := os.WriteFile(cpuMetricsFile, []byte(cpuCsvHeader), 0644)
		if err != nil {
			fmt.Printf("Error writing file: %s", err)
			return
		}
	}

	f, err := os.OpenFile(cpuMetricsFile, os.O_APPEND|os.O_WRONLY, 0644)
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
func diskMetrics() {
	out, err := getDiskUsage(true)
	if err != nil {
		fmt.Printf("Error getting filesystem usage: %s", err)
		return
	}
	_, err = os.Stat(diskMetricsFile)
	if err != nil {
		err := os.WriteFile(diskMetricsFile, []byte(diskCsvHeader), 0644)
		if err != nil {
			fmt.Printf("Error writing file: %s", err)
			return
		}
	}

	// open file in append mode and write out to it
	f, err := os.OpenFile(diskMetricsFile, os.O_APPEND|os.O_WRONLY, 0644)
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
	_, err = os.Stat(memoryMetricsFile)
	if err != nil {
		err := os.WriteFile(memoryMetricsFile, []byte(memoryCsvHeader), 0644)
		if err != nil {
			fmt.Printf("Error writing file: %s", err)
			return
		}
	}

	// open file in append mode and write out to it
	f, err := os.OpenFile(memoryMetricsFile, os.O_APPEND|os.O_WRONLY, 0644)
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
