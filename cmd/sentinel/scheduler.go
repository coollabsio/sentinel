package main

import (
	"context"
	"fmt"
	"log"
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

				CollectMemoryUsage()

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
				CollectDiskUsage()
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
		log.Printf("%v", err)
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

			metrics, err := getContainerMetrics(container.ID, true)
			if err != nil {
				fmt.Printf("Error getting container metrics: %s\n", err)
				return
			}

			containerNameFromLabel, ok := container.Labels["coolify.name"]
			if !ok {
				containerNameFromLabel = container.Names[0][1:]
			}
			_ = containerNameFromLabel

			containerName := "container-" + container.ID
			// log.Printf("%v", containerName)
			db.Write(containerName, int(time.Now().Unix()), metrics)

		}(container)
	}

}
