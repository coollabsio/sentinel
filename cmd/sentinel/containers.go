package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type Container struct {
	ID           string            `json:"id"`
	Image        string            `json:"image"`
	Name         string            `json:"name"`
	State        string            `json:"state"`
	Labels       map[string]string `json:"labels"`
	HealthStatus string            `json:"health_status"`
	Metrics      ContainerMetrics  `json:"metrics"`
}

type ContainerMetrics struct {
	CPUUsagePercentage    float64       `json:"cpu_usage_percentage"`
	MemoryUsagePercentage float64       `json:"memory_usage_percentage"`
	MemoryUsed            uint64        `json:"memory_used"`
	MemoryAvailable       uint64        `json:"available_memory"`
	NetworkUsage          NetworkDevice `json:"network_usage_in"`
}
type NetworkDevice struct {
	Name    string `json:"name"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

func getAllContainers() (string, error) {
	ctx := context.Background()
	apiClient, err := client.NewClientWithOpts()
	if err != nil {
		return "", err
	}
	apiClient.NegotiateAPIVersion(ctx)
	defer apiClient.Close()

	containers, err := apiClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return "", err
	}
	var containersData []Container
	for _, container := range containers {
		inspectData, err := apiClient.ContainerInspect(ctx, container.ID)
		if err != nil {
			log.Fatalf("Error inspecting container %s: %s", container.ID, err)
			return "", err
		}
		healthStatus := "unhealthy"
		if inspectData.State.Health != nil {
			healthStatus = inspectData.State.Health.Status
		}
		// Get container stats
		metrics := ContainerMetrics{
			CPUUsagePercentage:    0,
			MemoryUsagePercentage: 0,
			MemoryUsed:            0,
			MemoryAvailable:       0,
			NetworkUsage:          NetworkDevice{},
		}
		if container.State == "running" {
			stats, err := apiClient.ContainerStatsOneShot(ctx, container.ID)
			if err != nil {
				fmt.Printf("Error getting container stats: %v\n", err)
				continue
			}
			var v *types.StatsJSON
			dec := json.NewDecoder(stats.Body)
			if err := dec.Decode(&v); err != nil {
				if err != io.EOF {
					fmt.Printf("Error decoding container stats: %v\n", err)
				}
			}
			network_devices := v.Networks
			for _, device := range network_devices {
				metrics.NetworkUsage = NetworkDevice{
					Name:    device.InstanceID,
					RxBytes: device.RxBytes,
					TxBytes: device.TxBytes,
				}
			}

			metrics = ContainerMetrics{
				CPUUsagePercentage:    calculateCPUPercent(v),
				MemoryUsagePercentage: calculateMmemoryPercent(v),
				MemoryUsed:            v.MemoryStats.Usage,
				MemoryAvailable:       v.MemoryStats.Limit,
				NetworkUsage:          metrics.NetworkUsage,
			}
		}

		containersData = append(containersData, Container{
			ID:           container.ID,
			Image:        container.Image,
			Labels:       container.Labels,
			Name:         container.Names[0][1:],
			State:        container.State,
			HealthStatus: healthStatus,
			Metrics:      metrics,
		})
	}
	jsonData, err := json.MarshalIndent(containersData, "", "    ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil

}
func calculateCPUPercent(stat *types.StatsJSON) float64 {
	cpuPercent := 0.0
	cpuDelta := float64(stat.CPUStats.CPUUsage.TotalUsage) - float64(stat.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stat.CPUStats.SystemUsage) - float64(stat.PreCPUStats.SystemUsage)
	if systemDelta > 0.0 {
		cpuPercent = (cpuDelta / systemDelta) * float64(len(stat.CPUStats.CPUUsage.PercpuUsage)) * 100.0
	}
	return cpuPercent
}

func calculateMmemoryPercent(stat *types.StatsJSON) float64 {
	usageMemory := float64(stat.MemoryStats.Usage)
	cachedMemory := float64(stat.MemoryStats.Stats["cache"])
	availableMemory := float64(stat.MemoryStats.Limit)
	usedMemory := usageMemory - cachedMemory
	usedMemoryPercentage := (usedMemory / availableMemory) * 100
	return usedMemoryPercentage
}
