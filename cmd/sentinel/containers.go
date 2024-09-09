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

var containerMetricsCsvHeader = "time,cpu_usage_percent,memory_usage,memory_usage_percent\n"
var containerConfigCsvHeader = "time,id,image,name,state,health_status\n"

type Container struct {
	Time         string            `json:"time"`
	ID           string            `json:"id"`
	Image        string            `json:"image"`
	Name         string            `json:"name"`
	State        string            `json:"state"`
	Labels       map[string]string `json:"labels"`
	HealthStatus string            `json:"health_status"`
}

type ContainerMetrics struct {
	Time                  string        `json:"time"`
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

func getOneContainer(containerID string, csv bool) (string, error) {
	ctx := context.Background()
	apiClient, err := client.NewClientWithOpts()
	if err != nil {
		return "", err
	}
	apiClient.NegotiateAPIVersion(ctx)
	defer apiClient.Close()
	container, err := apiClient.ContainerInspect(ctx, containerID)
	if err != nil {
		log.Fatalf("Error inspecting container %s: %s", containerID, err)
		return "", err
	}
	healthStatus := "unhealthy"
	if container.State.Health != nil {
		healthStatus = container.State.Health.Status
	}

	containersData := Container{
		Time:         getUnixTimeInMilliUTC(),
		ID:           container.ID,
		Image:        container.Config.Image,
		Labels:       container.Config.Labels,
		Name:         container.Name[1:],
		State:        container.State.Status,
		HealthStatus: healthStatus,
	}
	jsonData, err := json.MarshalIndent(containersData, "", "    ")
	if err != nil {
		return "", err
	}
	if csv {
		return fmt.Sprintf("%s,%s,%s,%s,%s,%s\n", containersData.Time, containersData.ID, containersData.Image, containersData.Name, containersData.State, containersData.HealthStatus), nil

	}
	return string(jsonData), nil

}

func getContainerMetrics(containerID string, csv bool) (*ContainerMetrics, error) {
	ctx := context.Background()
	apiClient, err := client.NewClientWithOpts()
	if err != nil {
		return nil, err
	}
	apiClient.NegotiateAPIVersion(ctx)
	defer apiClient.Close()
	metrics := ContainerMetrics{
		CPUUsagePercentage:    0,
		MemoryUsagePercentage: 0,
		MemoryUsed:            0,
		MemoryAvailable:       0,
		NetworkUsage:          NetworkDevice{},
	}
	container, err := apiClient.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, err
	}
	stats, err := apiClient.ContainerStats(ctx, container.ID, false)
	if err != nil {
		return nil, err
	}
	var v types.StatsJSON
	dec := json.NewDecoder(stats.Body)
	if err := dec.Decode(&v); err != nil {
		if err != io.EOF {
			fmt.Printf("Error decoding container stats: %v\n", err)
		}
	}
	defer stats.Body.Close()
	network_devices := v.Networks
	for _, device := range network_devices {
		metrics.NetworkUsage = NetworkDevice{
			Name:    device.InstanceID,
			RxBytes: device.RxBytes,
			TxBytes: device.TxBytes,
		}
	}

	metrics = ContainerMetrics{
		Time:                  getUnixTimeInMilliUTC(),
		CPUUsagePercentage:    calculateCPUPercent(v),
		MemoryUsagePercentage: calculateMemoryPercent(v),
		MemoryUsed:            calculateMemoryUsed(v),
		MemoryAvailable:       v.MemoryStats.Limit,
		NetworkUsage:          metrics.NetworkUsage,
	}

	return &metrics, nil
}

func getOneContainerMetrics(containerID string, csv bool) (string, error) {

	metrics, err := getContainerMetrics(containerID, csv)
	if err != nil {
		return "", err
	}

	jsonData, err := json.MarshalIndent(metrics, "", "    ")
	if err != nil {
		return "", err
	}
	if csv {
		return fmt.Sprintf("%s,%f,%d,%f\n", metrics.Time, metrics.CPUUsagePercentage, metrics.MemoryUsed, metrics.MemoryUsagePercentage), nil
	}
	return string(jsonData), nil
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

		containersData = append(containersData, Container{
			ID:           container.ID,
			Image:        container.Image,
			Labels:       container.Labels,
			Name:         container.Names[0][1:],
			State:        container.State,
			HealthStatus: healthStatus,
		})
	}
	jsonData, err := json.MarshalIndent(containersData, "", "    ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil

}
func calculateCPUPercent(stat types.StatsJSON) float64 {
	cpuDelta := float64(stat.CPUStats.CPUUsage.TotalUsage) - float64(stat.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stat.CPUStats.SystemUsage) - float64(stat.PreCPUStats.SystemUsage)
	numberOfCpus := stat.CPUStats.OnlineCPUs
	return (cpuDelta / systemDelta) * float64(numberOfCpus) * 100.0
}

func calculateMemoryPercent(stat types.StatsJSON) float64 {
	usedMemory := float64(stat.MemoryStats.Usage) - float64(stat.MemoryStats.Stats["cache"])
	availableMemory := float64(stat.MemoryStats.Limit)
	return (usedMemory / availableMemory) * 100.0
}
func calculateMemoryUsed(stat types.StatsJSON) uint64 {
	return (stat.MemoryStats.Usage) / 1024 / 1024
}
