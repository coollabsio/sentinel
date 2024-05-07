package main

import (
	"context"
	"encoding/json"
	"log"

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
}

func getAllContainers() (string, error) {
	ctx := context.Background()
	apiClient, err := client.NewClientWithOpts()
	if err != nil {
		return "", err
	}
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
