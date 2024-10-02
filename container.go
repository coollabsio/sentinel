package main

import (
	"context"
	"log"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
)

type Container struct {
	Time         string            `json:"time"`
	ID           string            `json:"id"`
	Image        string            `json:"image"`
	Name         string            `json:"name"`
	State        string            `json:"state"`
	Labels       map[string]string `json:"labels"`
	HealthStatus string            `json:"health_status"`
}

func setupContainerRoutes(r *gin.Engine) {
	r.GET("/api/containers", func(c *gin.Context) {
		ctx := context.Background()
		apiClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		apiClient.NegotiateAPIVersion(ctx)
		defer apiClient.Close()

		containers, err := apiClient.ContainerList(ctx, container.ListOptions{All: true})
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		var containersData []Container
		for _, container := range containers {
			inspectData, err := apiClient.ContainerInspect(ctx, container.ID)
			if err != nil {
				log.Fatalf("Error inspecting container %s: %s", container.ID, err)
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			healthStatus := "unhealthy"
			if inspectData.State.Health != nil {
				healthStatus = inspectData.State.Health.Status
			}

			containersData = append(containersData, Container{
				Time:         time.Now().Format("2006-01-02T15:04:05Z"),
				ID:           container.ID,
				Image:        container.Image,
				Labels:       container.Labels,
				Name:         container.Names[0][1:],
				State:        container.State,
				HealthStatus: healthStatus,
			})
		}
		c.JSON(200, containersData)
	})
}
