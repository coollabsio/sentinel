package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
)

var httpClient = &http.Client{
	Timeout: time.Second * 10,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	},
}

func setupPushRoute(r *gin.Engine) {
	r.POST("/api/push", func(c *gin.Context) {
		incomingToken := c.GetHeader("Authorization")
		if incomingToken != "Bearer "+token {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			return
		}
		data, err := getPushData()
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, data)
	})
}

func setupPush() {
	go func() {
		ticker := time.NewTicker(time.Duration(pushIntervalSeconds) * time.Second)
		defer ticker.Stop()

		done := make(chan bool)
		go func() {
			sigint := make(chan os.Signal, 1)
			signal.Notify(sigint, os.Interrupt)
			<-sigint
			done <- true
		}()

		for {
			select {
			case <-done:
				fmt.Println("Push operation stopped")
				return
			case <-ticker.C:
				getPushData()
			}
		}
	}()
}

func getPushData() (map[string]interface{}, error) {
	fmt.Printf("[%s] Pushing to [%s]\n", time.Now().Format("2006-01-02 15:04:05"), pushUrl)
	containersData, err := containerData()
	if err != nil {
		log.Printf("Error getting containers data: %v", err)
		return nil, err
	}
	data := map[string]interface{}{
		"containers": containersData,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshalling data: %v", err)
		return nil, err
	}
	req, err := http.NewRequest("POST", pushUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("Error pushing to [%s]: %v", pushUrl, err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Error pushing to [%s]: status code %d, response: %s", pushUrl, resp.StatusCode, string(body))
	}
	return data, nil
}

func containerData() ([]Container, error) {
	ctx := context.Background()
	apiClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("Error getting container data: %v", err)
		return nil, err
	}
	apiClient.NegotiateAPIVersion(ctx)
	defer apiClient.Close()

	containers, err := apiClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		log.Printf("Error getting container data: %v", err)
		return nil, err
	}
	var containersData []Container
	for _, container := range containers {
		inspectData, err := apiClient.ContainerInspect(ctx, container.ID)
		if err != nil {
			log.Printf("Error inspecting container %s: %s", container.ID, err)
			return nil, err
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
	return containersData, nil
}
