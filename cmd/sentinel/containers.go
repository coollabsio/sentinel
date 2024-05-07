package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func getAllContainers() (string, error) {
	ctx := context.Background()
	apiClient, err := client.NewClientWithOpts()
	if err != nil {
		panic(err)
	}
	defer apiClient.Close()

	containers, err := apiClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		panic(err)
	}

	jsonData, err := json.Marshal(containers)
	if err != nil {
		log.Fatalf("Error marshalling containers to JSON: %s", err)
	}

	return string(jsonData), nil
}
