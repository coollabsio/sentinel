package push

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"syscall"
	"time"

	"github.com/coollabsio/sentinel/pkg/config"
	"github.com/coollabsio/sentinel/pkg/dockerClient"
	"github.com/coollabsio/sentinel/pkg/json"
	"github.com/coollabsio/sentinel/pkg/types"
	dockerContainer "github.com/docker/docker/api/types/container"
)

type Pusher struct {
	config       *config.Config
	client       *http.Client
	dockerClient *dockerClient.DockerClient
}

func New(config *config.Config, dockerClient *dockerClient.DockerClient) *Pusher {
	return &Pusher{
		config: config,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: 10 * time.Second,
		},
		dockerClient: dockerClient,
	}
}

func (p *Pusher) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(p.config.PushIntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Push operation stopped")
			return
		case <-ticker.C:
			p.GetPushData()
		}
	}
}

func (p *Pusher) GetPushData() (map[string]interface{}, error) {
	fmt.Printf("[%s] Pushing to [%s]\n", time.Now().Format("2006-01-02 15:04:05"), p.config.PushUrl)
	containersData, err := p.containerData()
	if err != nil {
		log.Printf("Error getting containers data: %v", err)
		return nil, err
	}
	filesystemUsageRoot, err := filesystemUsageRoot()
	if err != nil {
		log.Printf("Error getting disk usage: %v", err)
		return nil, err
	}
	data := map[string]interface{}{
		"containers":            containersData,
		"filesystem_usage_root": filesystemUsageRoot,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshalling data: %v", err)
		return nil, err
	}
	req, err := http.NewRequest("POST", p.config.PushUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.config.Token)
	resp, err := p.client.Do(req)
	if err != nil {
		log.Printf("Error pushing to [%s]: %v", p.config.PushUrl, err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("Error pushing to [%s]: status code %d", p.config.PushUrl, resp.StatusCode)
	}
	return data, nil
}

func filesystemUsageRoot() (map[string]interface{}, error) {
	fs := syscall.Statfs_t{}
	err := syscall.Statfs("/", &fs)
	if err != nil {
		return nil, err
	}
	totalSpace := fs.Blocks * uint64(fs.Bsize)
	freeSpace := fs.Bfree * uint64(fs.Bsize)
	usedSpace := totalSpace - freeSpace
	usedPercentage := float64(usedSpace) / float64(totalSpace) * 100

	return map[string]interface{}{
		"used_percentage": fmt.Sprintf("%d", int(usedPercentage)),
	}, nil
}

func (p *Pusher) containerData() ([]types.Container, error) {
	resp, err := p.dockerClient.MakeRequest("/containers/json?all=true")
	if err != nil {
		log.Printf("Error getting containers: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	containersOutput, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading containers response: %v", err)
		return nil, err
	}

	var containers []dockerContainer.Summary
	if err := json.Unmarshal(containersOutput, &containers); err != nil {
		log.Printf("Error unmarshalling container list: %v", err)
		return nil, err
	}

	var containersData []types.Container
	for _, container := range containers {
		resp, err := p.dockerClient.MakeRequest(fmt.Sprintf("/containers/%s/json", container.ID))
		if err != nil {
			log.Printf("Error inspecting container %s: %v", container.ID, err)
			continue
		}
		if resp == nil {
			log.Printf("Error: nil response when inspecting container %s", container.ID)
			continue
		}
		if resp.Body == nil {
			log.Printf("Error: nil response body when inspecting container %s", container.ID)
			continue
		}
		defer resp.Body.Close()

		inspectOutput, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Error reading inspect response for container %s: %v", container.ID, err)
			continue
		}
		if len(inspectOutput) == 0 {
			log.Printf("Warning: Empty inspect response for container %s", container.ID)
			continue
		}

		var inspectData dockerContainer.InspectResponse
		if err := json.Unmarshal(inspectOutput, &inspectData); err != nil {
			log.Printf("Error unmarshalling inspect data for container %s: %v", container.ID, err)
			continue
		}

		healthStatus := "unknown"
		if inspectData.ContainerJSONBase != nil && inspectData.State != nil && inspectData.State.Health != nil {
			healthStatus = inspectData.State.Health.Status
		} else if inspectData.ContainerJSONBase == nil {
			log.Printf("Warning: Container %s has nil ContainerJSONBase (possibly corrupted/dead)", container.ID)
		} else if inspectData.State == nil {
			log.Printf("Warning: Container %s has nil State (possibly corrupted/dead)", container.ID)
		}

		// Safe name extraction with bounds checking
		containerName := ""
		if len(container.Names) > 0 && len(container.Names[0]) > 1 {
			containerName = container.Names[0][1:] // Remove leading '/'
		} else if len(container.Names) > 0 {
			containerName = container.Names[0]
		} else {
			containerName = container.ID[:12] // Use short ID as fallback
			log.Printf("Warning: Container %s has no names, using ID as name", container.ID)
		}

		containersData = append(containersData, types.Container{
			Time:         time.Now().Format("2006-01-02T15:04:05Z"),
			ID:           container.ID,
			Image:        container.Image,
			Labels:       container.Labels,
			Name:         containerName,
			State:        container.State,
			HealthStatus: healthStatus,
		})
	}
	return containersData, nil
}
