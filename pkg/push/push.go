package push

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coollabsio/sentinel/pkg/config"
	"github.com/coollabsio/sentinel/pkg/json"
	"github.com/coollabsio/sentinel/pkg/types"
	dockerContainer "github.com/docker/docker/api/types/container"
)

type Pusher struct {
	config       *config.Config
	client       *http.Client
	dockerClient dockerAPI
}

type dockerAPI interface {
	MakeRequest(context.Context, string) (*http.Response, error)
}

func New(config *config.Config, dockerClient dockerAPI) *Pusher {
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
			if _, err := p.GetPushData(ctx); err != nil {
				log.Printf("Push operation failed: %v", err)
			}
		}
	}
}

func (p *Pusher) GetPushData(ctx context.Context) (map[string]interface{}, error) {
	fmt.Printf("[%s] Pushing to [%s]\n", time.Now().Format("2006-01-02 15:04:05"), p.config.PushUrl)
	containersData, inspectionFailures, err := p.containerData(ctx)
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
		"snapshot":              newSnapshotMetadata(inspectionFailures > 0, inspectionFailures),
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshalling data: %v", err)
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.PushUrl, bytes.NewBuffer(jsonData))
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return nil, fmt.Errorf("push to %s returned %s: %s", p.config.PushUrl, resp.Status, strings.TrimSpace(string(body)))
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

func newSnapshotMetadata(partial bool, inspectionFailures int) map[string]interface{} {
	return map[string]interface{}{
		"version":             1,
		"complete":            !partial,
		"inspection_failures": inspectionFailures,
	}
}

func (p *Pusher) containerData(ctx context.Context) ([]types.Container, int, error) {
	resp, err := p.dockerClient.MakeRequest(ctx, "/containers/json?all=true")
	if err != nil {
		log.Printf("Error getting containers: %v", err)
		return nil, 0, err
	}
	if resp == nil {
		log.Printf("Error: nil response when getting containers")
		return nil, 0, fmt.Errorf("nil response when getting containers")
	}
	if resp.Body == nil {
		log.Printf("Error: nil response body when getting containers")
		return nil, 0, fmt.Errorf("nil response body when getting containers")
	}
	defer func() { _ = resp.Body.Close() }()

	containersOutput, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading containers response: %v", err)
		return nil, 0, err
	}

	var containers []dockerContainer.Summary
	if err := json.Unmarshal(containersOutput, &containers); err != nil {
		log.Printf("Error unmarshalling container list: %v", err)
		return nil, 0, err
	}

	results := make([]*types.Container, len(containers))
	jobs := make(chan int)
	workerCount := min(10, len(containers))
	var waitGroup sync.WaitGroup
	for range workerCount {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for index := range jobs {
				containerData, err := p.inspectContainer(ctx, containers[index])
				if err != nil {
					log.Printf("Error inspecting container %s: %v", containers[index].ID, err)
					continue
				}
				results[index] = containerData
			}
		}()
	}
	for index := range containers {
		jobs <- index
	}
	close(jobs)
	waitGroup.Wait()

	containersData := make([]types.Container, 0, len(containers))
	for _, result := range results {
		if result != nil {
			containersData = append(containersData, *result)
		}
	}
	if skipped := len(containers) - len(containersData); skipped > 0 {
		log.Printf("Warning: Skipped %d out of %d containers due to inspection errors", skipped, len(containers))
		return containersData, skipped, nil
	}
	return containersData, 0, nil
}

func (p *Pusher) inspectContainer(ctx context.Context, container dockerContainer.Summary) (*types.Container, error) {
	resp, err := p.dockerClient.MakeRequest(ctx, fmt.Sprintf("/containers/%s/json", container.ID))
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("empty inspect response")
	}
	defer func() { _ = resp.Body.Close() }()

	inspectOutput, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(inspectOutput) == 0 {
		return nil, fmt.Errorf("empty inspect response")
	}

	var inspectData dockerContainer.InspectResponse
	if err := json.Unmarshal(inspectOutput, &inspectData); err != nil {
		return nil, err
	}

	healthStatus := "unknown"
	if inspectData.ContainerJSONBase != nil && inspectData.State != nil && inspectData.State.Health != nil {
		healthStatus = inspectData.State.Health.Status
	}

	containerName := container.ID
	if len(containerName) > 12 {
		containerName = containerName[:12]
	}
	if len(container.Names) > 0 {
		containerName = strings.TrimPrefix(container.Names[0], "/")
	}

	return &types.Container{
		Time:         time.Now().UTC().Format(time.RFC3339),
		ID:           container.ID,
		Image:        container.Image,
		Labels:       container.Labels,
		Name:         containerName,
		State:        container.State,
		HealthStatus: healthStatus,
	}, nil
}
