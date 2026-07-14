package dockerClient

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

/* Docker client is a wrapper around http.Client to easily format request to docker socket */
type DockerClient struct {
	httpClient *http.Client
}

const maxDockerResponseBytes = 32 * 1024 * 1024

type limitedReadCloser struct {
	io.Reader
	io.Closer
}

func New() *DockerClient {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &DockerClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", "/var/run/docker.sock")
				},
			},
			Timeout: 10 * time.Second,
		},
	}
}

func (d *DockerClient) MakeRequest(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	response, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("docker API returned an empty response")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		defer func() { _ = response.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4*1024))
		return nil, fmt.Errorf("docker API returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	response.Body = limitedReadCloser{
		Reader: io.LimitReader(response.Body, maxDockerResponseBytes),
		Closer: response.Body,
	}

	return response, nil
}
