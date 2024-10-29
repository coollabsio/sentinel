package dockerClient

import (
	"context"
	"net"
	"net/http"
	"time"
)

/* Docker client is a wrapper around http.Client to easily format request to docker socket */
type DockerClient struct {
	httpClient *http.Client
}

func New() *DockerClient {
	return &DockerClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", "/var/run/docker.sock")
				},
			},
			Timeout: 10 * time.Second,
		},
	}
}

func (d *DockerClient) MakeRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "http://localhost"+url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	return d.httpClient.Do(req)
}
