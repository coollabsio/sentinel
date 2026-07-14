package dockerClient

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestMakeRequestRejectsDockerErrors(t *testing.T) {
	client := &DockerClient{httpClient: &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Status:     "500 Internal Server Error",
				Body:       io.NopCloser(strings.NewReader("daemon failed")),
				Header:     make(http.Header),
			}, nil
		}),
	}}

	_, err := client.MakeRequest(context.Background(), "/containers/json")
	if err == nil || !strings.Contains(err.Error(), "daemon failed") {
		t.Fatalf("MakeRequest() error = %v, want Docker response body", err)
	}
}

func TestMakeRequestUsesProvidedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &DockerClient{httpClient: &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Context().Err() == nil {
				t.Fatal("request context was not cancelled")
			}
			return nil, request.Context().Err()
		}),
	}}

	if _, err := client.MakeRequest(ctx, "/containers/json"); err == nil {
		t.Fatal("MakeRequest() error = nil, want context cancellation")
	}
}

func TestMakeRequestLimitsSuccessfulResponseBodies(t *testing.T) {
	client := &DockerClient{httpClient: &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", maxDockerResponseBytes+10))),
				Header:     make(http.Header),
			}, nil
		}),
	}}

	response, err := client.MakeRequest(context.Background(), "/containers/json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != maxDockerResponseBytes {
		t.Fatalf("body length = %d, want %d", len(body), maxDockerResponseBytes)
	}
}
