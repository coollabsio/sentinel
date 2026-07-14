package push

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coollabsio/sentinel/pkg/config"
)

type fakeDockerClient struct {
	responses map[string]string
	errors    map[string]error
}

func (f fakeDockerClient) MakeRequest(_ context.Context, path string) (*http.Response, error) {
	if err := f.errors[path]; err != nil {
		return nil, err
	}
	body, ok := f.responses[path]
	if !ok {
		body = "[]"
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func TestSnapshotMetadataDefaultsToComplete(t *testing.T) {
	metadata := newSnapshotMetadata(false, 0)

	if metadata["version"] != 1 {
		t.Fatalf("expected version 1, got %v", metadata["version"])
	}
	if metadata["complete"] != true {
		t.Fatalf("expected complete snapshot, got %v", metadata["complete"])
	}
}

func TestSnapshotMetadataMarksInspectionFailuresPartial(t *testing.T) {
	metadata := newSnapshotMetadata(true, 2)

	if metadata["complete"] != false {
		t.Fatalf("expected partial snapshot, got %v", metadata["complete"])
	}
	if metadata["inspection_failures"] != 2 {
		t.Fatalf("expected 2 inspection failures, got %v", metadata["inspection_failures"])
	}
}

func TestGetPushDataReturnsErrorForNonSuccessfulResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := config.NewDefaultConfig()
	cfg.PushUrl = server.URL
	cfg.Token = "test-token"
	pusher := New(cfg, fakeDockerClient{})

	if _, err := pusher.GetPushData(context.Background()); err == nil {
		t.Fatal("GetPushData() error = nil, want HTTP status error")
	}
}

func TestContainerDataMarksInspectionFailuresAsPartial(t *testing.T) {
	docker := fakeDockerClient{
		responses: map[string]string{
			"/containers/json?all=true": `[{"Id":"abc","Names":["/app"]}]`,
		},
		errors: map[string]error{
			"/containers/abc/json": errors.New("inspect failed"),
		},
	}
	pusher := New(config.NewDefaultConfig(), docker)

	containers, failures, err := pusher.containerData(context.Background())
	if err != nil {
		t.Fatalf("containerData() error = %v", err)
	}
	if len(containers) != 0 || failures != 1 {
		t.Fatalf("containerData() = %d containers, %d failures; want 0, 1", len(containers), failures)
	}
}
