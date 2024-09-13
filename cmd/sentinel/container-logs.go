package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

var wg sync.WaitGroup

func streamLogsToFile() error {
	ctx := context.Background()
	apiClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer apiClient.Close()

	go listenToContainerCreation(ctx, apiClient)

	containers, err := apiClient.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return err
	}

	for _, cont := range containers {
		attachContainer(cont, ctx, apiClient)
	}
	wg.Wait()

	return nil
}

func attachContainer(cont types.Container, ctx context.Context, apiClient *client.Client) {
	wg.Add(1)
	go func(cont types.Container) {
		defer wg.Done()
		name := cont.Labels["coolify.name"]
		if name == "" {
			name = cont.Names[0][1:]
		} else {
			if cont.Labels["coolify.pullRequestId"] != "0" {
				name = fmt.Sprintf("%s-pr-%s", name, cont.Labels["coolify.pullRequestId"])
			}
		}
		// logFileName := fmt.Sprintf("%s/%s.txt", logsDir, name)
		streamLogs(ctx, apiClient, cont)
	}(cont)
}

func streamLogs(ctx context.Context, apiClient *client.Client, cont types.Container) {
	out, err := apiClient.ContainerLogs(ctx, cont.ID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "all",
		Timestamps: true,
	})
	if err != nil {
		fmt.Printf("Error retrieving logs for container %s: %s\n", cont.ID, err)
		return
	}
	defer out.Close()

	// logFile, err := os.OpenFile(logFileName, os.O_WRONLY|os.O_CREATE, 0666)
	// if err != nil {
	// 	fmt.Printf("Error opening log file %s: %s\n", logFileName, err)
	// 	return
	// }
	// defer logFile.Close()

	seenLines := make(map[string]bool)
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	stdOutWriter := newRemovingWriter(os.Stdout, seenLines, re)
	stdErrWriter := newRemovingWriter(os.Stderr, seenLines, re)

	if _, err := stdcopy.StdCopy(stdOutWriter, stdErrWriter, out); err != nil {
		fmt.Printf("Error saving logs for container %s: %s\n", cont.ID, err)
	}
}

type removingWriter struct {
	file      *os.File
	seenLines map[string]bool
	regex     *regexp.Regexp
}

func newRemovingWriter(file *os.File, seen map[string]bool, regex *regexp.Regexp) *removingWriter {
	return &removingWriter{
		file:      file,
		seenLines: seen,
		regex:     regex,
	}
}

func (rw *removingWriter) Write(p []byte) (n int, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(p))
	for scanner.Scan() {
		line := scanner.Text()
		cleanLine := rw.regex.ReplaceAllString(line, "") // Remove ANSI escape codes
		if !rw.seenLines[cleanLine] {
			rw.seenLines[cleanLine] = true
			if _, err := fmt.Fprintln(rw.file, cleanLine); err != nil {
				return 0, err
			}
		}
	}
	return len(p), scanner.Err()
}

func listenToContainerCreation(ctx context.Context, apiClient *client.Client) {
	messages, errs := apiClient.Events(ctx, types.EventsOptions{})
	for {
		select {
		case err := <-errs:
			if err != nil {
				fmt.Println("Error listening to Docker events:", err)
				return
			}
		case msg := <-messages:
			if msg.Type == "container" && msg.Action == "create" {
				containers, err := apiClient.ContainerList(ctx, container.ListOptions{})
				if err != nil {
					fmt.Println("Error listing containers:", err)
					return
				}
				for _, cont := range containers {
					if cont.ID == msg.Actor.ID {
						if cont.Image == "ghcr.io/coollabsio/coolify-helper:latest" {
							continue
						}
						if cont.Names[0] == "/coolify-sentinel" {
							continue
						}
						attachContainer(cont, ctx, apiClient)
						break
					}
				}
			}
		}
	}
}
