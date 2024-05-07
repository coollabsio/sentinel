package main

import (
	"fmt"
	"time"

	"github.com/go-co-op/gocron/v2"
)

func scheduler() {
	// start it in the background
	s, err := gocron.NewScheduler()
	if err != nil {
		// handle error
	}

	// add a job to the scheduler
	j, err := s.NewJob(
		gocron.DurationJob(
			5*time.Second,
		),
		gocron.NewTask(
			getAllContainers,
		),
	)
	if err != nil {
		// handle error
	}
	fmt.Println(j.ID())
	s.Start()

}
