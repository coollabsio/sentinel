package api

import (
	"context"
	"net/http"

	"github.com/coollabsio/sentinel/pkg/api/controller"
	"github.com/coollabsio/sentinel/pkg/config"
	"github.com/coollabsio/sentinel/pkg/db"
)

type Api struct {
	controller *controller.Controller
	srv        *http.Server
}

func New(config *config.Config, database *db.Database) *Api {
	controller := controller.New(config, database)
	controller.SetupRoutes()
	if config.Debug {
		controller.SetupDebugRoutes()
	}
	srv := &http.Server{
		Addr:    config.BindAddr,
		Handler: controller.GetEngine().Handler(),
	}
	return &Api{
		controller: controller,
		srv:        srv,
	}
}

func (a *Api) Start() error {
	return a.srv.ListenAndServe()
}

func (a *Api) Stop(ctx context.Context) error {
	return a.srv.Shutdown(ctx)
}
