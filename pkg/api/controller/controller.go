package controller

import (
	"net/http/pprof"

	"github.com/coollabsio/sentinel/pkg/config"
	"github.com/coollabsio/sentinel/pkg/db"
	"github.com/gin-gonic/gin"
)

type Controller struct {
	database *db.Database
	ginE     *gin.Engine
	config   *config.Config
}

func New(config *config.Config, database *db.Database) *Controller {
	return &Controller{
		database: database,
		ginE:     gin.Default(),
		config:   config,
	}
}

func (c *Controller) GetEngine() *gin.Engine {
	return c.ginE
}

func (c *Controller) SetupRoutes() {
	c.setupHealthRoutes()
	c.setupContainerRoutes()
	c.setupMemoryRoutes()
	c.setupCpuRoutes()
}

func (c *Controller) setupHealthRoutes() {
	c.ginE.GET("/api/health", func(c *gin.Context) {
		c.String(200, "ok")
	})
}

// TODO: Implement c.setupPushRoutes()
func (c *Controller) SetupDebugRoutes() {
	c.setupDebugRoutes()
	debugGroup := c.ginE.Group("/debug")
	debugGroup.GET("/pprof", func(c *gin.Context) {
		pprof.Index(c.Writer, c.Request)
	})
	debugGroup.GET("/cmdline", func(c *gin.Context) {
		pprof.Cmdline(c.Writer, c.Request)
	})
	debugGroup.GET("/profile", func(c *gin.Context) {
		pprof.Profile(c.Writer, c.Request)
	})
	debugGroup.GET("/symbol", func(c *gin.Context) {
		pprof.Symbol(c.Writer, c.Request)
	})
	debugGroup.GET("/trace", func(c *gin.Context) {
		pprof.Trace(c.Writer, c.Request)
	})
	debugGroup.GET("/heap", func(c *gin.Context) {
		pprof.Handler("heap").ServeHTTP(c.Writer, c.Request)
	})
	debugGroup.GET("/goroutine", func(c *gin.Context) {
		pprof.Handler("goroutine").ServeHTTP(c.Writer, c.Request)
	})
	debugGroup.GET("/block", func(c *gin.Context) {
		pprof.Handler("block").ServeHTTP(c.Writer, c.Request)
	})
}
