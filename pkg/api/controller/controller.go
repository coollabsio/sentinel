package controller

import (
	"crypto/subtle"
	"net/http"
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
	c.ginE.Use(c.authenticate())
	c.setupCoreRoutes()
	c.setupContainerRoutes()
	c.setupMemoryRoutes()
	c.setupCpuRoutes()
}

func (c *Controller) authenticate() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if ctx.Request.URL.Path == "/api/health" || ctx.Request.URL.Path == "/api/version" {
			ctx.Next()
			return
		}

		expected := "Bearer " + c.config.Token
		provided := ctx.GetHeader("Authorization")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		ctx.Next()
	}
}

func (c *Controller) setupCoreRoutes() {
	c.ginE.GET("/api/health", func(ctx *gin.Context) {
		ctx.String(200, "ok")
	})
	c.ginE.GET("/api/version", func(ctx *gin.Context) {
		ctx.String(200, c.config.Version)
	})
}

// TODO: Implement c.setupPushRoutes()
func (c *Controller) SetupDebugRoutes() {
	c.setupDebugRoutes()
	debugGroup := c.ginE.Group("/debug")
	debugGroup.GET("/pprof", func(ctx *gin.Context) {
		pprof.Index(ctx.Writer, ctx.Request)
	})
	debugGroup.GET("/cmdline", func(ctx *gin.Context) {
		pprof.Cmdline(ctx.Writer, ctx.Request)
	})
	debugGroup.GET("/profile", func(ctx *gin.Context) {
		pprof.Profile(ctx.Writer, ctx.Request)
	})
	debugGroup.GET("/symbol", func(ctx *gin.Context) {
		pprof.Symbol(ctx.Writer, ctx.Request)
	})
	debugGroup.GET("/trace", func(ctx *gin.Context) {
		pprof.Trace(ctx.Writer, ctx.Request)
	})
	debugGroup.GET("/heap", func(ctx *gin.Context) {
		pprof.Handler("heap").ServeHTTP(ctx.Writer, ctx.Request)
	})
	debugGroup.GET("/goroutine", func(ctx *gin.Context) {
		pprof.Handler("goroutine").ServeHTTP(ctx.Writer, ctx.Request)
	})
	debugGroup.GET("/block", func(ctx *gin.Context) {
		pprof.Handler("block").ServeHTTP(ctx.Writer, ctx.Request)
	})
}
