package main

import (
	"encoding/json"
	"flag"

	"github.com/gin-gonic/gin"
)

var token string
var version string = "0.0.2"

func Token() gin.HandlerFunc {
	return func(c *gin.Context) {
		if token != "" {
			if c.GetHeader("Authorization") != "Bearer "+token {
				c.JSON(401, gin.H{
					"error": "Unauthorized",
				})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}
func main() {
	// scheduler()
	flag.StringVar(&token, "token", "", "help message for flagname")
	flag.Parse()

	r := gin.Default()
	r.GET("/api/health", func(c *gin.Context) {
		c.String(200, "ok")
	})
	r.GET("/api/version", func(c *gin.Context) {
		c.String(200, version)
	})
	r.Use(gin.Recovery())

	authorized := r.Group("/api")
	authorized.Use(Token())
	{
		authorized.GET("/containers", func(c *gin.Context) {
			containers, err := getAllContainers()
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}

			c.JSON(200, gin.H{
				"containers": json.RawMessage(containers),
			})
		})
		authorized.GET("/cpu", func(c *gin.Context) {
			usage, err := getCpuUsage()
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}

			c.JSON(200, gin.H{
				"cpu_usage": json.RawMessage(usage),
			})
		})
		authorized.GET("/memory", func(c *gin.Context) {
			usage, err := getMemUsage()
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}

			c.JSON(200, gin.H{
				"mem_usage": json.RawMessage(usage),
			})
		})
		authorized.GET("/disk", func(c *gin.Context) {
			usage, err := getDiskUsage()
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}

			c.JSON(200, gin.H{
				"disk_usage": json.RawMessage(usage),
			})
		})
	}

	r.Run("0.0.0.0:8888")

}
