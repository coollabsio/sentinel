package main

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
)

func main() {
	// scheduler()
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello, World!",
		})
	})
	r.GET("/api/containers", func(c *gin.Context) {
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
	r.GET("/api/cpu", func(c *gin.Context) {
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
	r.GET("/api/memory", func(c *gin.Context) {
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
	r.GET("/api/disk", func(c *gin.Context) {
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
	r.Run("0.0.0.0:8888")

}
