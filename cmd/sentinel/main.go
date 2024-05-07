package main

import (
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
			"containers": containers,
		})
	})
	r.Run("0.0.0.0:8888")

}
