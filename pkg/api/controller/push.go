package controller

//Comment out till I figure out how to pass pusher to controller context

// func (c *Controller) setupPushRoute() {
// 	c.ginE.POST("/api/push", func(ctx *gin.Context) {
// 		incomingToken := ctx.GetHeader("Authorization")
// 		if incomingToken != "Bearer "+c.config.Token {
// 			ctx.JSON(401, gin.H{"error": "Unauthorized"})
// 			return
// 		}
// 		data, err := push.GetPushData()
// 		if err != nil {
// 			ctx.JSON(500, gin.H{"error": err.Error()})
// 			return
// 		}
// 		ctx.JSON(200, data)
// 	})
// }
