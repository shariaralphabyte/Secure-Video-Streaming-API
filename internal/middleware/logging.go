package middleware

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()

		// Process request
		c.Next()

		// Stop timer
		duration := time.Since(start)

		// Log request details
		log.Printf("[%s] %s %s %d %v",
			c.Request.Method,
			c.Request.URL.Path,
			c.ClientIP(),
			c.Writer.Status(),
			duration,
		)
	}
}

func ErrorHandlingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Only handle errors if they exist and haven't been handled
		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			log.Printf("Error in request: %v", err)

			// Send detailed error in debug mode
			if gin.Mode() == gin.DebugMode {
				c.JSON(c.Writer.Status(), gin.H{
					"error":   "Internal Server Error",
					"details": err.Error(),
					"path":    c.Request.URL.Path,
					"method":  c.Request.Method,
				})
				return
			}

			// Send generic error in production
			c.JSON(c.Writer.Status(), gin.H{
				"error": "Internal Server Error",
			})
		}
	}
}
