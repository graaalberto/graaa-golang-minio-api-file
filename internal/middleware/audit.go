package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// StructuredLogger registra cada requisição com identificador de correlação (Request-ID)
func StructuredLogger(logger *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Injetar Request-ID único para rastreamento distribuído
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		userID, _ := c.Get(ContextUserIDKey)
		userEmail, _ := c.Get(ContextUserEmailKey)

		if raw != "" {
			path = path + "?" + raw
		}

		fields := []interface{}{
			"status", status,
			"method", c.Request.Method,
			"path", path,
			"ip", c.ClientIP(),
			"latency_ms", latency.Milliseconds(),
			"request_id", requestID,
			"user_id", userID,
			"user_email", userEmail,
			"user_agent", c.Request.UserAgent(),
		}

		if status >= 500 {
			logger.Errorw("HTTP Server Error", fields...)
		} else if status >= 400 {
			logger.Warnw("HTTP Client Error", fields...)
		} else {
			logger.Infow("HTTP Request Handled", fields...)
		}
	}
}
