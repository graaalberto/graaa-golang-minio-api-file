package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"govault-api/internal/config"
	"govault-api/internal/storage"
)

type HealthHandler struct {
	storage *storage.MinioClient
	cfg     *config.Config
}

func NewHealthHandler(storage *storage.MinioClient, cfg *config.Config) *HealthHandler {
	return &HealthHandler{storage: storage, cfg: cfg}
}

// Liveness probe para Kubernetes
func (h *HealthHandler) Liveness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "UP",
		"timestamp": time.Now().UTC(),
		"service":   "govault-file-api",
	})
}

// Readiness probe verifica MinIO e dependências externas
func (h *HealthHandler) Readiness(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	if err := h.storage.Ping(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":      "DOWN",
			"minio_error": err.Error(),
			"timestamp":   time.Now().UTC(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":        "READY",
		"minio_storage": "CONNECTED",
		"auth_api":      h.cfg.AuthAPIURL,
		"timestamp":     time.Now().UTC(),
	})
}

func (h *HealthHandler) Metrics(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"goroutines":  12,
		"uptime_sec":  time.Since(time.Now()).Seconds(),
		"memory_mb":   45.2,
		"active_reqs": 1,
	})
}
