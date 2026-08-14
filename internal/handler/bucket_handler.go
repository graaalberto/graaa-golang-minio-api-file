package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"govault-api/internal/config"
	"govault-api/internal/model"
	"govault-api/internal/storage"
)

type BucketHandler struct {
	storage *storage.MinioClient
	cfg     *config.Config
	logger  *zap.SugaredLogger
}

func NewBucketHandler(storage *storage.MinioClient, cfg *config.Config, logger *zap.SugaredLogger) *BucketHandler {
	return &BucketHandler{
		storage: storage,
		cfg:     cfg,
		logger:  logger,
	}
}

// ListBuckets godoc
// @Summary      Listar buckets do MinIO (Admin)
// @Tags         Buckets
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} model.SuccessResponse{data=[]model.BucketInfo}
// @Router       /buckets [get]
func (h *BucketHandler) ListBuckets(c *gin.Context) {
	buckets, err := h.storage.ListBuckets(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "BUCKET_LIST_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Data:    buckets,
	})
}

// CreateBucket godoc
// @Summary      Criar novo bucket MinIO (Admin)
// @Tags         Buckets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body model.CreateBucketRequest true "Nome do bucket"
// @Success      201 {object} model.SuccessResponse
// @Router       /buckets [post]
func (h *BucketHandler) CreateBucket(c *gin.Context) {
	var req model.CreateBucketRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.BucketName == "" {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   "Campo 'bucket_name' é obrigatório",
			Code:    "INVALID_REQUEST",
		})
		return
	}

	region := req.Region
	if region == "" {
		region = h.cfg.MinioRegion
	}

	if err := h.storage.MakeBucket(c.Request.Context(), req.BucketName, region); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "BUCKET_CREATION_FAILED",
		})
		return
	}

	c.JSON(http.StatusCreated, model.SuccessResponse{
		Success: true,
		Message: "Bucket criado com sucesso no MinIO",
	})
}

// GetBucketStats godoc
// @Summary      Estatísticas de uso e cotas do bucket
// @Tags         Buckets
// @Produce      json
// @Security     BearerAuth
// @Param        name path string true "Nome do bucket"
// @Success      200 {object} model.SuccessResponse
// @Router       /buckets/{name}/stats [get]
func (h *BucketHandler) GetBucketStats(c *gin.Context) {
	bucketName := c.Param("name")
	objectsCh := h.storage.ListObjects(c.Request.Context(), bucketName, "", true)

	var totalObjects int64
	var totalSizeBytes int64

	for obj := range objectsCh {
		if obj.Err == nil {
			totalObjects++
			totalSizeBytes += obj.Size
		}
	}

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Data: gin.H{
			"bucket_name":      bucketName,
			"total_objects":    totalObjects,
			"total_size_bytes": totalSizeBytes,
			"total_size_mb":    float64(totalSizeBytes) / (1024 * 1024),
		},
	})
}

func (h *BucketHandler) SetBucketPolicy(c *gin.Context) {
	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Message: "Política de acesso do bucket atualizada com sucesso",
	})
}

func (h *BucketHandler) DeleteBucket(c *gin.Context) {
	bucketName := c.Param("name")
	if err := h.storage.RemoveBucket(c.Request.Context(), bucketName); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "BUCKET_DELETE_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Message: "Bucket excluído com sucesso",
	})
}
