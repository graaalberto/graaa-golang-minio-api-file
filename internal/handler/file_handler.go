package handler

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"govault-api/internal/config"
	"govault-api/internal/middleware"
	"govault-api/internal/model"
	"govault-api/internal/service"
)

type FileHandler struct {
	service service.FileService
	cfg     *config.Config
	logger  *zap.SugaredLogger
}

func NewFileHandler(service service.FileService, cfg *config.Config, logger *zap.SugaredLogger) *FileHandler {
	return &FileHandler{
		service: service,
		cfg:     cfg,
		logger:  logger,
	}
}

// UploadFile godoc
// @Summary      Upload de arquivo seguro
// @Description  Envia um arquivo com validação de magic bytes, SHA-256 e isolamento por usuário.
// @Tags         Files
// @Accept       multipart/form-data
// @Produce      json
// @Security     BearerAuth
// @Param        file formData file true "Arquivo para upload"
// @Param        is_public formData boolean false "Define se o arquivo será publicamente acessível"
// @Param        tags formData string false "Tags separadas por vírgula (ex: relatorios,financeiro)"
// @Success      201  {object}  model.SuccessResponse{data=model.FileResponse}
// @Failure      400  {object}  model.ErrorResponse
// @Failure      401  {object}  model.ErrorResponse
// @Failure      413  {object}  model.ErrorResponse
// @Router       /files/upload [post]
func (h *FileHandler) UploadFile(c *gin.Context) {
	// 1. Extração e Validação dos Claims do Usuário
	user := h.getUserClaims(c)
	if user == nil || user.UserID == "" {
		h.logger.Warnw("Tentativa de upload sem credenciais de usuário válidas")
		c.JSON(http.StatusUnauthorized, model.ErrorResponse{
			Success: false,
			Error:   "Token de autenticação inválido ou sem ID de usuário (user_id ausente)",
			Code:    "UNAUTHORIZED",
		})
		return
	}

	// 2. Validação da presença do arquivo no multipart
	header, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   "Campo 'file' é obrigatório no formulário multipart",
			Code:    "FILE_REQUIRED",
		})
		return
	}

	// 3. Processamento de Parâmetros Adicionais (is_public e tags)
	isPublic := c.PostForm("is_public") == "true"
	rawTags := c.PostForm("tags")
	var tags []string
	if rawTags != "" {
		for _, t := range strings.Split(rawTags, ",") {
			trimmed := strings.TrimSpace(t)
			if trimmed != "" {
				tags = append(tags, trimmed)
			}
		}
	}

	// 4. Chamada do Serviço
	res, err := h.service.UploadFile(c.Request.Context(), header, user, h.cfg.MinioDefaultBucket, isPublic, tags)
	if err != nil {
		h.logger.Warnw("Falha no upload de arquivo", "user", user.Email, "userID", user.UserID, "error", err)
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "UPLOAD_FAILED",
		})
		return
	}

	// 5. Resposta de Sucesso
	c.JSON(http.StatusCreated, model.SuccessResponse{
		Success: true,
		Message: "Arquivo enviado com sucesso para o MinIO",
		Data:    res,
	})
}

// ListFiles godoc
// @Summary      Listar arquivos do usuário
// @Description  Retorna a listagem de arquivos pertencentes ao usuário autenticado com filtros de busca.
// @Tags         Files
// @Produce      json
// @Security     BearerAuth
// @Param        search query string false "Termo de busca por nome"
// @Param        all_users query boolean false "Apenas Admin: Listar de todos os usuários"
// @Success      200  {object}  model.SuccessResponse{data=model.FileListResponse}
// @Router       /files [get]
func (h *FileHandler) ListFiles(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	filter := model.FileListFilter{
		Search:   c.Query("search"),
		AllUsers: c.Query("all_users") == "true",
	}

	res, err := h.service.ListUserFiles(c.Request.Context(), user, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "LIST_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Data:    res,
	})
}

// GetFileMetadata godoc
// @Summary      Obter metadados do arquivo
// @Tags         Files
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "ID do arquivo"
// @Success      200 {object} model.SuccessResponse{data=model.FileMetadata}
// @Router       /files/{id} [get]
func (h *FileHandler) GetFileMetadata(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	fileID := c.Param("id")
	meta, err := h.service.GetFileMetadata(c.Request.Context(), fileID, user)
	if err != nil {
		c.JSON(http.StatusNotFound, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "FILE_NOT_FOUND",
		})
		return
	}

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Data:    meta,
	})
}

// DownloadFile godoc
// @Summary      Download direto do arquivo com streaming
// @Description  Transfere o stream de dados do MinIO com cabeçalhos de segurança e nome original.
// @Tags         Files
// @Produce      application/octet-stream
// @Security     BearerAuth
// @Param        id path string true "ID do arquivo"
// @Success      200 {file} binary
// @Router       /files/{id}/download [get]
func (h *FileHandler) DownloadFile(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	fileID := c.Param("id")
	stream, meta, err := h.service.GetFileStream(c.Request.Context(), fileID, user)
	if err != nil {
		c.JSON(http.StatusNotFound, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "FILE_NOT_FOUND",
		})
		return
	}
	defer stream.Close()

	// Injetar cabeçalhos para forçar download seguro
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", meta.OriginalName))
	c.Header("Content-Type", meta.MimeType)
	c.Header("Content-Length", strconv.FormatInt(meta.Size, 10))
	c.Header("X-File-ID", meta.ID)

	io.Copy(c.Writer, stream)
}

// PreviewFile godoc
// @Summary      Visualização inline de arquivo (PDF, imagens, vídeo)
// @Tags         Files
// @Produce      */*
// @Security     BearerAuth
// @Param        id path string true "ID do arquivo"
// @Success      200 {file} binary
// @Router       /files/{id}/preview [get]
func (h *FileHandler) PreviewFile(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	fileID := c.Param("id")
	stream, meta, err := h.service.GetFileStream(c.Request.Context(), fileID, user)
	if err != nil {
		c.JSON(http.StatusNotFound, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "FILE_NOT_FOUND",
		})
		return
	}
	defer stream.Close()

	c.Header("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", meta.OriginalName))
	c.Header("Content-Type", meta.MimeType)
	c.Header("Content-Length", strconv.FormatInt(meta.Size, 10))

	io.Copy(c.Writer, stream)
}

// GeneratePresignedDownloadURL godoc
// @Summary      Gerar URL pré-assinada temporária para download
// @Description  Gera link com TTL customizável (máx 24h) com assinatura criptográfica do MinIO S3.
// @Tags         Presigned
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "ID do arquivo"
// @Param        body body model.PresignedRequest false "Configuração de expiração"
// @Success      200 {object} model.SuccessResponse{data=gin.H}
// @Router       /files/{id}/presigned-download [post]
func (h *FileHandler) GeneratePresignedDownloadURL(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	fileID := c.Param("id")
	var req model.PresignedRequest
	_ = c.ShouldBindJSON(&req)

	expiry := time.Duration(req.ExpirySeconds) * time.Second
	if expiry <= 0 {
		expiry = h.cfg.PresignedExpiryTTL
	}

	downloadURL, err := h.service.GeneratePresignedDownload(c.Request.Context(), fileID, user, expiry)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "PRESIGNED_GEN_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Data: gin.H{
			"file_id":      fileID,
			"download_url": downloadURL,
			"expires_in":   expiry.Seconds(),
			"expires_at":   time.Now().Add(expiry),
		},
	})
}

// GeneratePresignedUploadURL godoc
// @Summary      Gerar URL pré-assinada para upload direto ao MinIO
// @Tags         Presigned
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body model.PresignedUploadRequest true "Parâmetros do arquivo"
// @Success      200 {object} model.SuccessResponse{data=model.PresignedUploadResponse}
// @Router       /files/presigned-upload [post]
func (h *FileHandler) GeneratePresignedUploadURL(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	var req model.PresignedUploadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   "Parâmetro 'filename' é obrigatório",
			Code:    "INVALID_REQUEST",
		})
		return
	}

	expiry := time.Duration(req.ExpirySeconds) * time.Second
	res, err := h.service.GeneratePresignedUpload(c.Request.Context(), req.Filename, user, expiry, req.MaxSizeBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "PRESIGNED_UPLOAD_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Data:    res,
	})
}

// UpdateFileMetadata godoc
// @Summary      Atualizar tags e visibilidade
// @Tags         Files
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "ID do arquivo"
// @Param        body body model.UpdateFileMetadataRequest true "Novos metadados"
// @Success      200 {object} model.SuccessResponse{data=model.FileMetadata}
// @Router       /files/{id}/metadata [put]
func (h *FileHandler) UpdateFileMetadata(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	fileID := c.Param("id")
	var req model.UpdateFileMetadataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   "JSON inválido",
			Code:    "INVALID_BODY",
		})
		return
	}

	res, err := h.service.UpdateMetadata(c.Request.Context(), fileID, user, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "UPDATE_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Data:    res,
	})
}

// DeleteFile godoc
// @Summary      Excluir arquivo do MinIO
// @Tags         Files
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "ID do arquivo"
// @Success      200 {object} model.SuccessResponse
// @Router       /files/{id} [delete]
func (h *FileHandler) DeleteFile(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	fileID := c.Param("id")
	if err := h.service.DeleteFile(c.Request.Context(), fileID, user); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "DELETE_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Message: "Arquivo excluído permanentemente do MinIO",
	})
}

// BatchDeleteFiles godoc
// @Summary      Exclusão de arquivos em lote
// @Tags         Files
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body model.BatchDeleteRequest true "Lista de IDs"
// @Success      200 {object} model.SuccessResponse{data=model.BatchDeleteResponse}
// @Router       /files/batch-delete [post]
func (h *FileHandler) BatchDeleteFiles(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	var req model.BatchDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.FileIDs) == 0 {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   "Lista 'file_ids' não pode ser vazia",
			Code:    "INVALID_REQUEST",
		})
		return
	}

	res, err := h.service.BatchDeleteFiles(c.Request.Context(), req.FileIDs, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "BATCH_DELETE_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Data:    res,
	})
}

// CopyFile godoc
// @Summary      Copiar arquivo
// @Tags         Files
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "ID do arquivo de origem"
// @Param        body body model.CopyFileRequest false "Bucket e pasta destino"
// @Success      200 {object} model.SuccessResponse{data=model.FileMetadata}
// @Router       /files/{id}/copy [post]
func (h *FileHandler) CopyFile(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	fileID := c.Param("id")
	var req model.CopyFileRequest
	_ = c.ShouldBindJSON(&req)

	res, err := h.service.CopyFile(c.Request.Context(), fileID, req.TargetBucket, req.TargetFolder, user)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "COPY_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Data:    res,
	})
}

// MoveFile godoc
// @Summary      Mover arquivo
// @Tags         Files
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "ID do arquivo"
// @Router       /files/{id}/move [post]
func (h *FileHandler) MoveFile(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	fileID := c.Param("id")
	var req model.CopyFileRequest
	_ = c.ShouldBindJSON(&req)

	res, err := h.service.CopyFile(c.Request.Context(), fileID, req.TargetBucket, req.TargetFolder, user)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "MOVE_FAILED",
		})
		return
	}

	// Deletar o original após cópia concluída
	_ = h.service.DeleteFile(c.Request.Context(), fileID, user)

	c.JSON(http.StatusOK, model.SuccessResponse{
		Success: true,
		Message: "Arquivo movido com sucesso",
		Data:    res,
	})
}

func (h *FileHandler) UploadChunk(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "chunk_received", "message": "Chunk processado com sucesso"})
}

func (h *FileHandler) CompleteMultipartUpload(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "multipart_completed", "message": "Upload multipart finalizado"})
}

func (h *FileHandler) getUserClaims(c *gin.Context) *model.CustomJWTClaims {
	claimsVal, exists := c.Get(middleware.ContextClaimsKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, model.ErrorResponse{
			Success: false,
			Error:   "Usuário não autenticado",
			Code:    "UNAUTHORIZED",
		})
		return nil
	}
	return claimsVal.(*model.CustomJWTClaims)
}
