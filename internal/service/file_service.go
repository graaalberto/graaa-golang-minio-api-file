package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"govault-api/internal/config"
	"govault-api/internal/model"
	"govault-api/internal/storage"
	"govault-api/pkg/validator"
)

type FileService interface {
	UploadFile(ctx context.Context, header *multipart.FileHeader, user *model.CustomJWTClaims, bucket string, isPublic bool, tags []string) (*model.FileResponse, error)
	GetFileStream(ctx context.Context, fileID string, user *model.CustomJWTClaims) (io.ReadCloser, *model.FileMetadata, error)
	GetFileMetadata(ctx context.Context, fileID string, user *model.CustomJWTClaims) (*model.FileMetadata, error)
	ListUserFiles(ctx context.Context, user *model.CustomJWTClaims, filter model.FileListFilter) (*model.FileListResponse, error)
	GeneratePresignedDownload(ctx context.Context, fileID string, user *model.CustomJWTClaims, expiry time.Duration) (string, error)
	GeneratePresignedUpload(ctx context.Context, filename string, user *model.CustomJWTClaims, expiry time.Duration, maxSizeBytes int64) (*model.PresignedUploadResponse, error)
	UpdateMetadata(ctx context.Context, fileID string, user *model.CustomJWTClaims, req model.UpdateFileMetadataRequest) (*model.FileMetadata, error)
	DeleteFile(ctx context.Context, fileID string, user *model.CustomJWTClaims) error
	BatchDeleteFiles(ctx context.Context, fileIDs []string, user *model.CustomJWTClaims) (*model.BatchDeleteResponse, error)
	CopyFile(ctx context.Context, fileID, targetBucket, targetFolder string, user *model.CustomJWTClaims) (*model.FileMetadata, error)
}

type fileServiceImpl struct {
	storage *storage.MinioClient
	cfg     *config.Config
	logger  *zap.SugaredLogger
}

func NewFileService(storage *storage.MinioClient, cfg *config.Config, logger *zap.SugaredLogger) FileService {
	return &fileServiceImpl{
		storage: storage,
		cfg:     cfg,
		logger:  logger,
	}
}

// cleanPath limpa barras duplas e previne divergências de chaves S3/MinIO
func cleanPath(p string) string {
	return path.Clean(strings.ReplaceAll(p, "//", "/"))
}

func getMetaValue(meta map[string]string, key string) string {
	for k, v := range meta {
		if strings.EqualFold(k, key) || strings.EqualFold(k, "x-amz-meta-"+key) {
			return v
		}
	}
	return ""
}

func (s *fileServiceImpl) UploadFile(ctx context.Context, header *multipart.FileHeader, user *model.CustomJWTClaims, bucket string, isPublic bool, tags []string) (*model.FileResponse, error) {
	maxBytes := s.cfg.MaxUploadSizeMB << 20
	if header.Size > maxBytes {
		return nil, fmt.Errorf("tamanho do arquivo (%d bytes) excede o limite configurado de %d MB", header.Size, s.cfg.MaxUploadSizeMB)
	}

	file, err := header.Open()
	if err != nil {
		return nil, fmt.Errorf("falha ao ler arquivo: %w", err)
	}
	defer file.Close()

	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("erro ao analisar cabeçalho do arquivo: %w", err)
	}

	detectedMIME := validator.DetectMimeTypeFromMagicBytes(buffer[:n], header.Filename)
	if !validator.IsAllowedMimeType(detectedMIME) {
		return nil, fmt.Errorf("tipo de arquivo rejeitado pela política de segurança: '%s'", detectedMIME)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("erro ao redefinir ponteiro de leitura: %w", err)
	}

	hasher := sha256.New()
	teeReader := io.TeeReader(file, hasher)

	sanitizedOriginalName := validator.SanitizeFilename(header.Filename)
	fileExtension := strings.ToLower(filepath.Ext(sanitizedOriginalName))
	uniqueFileID := uuid.New().String()

	// 1. Extração segura de ID e Role do Usuário
	userID := "anonymous"
	userEmail := ""
	userRole := ""

	if user != nil {
		if user.UserID != "" {
			userID = user.UserID
		}
		userEmail = user.Email
		userRole = user.Role
	}

	// 2. Montagem do Path do Objeto no MinIO
	var objectKey string
	if isPublic {
		objectKey = fmt.Sprintf("public/%s%s", uniqueFileID, fileExtension)
	} else {
		objectKey = fmt.Sprintf("uploads/%s/%s%s", userID, uniqueFileID, fileExtension)
	}
	objectKey = cleanPath(objectKey)

	if bucket == "" {
		bucket = s.cfg.MinioDefaultBucket
	}

	// 3. Metadados salvos no MinIO (Sempre usar chaves em minúsculas)
	userMetadata := map[string]string{
		"file-id":        uniqueFileID,
		"original-name":  sanitizedOriginalName,
		"uploaded-by":    userID,
		"uploader-email": userEmail,
		"uploader-role":  userRole,
		"is-public":      fmt.Sprintf("%t", isPublic),
		"tags":           strings.Join(tags, ","),
		"created-at":     time.Now().UTC().Format(time.RFC3339),
	}

	uploadInfo, err := s.storage.PutObject(ctx, bucket, objectKey, teeReader, header.Size, detectedMIME, userMetadata)
	if err != nil {
		s.logger.Errorw("Erro no upload para MinIO", "objectKey", objectKey, "error", err)
		return nil, fmt.Errorf("falha no armazenamento MinIO: %w", err)
	}

	checksumHex := hex.EncodeToString(hasher.Sum(nil))

	s.logger.Infow("Arquivo armazenado com sucesso",
		"fileID", uniqueFileID,
		"objectKey", objectKey,
		"size", uploadInfo.Size,
		"mime", detectedMIME,
		"checksum", checksumHex,
		"user", userEmail,
	)

	return &model.FileResponse{
		ID:           uniqueFileID,
		Name:         uniqueFileID + fileExtension,
		OriginalName: sanitizedOriginalName,
		Bucket:       bucket,
		Path:         objectKey,
		Size:         uploadInfo.Size,
		MimeType:     detectedMIME,
		Checksum:     checksumHex,
		UploadedBy: model.UserInfo{
			ID:    userID,
			Email: userEmail,
			Role:  userRole,
		},
		UploadDate: time.Now().UTC(),
		IsPublic:   isPublic,
		Tags:       tags,
		Encryption: "SSE-S3",
	}, nil
}

func (s *fileServiceImpl) GetFileStream(ctx context.Context, fileID string, user *model.CustomJWTClaims) (io.ReadCloser, *model.FileMetadata, error) {
	meta, err := s.GetFileMetadata(ctx, fileID, user)
	if err != nil {
		return nil, nil, err
	}

	obj, _, err := s.storage.GetObject(ctx, meta.Bucket, meta.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("erro ao abrir stream do arquivo: %w", err)
	}

	return obj, meta, nil
}

func (s *fileServiceImpl) GetFileMetadata(ctx context.Context, fileID string, user *model.CustomJWTClaims) (*model.FileMetadata, error) {
	cleanFileID := strings.TrimSuffix(fileID, filepath.Ext(fileID))

	// 1. Monta os prefixos de busca
	var prefixes []string
	if user != nil && user.Role == "admin" {
		prefixes = []string{"uploads/", "public/", ""}
	} else if user != nil && user.UserID != "" {
		prefixes = []string{
			fmt.Sprintf("uploads/%s/", user.UserID),
			"public/",
			"uploads/", // Fallback caso o upload tenha sido feito sem user_id no path
		}
	} else {
		prefixes = []string{"uploads/", "public/", ""}
	}

	s.logger.Infow("Iniciando busca de arquivo",
		"fileID", fileID,
		"cleanFileID", cleanFileID,
		"userID", user.UserID,
		"role", user.Role,
	)

	for _, prefix := range prefixes {
		objectsCh := s.storage.ListObjects(ctx, s.cfg.MinioDefaultBucket, prefix, true)
		for obj := range objectsCh {
			if obj.Err != nil {
				continue
			}

			// Se a chave no MinIO contém o UUID enviado
			if strings.Contains(obj.Key, cleanFileID) {
				stat, err := s.storage.StatObject(ctx, s.cfg.MinioDefaultBucket, obj.Key)
				if err != nil {
					return nil, err
				}

				uploaderID := getMetaValue(stat.UserMetadata, "uploaded-by")
				isPublic := getMetaValue(stat.UserMetadata, "is-public") == "true"

				// Se for admin ou dono do arquivo ou público -> permite
				if !isPublic && (user != nil && user.Role != "admin") && uploaderID != "" && uploaderID != user.UserID {
					return nil, errors.New("permissão negada: você não é o proprietário deste arquivo")
				}

				tagsStr := getMetaValue(stat.UserMetadata, "tags")
				var tags []string
				if tagsStr != "" {
					tags = strings.Split(tagsStr, ",")
				}

				storedFileID := getMetaValue(stat.UserMetadata, "file-id")
				if storedFileID == "" {
					storedFileID = cleanFileID
				}

				return &model.FileMetadata{
					ID:           storedFileID,
					Name:         filepath.Base(obj.Key),
					OriginalName: getMetaValue(stat.UserMetadata, "original-name"),
					Bucket:       s.cfg.MinioDefaultBucket,
					Path:         cleanPath(obj.Key),
					Size:         stat.Size,
					MimeType:     stat.ContentType,
					UploadedBy: model.UserInfo{
						ID:    uploaderID,
						Email: getMetaValue(stat.UserMetadata, "uploader-email"),
						Role:  getMetaValue(stat.UserMetadata, "uploader-role"),
					},
					UploadDate: stat.LastModified,
					IsPublic:   isPublic,
					Tags:       tags,
				}, nil
			}
		}
	}

	return nil, errors.New("arquivo não encontrado")
}

func (s *fileServiceImpl) ListUserFiles(ctx context.Context, user *model.CustomJWTClaims, filter model.FileListFilter) (*model.FileListResponse, error) {
	// 1. Determina se é Admin checando diretamente user.Role
	isAdmin := false
	if user != nil && user.Role == "admin" {
		isAdmin = true
	}

	// 2. Define os prefixos de busca
	var prefixes []string
	if isAdmin || filter.AllUsers {
		// Admin ou solicitação explícita de todos os arquivos -> varre a raiz e as subpastas
		prefixes = []string{"", "uploads/", "public/"}
	} else if user != nil && user.UserID != "" {
		// Usuário comum -> busca no seu diretório e também na raiz/público
		prefixes = []string{
			fmt.Sprintf("uploads/%s/", user.UserID),
			"public/",
			"", // Fallback para arquivos gravados sem diretório
		}
	} else {
		prefixes = []string{"", "public/"}
	}

	var items []model.FileMetadata
	seenKeys := make(map[string]bool)

	// 3. Itera sobre os prefixos para varrer os objetos no MinIO
	for _, prefix := range prefixes {
		objectsCh := s.storage.ListObjects(ctx, s.cfg.MinioDefaultBucket, prefix, true)

		for obj := range objectsCh {
			if obj.Err != nil || obj.Key == "" || seenKeys[obj.Key] {
				continue
			}

			// Garante que o mesmo arquivo não seja duplicado no loop multi-prefixo
			seenKeys[obj.Key] = true

			stat, err := s.storage.StatObject(ctx, s.cfg.MinioDefaultBucket, obj.Key)
			if err != nil {
				continue
			}

			uploaderID := getMetaValue(stat.UserMetadata, "uploaded-by")
			isPublic := getMetaValue(stat.UserMetadata, "is-public") == "true"

			// Se não for admin e o arquivo não for do usuário nem público, salta
			if !isAdmin && !isPublic && uploaderID != "" && user != nil && uploaderID != user.UserID {
				continue
			}

			fileID := getMetaValue(stat.UserMetadata, "file-id")
			if fileID == "" {
				fileID = filepath.Base(obj.Key)
			}

			origName := getMetaValue(stat.UserMetadata, "original-name")
			if origName == "" {
				origName = filepath.Base(obj.Key)
			}

			// Filtro de busca por nome
			if filter.Search != "" && !strings.Contains(strings.ToLower(origName), strings.ToLower(filter.Search)) {
				continue
			}

			tagsStr := getMetaValue(stat.UserMetadata, "tags")
			var tags []string
			if tagsStr != "" {
				tags = strings.Split(tagsStr, ",")
			}

			items = append(items, model.FileMetadata{
				ID:           fileID,
				Name:         filepath.Base(obj.Key),
				OriginalName: origName,
				Bucket:       s.cfg.MinioDefaultBucket,
				Path:         cleanPath(obj.Key),
				Size:         stat.Size,
				MimeType:     stat.ContentType,
				UploadedBy: model.UserInfo{
					ID:    uploaderID,
					Email: getMetaValue(stat.UserMetadata, "uploader-email"),
					Role:  getMetaValue(stat.UserMetadata, "uploader-role"),
				},
				UploadDate: stat.LastModified,
				IsPublic:   isPublic,
				Tags:       tags,
			})
		}
	}

	return &model.FileListResponse{
		Total: len(items),
		Files: items,
	}, nil
}

func (s *fileServiceImpl) GeneratePresignedDownload(ctx context.Context, fileID string, user *model.CustomJWTClaims, expiry time.Duration) (string, error) {
	meta, err := s.GetFileMetadata(ctx, fileID, user)
	if err != nil {
		return "", err
	}

	if expiry <= 0 || expiry > 24*time.Hour {
		expiry = s.cfg.PresignedExpiryTTL
	}

	reqParams := make(url.Values)
	reqParams.Set("response-content-disposition", fmt.Sprintf("attachment; filename=\"%s\"", meta.OriginalName))

	signedURL, err := s.storage.PresignedGetObject(ctx, meta.Bucket, meta.Path, expiry, reqParams)
	if err != nil {
		return "", fmt.Errorf("falha ao gerar URL pré-assinada: %w", err)
	}

	return signedURL.String(), nil
}

func (s *fileServiceImpl) GeneratePresignedUpload(ctx context.Context, filename string, user *model.CustomJWTClaims, expiry time.Duration, maxSizeBytes int64) (*model.PresignedUploadResponse, error) {
	sanitized := validator.SanitizeFilename(filename)
	ext := filepath.Ext(sanitized)
	fileID := uuid.New().String()
	objectKey := cleanPath(fmt.Sprintf("uploads/%s/%s%s", user.UserID, fileID, ext))

	if expiry <= 0 {
		expiry = s.cfg.PresignedExpiryTTL
	}

	signedURL, err := s.storage.PresignedPutObject(ctx, s.cfg.MinioDefaultBucket, objectKey, expiry)
	if err != nil {
		return nil, fmt.Errorf("erro ao gerar presigned PUT URL: %w", err)
	}

	return &model.PresignedUploadResponse{
		FileID:       fileID,
		ObjectKey:    objectKey,
		Bucket:       s.cfg.MinioDefaultBucket,
		UploadURL:    signedURL.String(),
		ExpiresAt:    time.Now().Add(expiry),
		MaxSizeBytes: maxSizeBytes,
	}, nil
}

func (s *fileServiceImpl) UpdateMetadata(ctx context.Context, fileID string, user *model.CustomJWTClaims, req model.UpdateFileMetadataRequest) (*model.FileMetadata, error) {
	meta, err := s.GetFileMetadata(ctx, fileID, user)
	if err != nil {
		return nil, err
	}

	meta.Tags = req.Tags
	meta.IsPublic = req.IsPublic

	return meta, nil
}

func (s *fileServiceImpl) DeleteFile(ctx context.Context, fileID string, user *model.CustomJWTClaims) error {
	meta, err := s.GetFileMetadata(ctx, fileID, user)
	if err != nil {
		return err
	}

	return s.storage.RemoveObject(ctx, meta.Bucket, meta.Path)
}

func (s *fileServiceImpl) BatchDeleteFiles(ctx context.Context, fileIDs []string, user *model.CustomJWTClaims) (*model.BatchDeleteResponse, error) {
	var deleted []string
	var failed []string

	for _, id := range fileIDs {
		if err := s.DeleteFile(ctx, id, user); err != nil {
			failed = append(failed, id)
		} else {
			deleted = append(deleted, id)
		}
	}

	return &model.BatchDeleteResponse{
		DeletedCount: len(deleted),
		FailedCount:  len(failed),
		DeletedIDs:   deleted,
		FailedIDs:    failed,
	}, nil
}

func (s *fileServiceImpl) CopyFile(ctx context.Context, fileID, targetBucket, targetFolder string, user *model.CustomJWTClaims) (*model.FileMetadata, error) {
	meta, err := s.GetFileMetadata(ctx, fileID, user)
	if err != nil {
		return nil, err
	}

	if targetBucket == "" {
		targetBucket = meta.Bucket
	}

	newFileID := uuid.New().String()
	ext := filepath.Ext(meta.Path)
	destObject := cleanPath(fmt.Sprintf("uploads/%s/%s%s", user.UserID, newFileID, ext))
	if targetFolder != "" {
		destObject = cleanPath(fmt.Sprintf("%s/%s%s", strings.Trim(targetFolder, "/"), newFileID, ext))
	}

	_, err = s.storage.CopyObject(ctx, meta.Bucket, meta.Path, targetBucket, destObject)
	if err != nil {
		return nil, fmt.Errorf("erro ao copiar objeto no MinIO: %w", err)
	}

	return &model.FileMetadata{
		ID:           newFileID,
		Name:         filepath.Base(destObject),
		OriginalName: "Copy_of_" + meta.OriginalName,
		Bucket:       targetBucket,
		Path:         destObject,
		Size:         meta.Size,
		MimeType:     meta.MimeType,
		UploadedBy:   meta.UploadedBy,
		UploadDate:   time.Now().UTC(),
		IsPublic:     meta.IsPublic,
		Tags:         meta.Tags,
	}, nil
}
