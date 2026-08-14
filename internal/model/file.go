package model

import (
	"time"
)

type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type FileResponse struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	OriginalName string    `json:"original_name"`
	Bucket       string    `json:"bucket"`
	Path         string    `json:"path"`
	Size         int64     `json:"size_bytes"`
	MimeType     string    `json:"mime_type"`
	Checksum     string    `json:"checksum_sha256"`
	UploadedBy   UserInfo  `json:"uploaded_by"`
	UploadDate   time.Time `json:"upload_date"`
	IsPublic     bool      `json:"is_public"`
	Tags         []string  `json:"tags"`
	Encryption   string    `json:"encryption"`
}

type FileMetadata struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	OriginalName string    `json:"original_name"`
	Bucket       string    `json:"bucket"`
	Path         string    `json:"path"`
	Size         int64     `json:"size_bytes"`
	MimeType     string    `json:"mime_type"`
	UploadedBy   UserInfo  `json:"uploaded_by"`
	UploadDate   time.Time `json:"upload_date"`
	IsPublic     bool      `json:"is_public"`
	Tags         []string  `json:"tags"`
}

type FileListFilter struct {
	Search   string
	AllUsers bool
	Page     int
	Limit    int
}

type FileListResponse struct {
	Total int            `json:"total"`
	Files []FileMetadata `json:"files"`
}

type PresignedRequest struct {
	ExpirySeconds int64 `json:"expiry_seconds"`
}

type PresignedUploadRequest struct {
	Filename      string `json:"filename" binding:"required"`
	ExpirySeconds int64  `json:"expiry_seconds"`
	MaxSizeBytes  int64  `json:"max_size_bytes"`
}

type PresignedUploadResponse struct {
	FileID       string    `json:"file_id"`
	ObjectKey    string    `json:"object_key"`
	Bucket       string    `json:"bucket"`
	UploadURL    string    `json:"upload_url"`
	ExpiresAt    time.Time `json:"expires_at"`
	MaxSizeBytes int64     `json:"max_size_bytes"`
}

type UpdateFileMetadataRequest struct {
	Tags     []string `json:"tags"`
	IsPublic bool     `json:"is_public"`
}

type BatchDeleteRequest struct {
	FileIDs []string `json:"file_ids" binding:"required"`
}

type BatchDeleteResponse struct {
	DeletedCount int      `json:"deleted_count"`
	FailedCount  int      `json:"failed_count"`
	DeletedIDs   []string `json:"deleted_ids"`
	FailedIDs    []string `json:"failed_ids"`
}

type CopyFileRequest struct {
	TargetBucket string `json:"target_bucket"`
	TargetFolder string `json:"target_folder"`
}

type BucketInfo struct {
	Name         string    `json:"name"`
	CreationDate time.Time `json:"creation_date"`
}

type CreateBucketRequest struct {
	BucketName string `json:"bucket_name" binding:"required"`
	Region     string `json:"region"`
}
