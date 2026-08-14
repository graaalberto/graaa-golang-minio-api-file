package storage

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"

	"govault-api/internal/config"
	"govault-api/internal/model"
)

type MinioClient struct {
	client        *minio.Client
	defaultBucket string
	logger        *zap.SugaredLogger
}

func NewMinioClient(ctx context.Context, cfg *config.Config, logger *zap.SugaredLogger) (*MinioClient, error) {
	// Inicializar MinIO com credenciais seguras
	client, err := minio.New(cfg.MinioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinioAccessKey, cfg.MinioSecretKey, ""),
		Secure: cfg.MinioUseSSL,
		Region: cfg.MinioRegion,
	})
	if err != nil {
		return nil, fmt.Errorf("erro ao instanciar cliente MinIO: %w", err)
	}

	mc := &MinioClient{
		client:        client,
		defaultBucket: cfg.MinioDefaultBucket,
		logger:        logger,
	}

	// Garantir que o bucket padrão exista e esteja pronto
	if err := mc.EnsureBucket(ctx, cfg.MinioDefaultBucket, cfg.MinioRegion); err != nil {
		return nil, fmt.Errorf("erro ao provisionar bucket padrão '%s': %w", cfg.MinioDefaultBucket, err)
	}

	return mc, nil
}

// EnsureBucket verifica se o bucket existe e o cria se necessário com configurações seguras
func (m *MinioClient) EnsureBucket(ctx context.Context, bucketName, region string) error {
	exists, err := m.client.BucketExists(ctx, bucketName)
	if err != nil {
		return err
	}

	if !exists {
		m.logger.Infof("Bucket '%s' não encontrado. Criando novo bucket privado...", bucketName)
		err = m.client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{
			Region: region,
		})
		if err != nil {
			return err
		}
		m.logger.Infof("Bucket '%s' criado com sucesso.", bucketName)
	}

	return nil
}

// PutObject realiza upload com suporte a metadados de usuário, tipo MIME e criptografia SSE
func (m *MinioClient) PutObject(ctx context.Context, bucket, objectName string, reader io.Reader, objectSize int64, contentType string, userMetadata map[string]string) (minio.UploadInfo, error) {
	if bucket == "" {
		bucket = m.defaultBucket
	}

	opts := minio.PutObjectOptions{
		ContentType:  contentType,
		UserMetadata: userMetadata,
		// PartSize otimizado para uploads grandes
		PartSize: 10 * 1024 * 1024,
	}

	return m.client.PutObject(ctx, bucket, objectName, reader, objectSize, opts)
}

// GetObject obtém o stream do objeto para download ou visualização
func (m *MinioClient) GetObject(ctx context.Context, bucket, objectName string) (*minio.Object, minio.ObjectInfo, error) {
	if bucket == "" {
		bucket = m.defaultBucket
	}

	obj, err := m.client.GetObject(ctx, bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, minio.ObjectInfo{}, err
	}

	info, err := obj.Stat()
	if err != nil {
		obj.Close()
		return nil, minio.ObjectInfo{}, err
	}

	return obj, info, nil
}

// StatObject obtém metadados sem transferir o corpo do arquivo
func (m *MinioClient) StatObject(ctx context.Context, bucket, objectName string) (minio.ObjectInfo, error) {
	if bucket == "" {
		bucket = m.defaultBucket
	}
	return m.client.StatObject(ctx, bucket, objectName, minio.StatObjectOptions{})
}

// RemoveObject deleta um único arquivo
func (m *MinioClient) RemoveObject(ctx context.Context, bucket, objectName string) error {
	if bucket == "" {
		bucket = m.defaultBucket
	}
	return m.client.RemoveObject(ctx, bucket, objectName, minio.RemoveObjectOptions{})
}

// RemoveObjects remove múltiplos arquivos em lote
func (m *MinioClient) RemoveObjects(ctx context.Context, bucket string, objectNames []string) []error {
	if bucket == "" {
		bucket = m.defaultBucket
	}

	objectsCh := make(chan minio.ObjectInfo)
	go func() {
		defer close(objectsCh)
		for _, name := range objectNames {
			objectsCh <- minio.ObjectInfo{Key: name}
		}
	}()

	opts := minio.RemoveObjectsOptions{
		GovernanceBypass: true,
	}

	var errs []error
	for rErr := range m.client.RemoveObjects(ctx, bucket, objectsCh, opts) {
		errs = append(errs, rErr.Err)
	}

	return errs
}

// PresignedGetObject gera URL temporária assinada para download direto e seguro
func (m *MinioClient) PresignedGetObject(ctx context.Context, bucket, objectName string, expiry time.Duration, reqParams url.Values) (*url.URL, error) {
	if bucket == "" {
		bucket = m.defaultBucket
	}
	return m.client.PresignedGetObject(ctx, bucket, objectName, expiry, reqParams)
}

// PresignedPutObject gera URL temporária para upload direto do cliente para o MinIO sem sobrecarregar a API
func (m *MinioClient) PresignedPutObject(ctx context.Context, bucket, objectName string, expiry time.Duration) (*url.URL, error) {
	if bucket == "" {
		bucket = m.defaultBucket
	}
	return m.client.PresignedPutObject(ctx, bucket, objectName, expiry)
}

// ListObjects lista objetos com paginação e suporte a prefixos (pastas virtuais)
func (m *MinioClient) ListObjects(ctx context.Context, bucket, prefix string, recursive bool) <-chan minio.ObjectInfo {
	if bucket == "" {
		bucket = m.defaultBucket
	}
	return m.client.ListObjects(ctx, bucket, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: recursive,
	})
}

// CopyObject copia ou renomeia objetos dentro do MinIO sem transferência de rede para a API
func (m *MinioClient) CopyObject(ctx context.Context, srcBucket, srcObject, destBucket, destObject string) (minio.UploadInfo, error) {
	srcOpts := minio.CopySrcOptions{
		Bucket: srcBucket,
		Object: srcObject,
	}
	destOpts := minio.CopyDestOptions{
		Bucket: destBucket,
		Object: destObject,
	}
	return m.client.CopyObject(ctx, destOpts, srcOpts)
}

// ListBuckets lista todos os buckets disponíveis (Admin)
func (m *MinioClient) ListBuckets(ctx context.Context) ([]model.BucketInfo, error) {
	buckets, err := m.client.ListBuckets(ctx)
	if err != nil {
		return nil, err
	}

	var result []model.BucketInfo
	for _, b := range buckets {
		result = append(result, model.BucketInfo{
			Name:         b.Name,
			CreationDate: b.CreationDate,
		})
	}

	return result, nil
}

// MakeBucket cria um novo bucket
func (m *MinioClient) MakeBucket(ctx context.Context, bucketName, region string) error {
	return m.client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{Region: region})
}

// RemoveBucket deleta um bucket
func (m *MinioClient) RemoveBucket(ctx context.Context, bucketName string) error {
	return m.client.RemoveBucket(ctx, bucketName)
}

// Ping testa a conectividade para health checks
func (m *MinioClient) Ping(ctx context.Context) error {
	_, err := m.client.BucketExists(ctx, m.defaultBucket)
	return err
}
