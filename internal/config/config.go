package config

import (
	"errors"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Environment        string        `mapstructure:"ENVIRONMENT"`
	Port               int           `mapstructure:"PORT"`
	AllowedOrigins     []string      `mapstructure:"ALLOWED_ORIGINS"`
	RateLimitPerMin    int           `mapstructure:"RATE_LIMIT_PER_MIN"`
	MaxUploadSizeMB    int64         `mapstructure:"MAX_UPLOAD_SIZE_MB"`
	MaxMemoryMultipartMB int64       `mapstructure:"MAX_MEMORY_MULTIPART_MB"`
	ReadTimeout        time.Duration `mapstructure:"READ_TIMEOUT"`
	WriteTimeout       time.Duration `mapstructure:"WRITE_TIMEOUT"`
	IdleTimeout        time.Duration `mapstructure:"IDLE_TIMEOUT"`

	// MinIO / S3 Configuration
	MinioEndpoint      string `mapstructure:"MINIO_ENDPOINT"`
	MinioAccessKey     string `mapstructure:"MINIO_ACCESS_KEY"`
	MinioSecretKey     string `mapstructure:"MINIO_SECRET_KEY"`
	MinioUseSSL        bool   `mapstructure:"MINIO_USE_SSL"`
	MinioDefaultBucket string `mapstructure:"MINIO_DEFAULT_BUCKET"`
	MinioRegion        string `mapstructure:"MINIO_REGION"`

	// JWT & Auth API Integration (golang-auth-api)
	AuthAPIURL         string        `mapstructure:"AUTH_API_URL"`
	JWTSecretKey       string        `mapstructure:"JWT_SECRET_KEY"`
	JWTIssuer          string        `mapstructure:"JWT_ISSUER"`
	JWTPublicKeyPEM    string        `mapstructure:"JWT_PUBLIC_KEY_PEM"`
	AuthValidationMode string        `mapstructure:"AUTH_VALIDATION_MODE"` // "local_signature" ou "remote_introspection"
	PresignedExpiryTTL time.Duration `mapstructure:"PRESIGNED_EXPIRY_TTL"`
}

func LoadConfig() (*Config, error) {
	viper.SetConfigFile(".env")
	viper.AutomaticEnv()

	// Defaults
	viper.SetDefault("ENVIRONMENT", "development")
	viper.SetDefault("PORT", 8080)
	viper.SetDefault("ALLOWED_ORIGINS", []string{"*"})
	viper.SetDefault("RATE_LIMIT_PER_MIN", 120)
	viper.SetDefault("MAX_UPLOAD_SIZE_MB", 100) // 100MB
	viper.SetDefault("MAX_MEMORY_MULTIPART_MB", 32)
	viper.SetDefault("READ_TIMEOUT", "30s")
	viper.SetDefault("WRITE_TIMEOUT", "60s")
	viper.SetDefault("IDLE_TIMEOUT", "120s")

	viper.SetDefault("MINIO_ENDPOINT", "localhost:9000")
	viper.SetDefault("MINIO_ACCESS_KEY", "minioadmin")
	viper.SetDefault("MINIO_SECRET_KEY", "minioadmin")
	viper.SetDefault("MINIO_USE_SSL", false)
	viper.SetDefault("MINIO_DEFAULT_BUCKET", "user-files")
	viper.SetDefault("MINIO_REGION", "us-east-1")

	viper.SetDefault("AUTH_API_URL", "http://localhost:8000")
	viper.SetDefault("JWT_SECRET_KEY", "your-256-bit-secret-key-matching-auth-api")
	viper.SetDefault("JWT_ISSUER", "golang-auth-api")
	viper.SetDefault("AUTH_VALIDATION_MODE", "local_signature")
	viper.SetDefault("PRESIGNED_EXPIRY_TTL", "15m")

	if err := viper.ReadInConfig(); err != nil {
		// Se não encontrou o arquivo .env, continua usando variáveis de ambiente do sistema
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// Validação de Segurança
	if cfg.JWTSecretKey == "" && cfg.JWTPublicKeyPEM == "" && cfg.AuthValidationMode == "local_signature" {
		return nil, errors.New("JWT_SECRET_KEY ou JWT_PUBLIC_KEY_PEM deve ser configurado para validação local")
	}

	if cfg.MinioAccessKey == "" || cfg.MinioSecretKey == "" {
		return nil, errors.New("credenciais MinIO (MINIO_ACCESS_KEY, MINIO_SECRET_KEY) são obrigatórias")
	}

	return &cfg, nil
}
