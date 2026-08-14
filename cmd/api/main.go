package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"govault-api/internal/config"
	"govault-api/internal/handler"
	"govault-api/internal/middleware"
	"govault-api/internal/service"
	"govault-api/internal/storage"
)

// @title           Go MinIO File Management API
// @version         1.0.0
// @description     API corporativa de gerenciamento de arquivos integrada com MinIO e autenticação JWT via golang-auth-api.
// @termsOfService  http://swagger.io/terms/

// @contact.name    Engenharia de Segurança & Armazenamento
// @contact.email   security@example.com

// @license.name    Apache 2.0
// @license.url     http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Insira o token JWT no formato: Bearer {token} gerado pelo golang-auth-api

func main() {
	// 1. Inicializar Logger Estruturado (Uber Zap)
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Printf("Falha ao inicializar logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	// 2. Carregar Configurações do Ambiente (.env ou variáveis de sistema)
	cfg, err := config.LoadConfig()
	if err != nil {
		sugar.Fatalf("Erro crítico ao carregar configurações: %v", err)
	}

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	sugar.Infof("Iniciando GoVault File API [Ambiente: %s]...", cfg.Environment)

	// 3. Inicializar Cliente MinIO com TLS e Políticas de Resiliência
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	minioClient, err := storage.NewMinioClient(ctx, cfg, sugar)
	if err != nil {
		sugar.Fatalf("Falha na conexão com MinIO S3: %v", err)
	}
	sugar.Infof("Conectado com sucesso ao MinIO em: %s (Bucket padrão: %s)", cfg.MinioEndpoint, cfg.MinioDefaultBucket)

	// 4. Inicializar Serviços de Domínio
	fileService := service.NewFileService(minioClient, cfg, sugar)

	// 5. Inicializar Handlers HTTP
	fileHandler := handler.NewFileHandler(fileService, cfg, sugar)
	bucketHandler := handler.NewBucketHandler(minioClient, cfg, sugar)
	healthHandler := handler.NewHealthHandler(minioClient, cfg)

	// 6. Configurar Roteador Gin com Middlewares de Segurança
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.StructuredLogger(sugar))
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.CORS(cfg.AllowedOrigins))
	router.Use(middleware.RateLimiter(cfg.RateLimitPerMin))

	// Limite de memória para upload de multipart (ex: 32MB em memória, o restante em buffer temporário)
	router.MaxMultipartMemory = cfg.MaxMemoryMultipartMB << 20

	// 7. Registro das Rotas da API
	// Rotas Públicas / Health Probes
	router.GET("/healthz", healthHandler.Liveness)
	router.GET("/readyz", healthHandler.Readiness)
	router.GET("/metrics", healthHandler.Metrics)

	// Grupo Principal v1
	v1 := router.Group("/api/v1")
	{
		// Rotas Protegidas por JWT (Validação contra golang-auth-api)
		authRequired := v1.Group("")
		authRequired.Use(middleware.JWTAuthMiddleware(cfg, sugar))
		{
			// Operações de Upload e Arquivos
			files := authRequired.Group("/files")
			{
				files.POST("/upload", fileHandler.UploadFile)
				files.POST("/upload/chunk", fileHandler.UploadChunk)
				files.POST("/upload/complete", fileHandler.CompleteMultipartUpload)
				files.GET("", fileHandler.ListFiles)
				files.GET("/:id", fileHandler.GetFileMetadata)
				files.GET("/:id/download", fileHandler.DownloadFile)
				files.GET("/:id/preview", fileHandler.PreviewFile)
				files.POST("/:id/presigned-download", fileHandler.GeneratePresignedDownloadURL)
				files.POST("/presigned-upload", fileHandler.GeneratePresignedUploadURL)
				files.PUT("/:id/metadata", fileHandler.UpdateFileMetadata)
				files.DELETE("/:id", fileHandler.DeleteFile)
				files.POST("/batch-delete", fileHandler.BatchDeleteFiles)
				files.POST("/:id/copy", fileHandler.CopyFile)
				files.POST("/:id/move", fileHandler.MoveFile)
			}

			// Gestão de Buckets (Apenas Role: Admin)
			admin := authRequired.Group("/buckets")
			admin.Use(middleware.RequireRole("admin"))
			{
				admin.GET("", bucketHandler.ListBuckets)
				admin.POST("", bucketHandler.CreateBucket)
				admin.GET("/:name/stats", bucketHandler.GetBucketStats)
				admin.PUT("/:name/policy", bucketHandler.SetBucketPolicy)
				admin.DELETE("/:name", bucketHandler.DeleteBucket)
			}
		}
	}

	// 8. Inicialização do Servidor HTTP com Graceful Shutdown
	srv := &http.Server{
		Addr:           fmt.Sprintf(":%d", cfg.Port),
		Handler:        router,
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		IdleTimeout:    cfg.IdleTimeout,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	go func() {
		sugar.Infof("Servidor HTTP rodando na porta %d", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			sugar.Fatalf("Erro fatal no servidor HTTP: %v", err)
		}
	}()

	// Graceful Shutdown (SIGINT, SIGTERM)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	sugar.Warn("Sinal de encerramento recebido. Desligando servidor graciosamente...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		sugar.Errorf("Forçando desligamento do servidor: %v", err)
	}

	sugar.Info("Servidor GoVault finalizado com segurança.")
}
