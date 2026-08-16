# 🚀 Graaa - Enterprise File Management API com MinIO e Golang Auth API

Uma API de gerenciamento de arquivos completa, segura e de alto desempenho desenvolvida em **Go (Golang)**, conectada ao **MinIO (S3-compatible Object Storage)** e autenticada via **JWT** integrado ao [graaa-golang-auth-api](https://github.com/gjovanovicst/golang-auth-api).

---

## 📋 Sumário
1. [Visão Geral e Arquitetura](#-visão-geral-e-arquitetura)
2. [Recursos e Capacidades](#-recursos-e-capacidades)
3. [Integração com golang-auth-api](#-integração-com-golang-auth-api)
4. [Segurança e Regras OWASP](#-segurança-e-regras-owasp)
5. [Endpoints da API](#-endpoints-da-api)
6. [Execução Rápida com Docker](#-execução-rápida-com-docker)
7. [Exemplos de cURL](#-exemplos-de-curl)

---

## 🏛 Visão Geral e Arquitetura

O sistema adota uma arquitetura em camadas (Clean Architecture) com desacoplamento total entre o armazenamento em nuvem e a camada de transporte HTTP:

```
  [ Cliente HTTP / Frontend ]
               │
               ▼ Bearer JWT Token
  ┌────────────────────────────────────────────────────────┐
  │                 Graaa File API                       │
  │                                                        │
  │  1. Middlewares:                                       │
  │     ├─ JWT Auth (Validação contra golang-auth-api)     │
  │     ├─ OWASP Security Headers (nosniff, CSP, HSTS)     │
  │     ├─ Rate Limiting (Token Bucket por IP)             │
  │     └─ Structured Audit Logging (Request-ID)           │
  │                                                        │
  │  2. Domain Handlers & Validators:                      │
  │     ├─ Magic Bytes MIME Sniffing                       │
  │     ├─ Filename Sanitization (Anti-Path Traversal)     │
  │     └─ SHA-256 Checksum Calculation                    │
  │                                                        │
  │  3. MinIO S3 Storage Adapter:                          │
  │     ├─ User Bucket Partitioning                        │
  │     ├─ Presigned URL Generator (GET / PUT)             │
  │     └─ Server-Side Encryption (SSE-S3)                 │
  └────────────────────────────────────────────────────────┘
         │                                    │
         ▼                                    ▼
┌──────────────────┐               ┌───────────────────────┐
│ MinIO S3 Storage │               │    golang-auth-api    │
│  (Port 9000)     │               │     (Port 8080)       │
└──────────────────┘               └───────────────────────┘
```

---

## 🔐 Integração com graaa-golang-auth-api

O sistema suporta dois modos configuráveis de validação de token:

### Modo 1: Validação por Assinatura Criptográfica (Local - Recomendado)
- O **golang-auth-api** emite tokens assinados com `HMAC-SHA256` contendo as claims `id`, `email` e `role`.
- O **GoVault** valida localmente a assinatura em menos de **0.1ms**, sem latência de rede adicional.

### Modo 2: Introspecção Remota (Webhook)
- O Graaa chama `GET http://localhost:8080/api/auth/user` passando o Bearer token para validação dinâmica.

---

## 🛡 Segurança e Regras OWASP Implementadas

1. **Magic Bytes Validation**: O arquivo é inspecionado nos primeiros 512 bytes para garantir que o tipo MIME real corresponda ao esperado, impedindo malwares camuflados.
2. **Anti-Path Traversal**: Nomes de arquivo são higienizados com expressões regulares, prevenindo injeções de diretório (`../../`).
3. **Isolamento de Arquivos por Usuário**: Arquivos são particionados em pastas exclusivas: `uploads/{user_id}/{uuid}{ext}`.
4. **URLs Pré-Assinadas Temporárias**: Links de download e upload direto possuem TTL configurável e expiração automática.
5. **Rate Limiting**: Algoritmo Token Bucket protegendo contra ataques de negação de serviço (DoS).

---

## 📡 Endpoints da API

| Método | Rota | Descrição | Permissão |
|---|---|---|---|
| `POST` | `/api/v1/files/upload` | Upload multipart de arquivo | Usuário Autenticado |
| `GET` | `/api/v1/files` | Listar arquivos do usuário | Usuário Autenticado |
| `GET` | `/api/v1/files/:id` | Obter metadados do arquivo | Dono ou Admin |
| `GET` | `/api/v1/files/:id/download` | Download direto com streaming | Dono ou Admin |
| `GET` | `/api/v1/files/:id/preview` | Visualização inline (PDF/Imagem) | Dono ou Admin |
| `POST` | `/api/v1/files/:id/presigned-download` | Gerar URL assinada de download | Dono ou Admin |
| `POST` | `/api/v1/files/presigned-upload` | Gerar URL assinada de upload | Usuário Autenticado |
| `PUT` | `/api/v1/files/:id/metadata` | Atualizar tags e visibilidade | Dono ou Admin |
| `DELETE` | `/api/v1/files/:id` | Excluir arquivo permanentemente | Dono ou Admin |
| `POST` | `/api/v1/files/batch-delete` | Exclusão em lote | Dono ou Admin |
| `GET` | `/api/v1/buckets` | Listar buckets MinIO | Role: Admin |
| `GET` | `/healthz` / `/readyz` | Health check liveness & readiness | Público |

---

## 🐳 Execução Rápida com Docker

```bash
# 1. Clonar o repositório
git clone https://github.com/graaalberto/graaa-golang-minio-api-file.git

cd graaa-golang-minio-api-file

go mod tidy - para baixar todas pendencia 

go run cmd/api/main.go 
ou 
docker-compose up.
````
# 2. Iniciar todos os serviços (Go API + MinIO + Auth API + PostgreSQL)
docker-compose up -d --build

# 3. Acessar as interfaces:
# - Go File API:        http://localhost:8000/healthz
# - MinIO Web Console:  http://localhost:9001 (User: minioadmin / Pass: minioadmin123)
# - Golang Auth API:    http://localhost:8080



 🐳 Rotas documentadas com exemplo


`Upload de Arquivo Único``
/api/v1/files/upload
curl -X POST http://localhost:8000/api/v1/files/upload \
  -H "Authorization: Bearer <SEU_TOKEN_JWT>" \
  -F "file=@/caminho/do/relatorio.pdf" \
  -F "is_public=false" \
  -F "tags=financeiro,relatorio"
Resposta:
{
    "success": true,
    "message": "Arquivo enviado com sucesso para o MinIO",
    "data": {
        "id": "4227e123-736f-4ed8-a11f-2621320ac38c",
        "name": "4227e123-736f-4ed8-a11f-2621320ac38c.jpg",
        "original_name": "20260731_092307.jpg",
        "bucket": "users-file",
        "path": "uploads/4227e123-736f-4ed8-a11f-2621320ac38c.jpg",
        "size_bytes": 9634927,
        "mime_type": "image/jpeg",
        "checksum_sha256": "d1c62b1450e3226ad0dc7ad333bb432eb163ac16d466cb60739676f58f6f9331",
        "uploaded_by": {
            "id": "",
            "email": "",
            "role": "user"
        },
        "upload_date": "2026-08-14T20:09:26.1476363Z",
        "is_public": false,
        "tags": [
            "Bilhete"
       ],
        "encryption": "SSE-S3"
    }
}

  Listar Arquivos do Usuário
  /api/v1/files
  curl -X GET "http://localhost:8000/api/v1/files?search=relatorio" \
  -H "Authorization: Bearer <SEU_TOKEN_JWT>"

  Obter Metadados do Arquivo
  /api/v1/files/:id
  curl -X GET http://localhost:8000/api/v1/files/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <SEU_TOKEN_JWT>"

  Download com Streaming Seguro
/api/v1/files/:id/download
curl -X GET http://localhost:8000/api/v1/files/550e8400-e29b-41d4-a716-446655440000/download \
  -H "Authorization: Bearer <SEU_TOKEN_JWT>" \
  --output "download_relatorio.pdf"

  Visualização Inline Segura (Preview)
  /api/v1/files/:id/preview
  curl -X GET http://localhost:8000/api/v1/files/550e8400-e29b-41d4-a716-446655440000/preview \
  -H "Authorization: Bearer <SEU_TOKEN_JWT>"

  Gerar URL Pré-Assinada de Download
  /api/v1/files/:id/presigned-download
  curl -X POST http://localhost:8000/api/v1/files/550e8400-e29b-41d4-a716-446655440000/presigned-download \
  -H "Authorization: Bearer <SEU_TOKEN_JWT>" \
  -H "Content-Type: application/json" \
  -d '{"expiry_seconds": 900}'

  Gerar URL Pré-Assinada de Upload Direto
  /api/v1/files/presigned-upload
curl -X POST http://localhost:8000/api/v1/files/presigned-upload \
  -H "Authorization: Bearer <SEU_TOKEN_JWT>" \
  -H "Content-Type: application/json" \
  -d '{"filename": "video_treinamento.mp4", "expiry_seconds": 1800}'

Atualizar Metadados e Tags
/api/v1/files/:id/metadata
curl -X PUT http://localhost:8000/api/v1/files/550e8400-e29b-41d4-a716-446655440000/metadata \
  -H "Authorization: Bearer <SEU_TOKEN_JWT>" \
  -H "Content-Type: application/json" \
  -d '{"tags": ["documentos", "aprovado"], "is_public": false}'

Excluir Arquivo Único
/api/v1/files/:id
curl -X DELETE http://localhost:8000/api/v1/files/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <SEU_TOKEN_JWT>"



