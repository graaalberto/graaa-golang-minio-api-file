# Build Stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Compilação estática sem CGO para máxima performance e segurança
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -X main.version=1.0.0" -o /app/govault-api ./cmd/api/main.go

# Production Stage (Distroless minimalista & seguro)
FROM alpine:3.19

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/govault-api /app/govault-api

USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/govault-api"]
