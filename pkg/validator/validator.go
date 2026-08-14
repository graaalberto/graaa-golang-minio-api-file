package validator

import (
	"bytes"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
)

// Magic numbers para verificação profunda do cabeçalho binário
var magicSignatures = []struct {
	mimeType string
	sig      []byte
	offset   int
}{
	// Imagens
	{"image/png", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0},
	{"image/jpeg", []byte{0xFF, 0xD8, 0xFF}, 0},
	{"image/gif", []byte("GIF87a"), 0},
	{"image/gif", []byte("GIF89a"), 0},
	{"image/webp", []byte("WEBP"), 8},
	{"image/svg+xml", []byte("<?xml"), 0},
	{"image/svg+xml", []byte("<svg"), 0},

	// Documentos
	{"application/pdf", []byte("%PDF-"), 0},
	{"application/zip", []byte{0x50, 0x4B, 0x03, 0x04}, 0},
	{"application/gzip", []byte{0x1F, 0x8B}, 0},

	// Áudio e Vídeo
	{"video/mp4", []byte("ftyp"), 4},
	{"audio/mpeg", []byte{0xFF, 0xFB}, 0},
	{"audio/mpeg", []byte("ID3"), 0},
}

// Lista de tipos MIME seguros permitidos no sistema
var allowedMIMETypes = map[string]bool{
	// Imagens
	"image/png":     true,
	"image/jpeg":    true,
	"image/webp":    true,
	"image/gif":     true,
	"image/svg+xml": true,

	// Documentos
	"application/pdf":    true,
	"text/plain":         true,
	"text/csv":           true,
	"application/json":   true,
	"application/zip":    true,
	"application/msword": true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,

	// Mídia
	"video/mp4":  true,
	"audio/mpeg": true,
	"audio/wav":  true,
}

// DetectMimeTypeFromMagicBytes inspeciona os bytes reais do arquivo ao invés de confiar na extensão fornecida
func DetectMimeTypeFromMagicBytes(headerBytes []byte, originalFilename string) string {
	for _, m := range magicSignatures {
		if len(headerBytes) >= m.offset+len(m.sig) {
			if bytes.Equal(headerBytes[m.offset:m.offset+len(m.sig)], m.sig) {
				return m.mimeType
			}
		}
	}

	// Fallback padrão do Go (http.DetectContentType)
	detected := http.DetectContentType(headerBytes)
	if detected != "application/octet-stream" {
		return strings.Split(detected, ";")[0]
	}

	// Fallback por extensão segura
	ext := strings.ToLower(filepath.Ext(originalFilename))
	switch ext {
	case ".csv":
		return "text/csv"
	case ".json":
		return "application/json"
	case ".txt":
		return "text/plain"
	case ".pdf":
		return "application/pdf"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	}

	return "application/octet-stream"
}

func IsAllowedMimeType(mime string) bool {
	return allowedMIMETypes[mime]
}

var invalidCharRegex = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// SanitizeFilename previne Path Traversal (../, null bytes, caracteres de controle)
func SanitizeFilename(name string) string {
	base := filepath.Base(name)
	base = strings.ReplaceAll(base, "\x00", "")
	base = strings.ReplaceAll(base, "/", "")
	base = strings.ReplaceAll(base, "\\", "")
	base = strings.TrimSpace(base)

	// Remove caracteres perigosos
	cleaned := invalidCharRegex.ReplaceAllString(base, "_")
	if cleaned == "" || cleaned == "." {
		cleaned = "unnamed_file"
	}
	return cleaned
}
