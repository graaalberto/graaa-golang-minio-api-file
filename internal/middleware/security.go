package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// SecurityHeaders injeta cabeçalhos de proteção recomendados pela OWASP
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Evita que o navegador infira o Content-Type (previne ataques MIME sniffing)
		c.Header("X-Content-Type-Options", "nosniff")
		
		// Proteção contra Clickjacking
		c.Header("X-Frame-Options", "DENY")
		
		// Ativa proteção XSS nos navegadores legados
		c.Header("X-XSS-Protection", "1; mode=block")
		
		// HSTS (Força HTTPS em produção)
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		
		// Content Security Policy segura para respostas da API
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox;")
		
		// Política de Referrer
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Previne cache de respostas sensíveis por padrão
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		c.Next()
	}
}

// CORS configura permissões de origem cruzada de forma segura
func CORS(allowedOrigins []string) gin.HandlerFunc {
	originsMap := make(map[string]bool)
	allowAll := false
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
		}
		originsMap[o] = true
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if allowAll || originsMap[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-File-Checksum, X-Original-Filename")
			c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")
			c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Disposition, Content-Type, X-File-ID, X-File-Checksum")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// IPRateLimiter implementa limitação de requisições por IP usando Token Bucket
type IPRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  *sync.RWMutex
	r   rate.Limit
	b   int
}

func RateLimiter(requestsPerMinute int) gin.HandlerFunc {
	limiter := &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
		mu:  &sync.RWMutex{},
		r:   rate.Every(time.Minute / time.Duration(requestsPerMinute)),
		b:   requestsPerMinute,
	}

	// Limpeza periódica de IPs inativos a cada 10 minutos
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			limiter.mu.Lock()
			limiter.ips = make(map[string]*rate.Limiter)
			limiter.mu.Unlock()
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()
		
		limiter.mu.Lock()
		l, exists := limiter.ips[ip]
		if !exists {
			l = rate.NewLimiter(limiter.r, limiter.b)
			limiter.ips[ip] = l
		}
		limiter.mu.Unlock()

		if !l.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"error":   "Taxa limite de requisições excedida. Tente novamente em instantes.",
				"code":    "RATE_LIMIT_EXCEEDED",
			})
			return
		}

		c.Next()
	}
}
