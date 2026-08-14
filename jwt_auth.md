package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"govault-api/internal/config"
	"govault-api/internal/model"
)

const (
	ContextUserIDKey    = "user_id"
	ContextUserEmailKey = "user_email"
	ContextUserRoleKey  = "user_role"
	ContextClaimsKey    = "jwt_claims"
)

// JWTAuthMiddleware valida tokens JWT emitidos pelo golang-auth-api
func JWTAuthMiddleware(cfg *config.Config, logger *zap.SugaredLogger) gin.HandlerFunc {
	httpClient := &http.Client{Timeout: 5 * time.Second}

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// Suporte alternativo para token via query param (ex: para downloads diretos via tag <img> ou link)
			authHeader = c.Query("token")
			if authHeader != "" {
				authHeader = "Bearer " + authHeader
			}
		}

		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{
				Success: false,
				Error:   "Token de autorização não fornecido no cabeçalho Authorization",
				Code:    "AUTH_TOKEN_MISSING",
			})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{
				Success: false,
				Error:   "Formato inválido de cabeçalho. Utilize 'Bearer <token>'",
				Code:    "AUTH_HEADER_INVALID",
			})
			return
		}

		tokenString := parts[1]

		var claims *model.CustomJWTClaims
		var err error

		if cfg.AuthValidationMode == "remote_introspection" {
			// Modo 1: Validação chamando o endpoint de introspecção do golang-auth-api
			claims, err = validateWithAuthAPI(httpClient, cfg.AuthAPIURL, tokenString)
		} else {
			// Modo 2: Validação rápida e descentralizada por assinatura criptográfica HMAC-SHA256
			claims, err = validateTokenLocally(tokenString, cfg.JWTSecretKey, cfg.JWTIssuer)
		}

		if err != nil {
			logger.Warnw("Falha na autenticação JWT", "error", err.Error(), "ip", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{
				Success: false,
				Error:   fmt.Sprintf("Token JWT inválido ou expirado: %v", err),
				Code:    "AUTH_TOKEN_INVALID",
			})
			return
		}

		// Armazenar os dados do usuário autenticado no contexto do Gin para uso nos handlers
		c.Set(ContextUserIDKey, claims.UserID)
		c.Set(ContextUserEmailKey, claims.Email)
		c.Set(ContextUserRoleKey, claims.Role)
		c.Set(ContextClaimsKey, claims)

		c.Next()
	}
}

// validateTokenLocally decodifica e valida o JWT contra a chave secreta compartilhada
func validateTokenLocally(tokenString, secretKey, expectedIssuer string) (*model.CustomJWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &model.CustomJWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		// Validar algoritmo de assinatura para prevenir ataques de downgrade (ex: 'none' algorithm)
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("algoritmo de assinatura inesperado: %v", t.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, err
	}
	// codigo da função Clains original
	// claims, ok := token.Claims.(*model.CustomJWTClaims)
	//
	//	if !ok || !token.Valid {
	//		return nil, errors.New("claims de JWT inválidas")
	//	}
	//
	// codigo atualizado da fincao Claims
	// Exemplo de como deve estar dentro do Handler do Middleware JWT:
	claims, ok := token.Claims.(*model.CustomJWTClaims)
	if ok && token.Valid {
		// Normaliza a Role principal a partir do array Roles se necessário
		if claims.Role == "" && len(claims.Roles) > 0 {
			claims.Role = claims.Roles[0]
		}

		// Injeta os claims no contexto do Gin
		c.Set("user", claims)
		c.Next()
		return
	}

	// Validar data de expiração (exp)
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, errors.New("o token JWT expirou")
	}

	// Normalizar ID do usuário se vier em 'sub' ou 'id'
	if claims.UserID == "" && claims.Subject != "" {
		claims.UserID = claims.Subject
	}

	if claims.Role == "" {
		claims.Role = "user" // Role padrão se omitido
	}

	return claims, nil
}

// validateWithAuthAPI realiza verificação HTTP remota com o golang-auth-api (/api/auth/validate ou /api/auth/user)
func validateWithAuthAPI(client *http.Client, authURL, token string) (*model.CustomJWTClaims, error) {
	req, err := http.NewRequest("GET", authURL+"/api/auth/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("não foi possível contactar golang-auth-api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("golang-auth-api rejeitou o token com status %d", resp.StatusCode)
	}

	var authUserResponse struct {
		ID    interface{} `json:"id"`
		Email string      `json:"email"`
		Role  string      `json:"role"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authUserResponse); err != nil {
		return nil, fmt.Errorf("erro ao ler resposta do auth-api: %w", err)
	}

	return &model.CustomJWTClaims{
		UserID: fmt.Sprintf("%v", authUserResponse.ID),
		Email:  authUserResponse.Email,
		Role:   authUserResponse.Role,
	}, nil
}

// RequireRole é um middleware de autorização baseado em papéis (RBAC)
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleVal, exists := c.Get(ContextUserRoleKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, model.ErrorResponse{
				Success: false,
				Error:   "Acesso negado: Perfil não identificado",
				Code:    "AUTH_FORBIDDEN",
			})
			return
		}

		userRole, ok := roleVal.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, model.ErrorResponse{
				Success: false,
				Error:   "Tipo de perfil inválido",
				Code:    "AUTH_FORBIDDEN",
			})
			return
		}

		// Se o usuário for admin, tem permissão total
		if userRole == "admin" {
			c.Next()
			return
		}

		for _, allowed := range allowedRoles {
			if strings.EqualFold(userRole, allowed) {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, model.ErrorResponse{
			Success: false,
			Error:   fmt.Sprintf("Acesso negado: Requer um dos seguintes privilégios: %v", allowedRoles),
			Code:    "AUTH_INSUFFICIENT_PRIVILEGES",
		})
	}
}
