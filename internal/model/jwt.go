package model

import "github.com/golang-jwt/jwt/v5"

// CustomJWTClaims mapeia os claims emitidos pelo golang-auth-api
// https://github.com/gjovanovicst/golang-auth-api
//codigo original
//type CustomJWTClaims struct {
//UserID string `json:"id,omitempty"`
//Email  string `json:"email"`
//Role   string `json:"role"`
//jwt.RegisteredClaims
//codigo final original}

// codigo aualizado
type CustomJWTClaims struct {
	UserID    string   `json:"user_id"` // DEVE bater com "user_id" do JWT
	Email     string   `json:"email"`   // DEVE bater com "email"
	Role      string   `json:"role"`    // Para tokens com role única
	Roles     []string `json:"roles"`   // DEVE bater com "roles": ["admin"]
	AppID     string   `json:"app_id"`
	SessionID string   `json:"session_id"`
	jwt.RegisteredClaims
}

// GetPrimaryRole extrai a role principal (seja do campo Role ou do array Roles)
func (c *CustomJWTClaims) GetPrimaryRole() string {
	if c.Role != "" {
		return c.Role
	}
	if len(c.Roles) > 0 {
		return c.Roles[0]
	}
	return "user"
}
