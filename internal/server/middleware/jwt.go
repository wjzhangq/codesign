package middleware

import (
	"context"
	"net/http"
	"strings"

	"codesign/internal/server/token"
)

// contextKey 用于在 context 中存储用户信息
type contextKey string

const userKey contextKey = "user"

// JWT 创建 JWT 验证中间件
func JWT(tm *token.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeJSONError(w, http.StatusUnauthorized, "missing Authorization header")
				return
			}

			const prefix = "Bearer "
			if !strings.HasPrefix(authHeader, prefix) {
				writeJSONError(w, http.StatusUnauthorized, "invalid Authorization format, expected Bearer <token>")
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, prefix)
			if tokenStr == "" {
				writeJSONError(w, http.StatusUnauthorized, "empty token")
				return
			}

			user, err := tm.Verify(tokenStr)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
				return
			}

			// 将用户名注入请求 context
			ctx := contextWithUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// JWTHandler 对单个 handler 应用 JWT 中间件
func JWTHandler(tm *token.Manager, h http.Handler) http.Handler {
	return JWT(tm)(h)
}

// contextWithUser 将用户名存入 context
func contextWithUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, userKey, user)
}

// UserFromContext 从 context 取出用户名
func UserFromContext(ctx context.Context) string {
	user, _ := ctx.Value(userKey).(string)
	return user
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(`{"error":"` + escapeJSON(msg) + `"}`)) //nolint:errcheck
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
