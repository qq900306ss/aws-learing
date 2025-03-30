package auth

import (
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// AuthMiddleware checks if the request is authenticated
func AuthMiddleware(req events.APIGatewayProxyRequest) (*Claims, error) {
	// Get the Authorization header
	authHeader := req.Headers["Authorization"]
	if authHeader == "" {
		return nil, nil // No token provided
	}

	// Check if it's a Bearer token
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, nil // Not a Bearer token
	}

	// Extract the token
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate the token
	claims, err := ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// RequireAuth ensures the request is authenticated
func RequireAuth(req events.APIGatewayProxyRequest) (*Claims, *events.APIGatewayProxyResponse) {
	claims, err := AuthMiddleware(req)
	if err != nil {
		return nil, createErrorResponse(http.StatusUnauthorized, err.Error())
	}

	if claims == nil {
		return nil, createErrorResponse(http.StatusUnauthorized, "authentication required")
	}

	return claims, nil
}

// RequireAdmin ensures the request is authenticated and the user is an admin
func RequireAdmin(req events.APIGatewayProxyRequest) (*Claims, *events.APIGatewayProxyResponse) {
	claims, response := RequireAuth(req)
	if response != nil {
		return nil, response
	}

	if !claims.Admin {
		return nil, createErrorResponse(http.StatusForbidden, "admin privileges required")
	}

	return claims, nil
}

// AdminAuthMiddlewareAPIGateway 檢查 API Gateway 請求中的用戶是否為管理員
func AdminAuthMiddlewareAPIGateway(req events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, bool) {
	// 從請求頭中獲取 Authorization
	authHeader, ok := req.Headers["Authorization"]
	if !ok {
		return createErrorResponse(http.StatusUnauthorized, "未授權訪問"), false
	}

	// 驗證令牌
	claims, err := ValidateTokenGin(authHeader)
	if err != nil {
		return createErrorResponse(http.StatusUnauthorized, "無效的令牌"), false
	}

	// 檢查用戶是否為管理員
	if !claims.Admin {
		return createErrorResponse(http.StatusForbidden, "權限不足，需要管理員權限"), false
	}

	return nil, true
}
