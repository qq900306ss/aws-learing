package handlers

import (
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/qq900306/pkg/auth"
	"github.com/qq900306/pkg/api_response"
)

// HandleOAuth 處理 OAuth 認證
func HandleOAuth(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*events.APIGatewayProxyResponse, error) {
	return auth.HandleOAuth(req, tableName, dynaClient)
}

// GetUserProfileLambda 處理 Lambda 事件獲取用戶資料
func GetUserProfileLambda(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*events.APIGatewayProxyResponse, error) {
	// 從請求頭獲取 Authorization
	authHeader, ok := req.Headers["Authorization"]
	if !ok {
		return api_response.Error(http.StatusUnauthorized, "未提供授權令牌")
	}

	// 驗證令牌
	claims, err := auth.ValidateToken(authHeader)
	if err != nil {
		return api_response.Error(http.StatusUnauthorized, "無效的令牌")
	}

	// 從數據庫獲取用戶資料
	result, err := dynaClient.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(claims.UserID),
			},
		},
	})

	if err != nil {
		return api_response.Error(http.StatusInternalServerError, "獲取用戶資料時出錯")
	}

	// 如果用戶不存在
	if result.Item == nil {
		return api_response.Error(http.StatusNotFound, "用戶不存在")
	}

	// 反序列化用戶資料
	var user auth.User
	err = dynamodbattribute.UnmarshalMap(result.Item, &user)
	if err != nil {
		return api_response.Error(http.StatusInternalServerError, "解析用戶資料時出錯")
	}

	// 返回用戶資料
	return api_response.Success(http.StatusOK, user)
}
