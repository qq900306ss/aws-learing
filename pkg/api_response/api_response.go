package api_response

import (
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
)

// ErrorBody 表示錯誤響應的主體
type ErrorBody struct {
	ErrorMsg *string `json:"error,omitempty"`
}

// Success 創建成功的 API 響應
func Success(status int, body interface{}) (*events.APIGatewayProxyResponse, error) {
	return apiResponse(status, body)
}

// Error 創建錯誤的 API 響應
func Error(status int, errorMessage string) (*events.APIGatewayProxyResponse, error) {
	return apiResponse(status, ErrorBody{
		ErrorMsg: aws.String(errorMessage),
	})
}

// apiResponse 創建 API 響應
func apiResponse(status int, body interface{}) (*events.APIGatewayProxyResponse, error) {
	resp := events.APIGatewayProxyResponse{
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}
	resp.StatusCode = status
	stringBody, _ := json.Marshal(body)
	resp.Body = string(stringBody)
	return &resp, nil
}
