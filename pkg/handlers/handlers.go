package handlers

import (
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/qq900306/pkg/api_response"
)

var ErrorMethodNotAllowed = "Method Not Allowed"

type ErrorBody struct {
	Error *string `json:"error,omitempty"`
}

func UnhhandledMethod() (*events.APIGatewayProxyResponse, error) {
	return api_response.Error(http.StatusMethodNotAllowed, ErrorMethodNotAllowed)
}
