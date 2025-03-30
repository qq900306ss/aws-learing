package handlers

import (
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/qq900306/pkg/product"
)

// GetProduct handles the GET request for a single product
func GetProduct(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*events.APIGatewayProxyResponse, error) {
	id := req.PathParameters["id"]
	
	if id != "" {
		result, err := product.FetchProduct(id, tableName, dynaClient)
		if err != nil {
			return apiResponse(http.StatusNotFound, ErrorBody{aws.String(err.Error())})
		}
		return apiResponse(http.StatusOK, result)
	}
	
	return apiResponse(http.StatusBadRequest, ErrorBody{aws.String("missing product ID")})
}

// GetProducts handles the GET request for all products
func GetProducts(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*events.APIGatewayProxyResponse, error) {
	result, err := product.FetchProducts(tableName, dynaClient)
	if err != nil {
		return apiResponse(http.StatusInternalServerError, ErrorBody{aws.String(err.Error())})
	}
	return apiResponse(http.StatusOK, result)
}

// CreateProduct handles the POST request to create a new product
func CreateProduct(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*events.APIGatewayProxyResponse, error) {
	// 檢查用戶是否為管理員
	errorResponse, isAdmin := CheckAdminAuth(req)
	if !isAdmin {
		return errorResponse, nil
	}
	
	result, err := product.CreateProduct(req, tableName, dynaClient)
	if err != nil {
		return apiResponse(http.StatusBadRequest, ErrorBody{
			aws.String(err.Error()),
		})
	}
	return apiResponse(http.StatusCreated, result)
}

// UpdateProduct handles the PUT request to update an existing product
func UpdateProduct(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*events.APIGatewayProxyResponse, error) {
	// 檢查用戶是否為管理員
	errorResponse, isAdmin := CheckAdminAuth(req)
	if !isAdmin {
		return errorResponse, nil
	}
	
	result, err := product.UpdateProduct(req, tableName, dynaClient)
	if err != nil {
		return apiResponse(http.StatusBadRequest, ErrorBody{
			aws.String(err.Error()),
		})
	}
	return apiResponse(http.StatusOK, result)
}

// DeleteProduct handles the DELETE request to remove a product
func DeleteProduct(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*events.APIGatewayProxyResponse, error) {
	// 檢查用戶是否為管理員
	errorResponse, isAdmin := CheckAdminAuth(req)
	if !isAdmin {
		return errorResponse, nil
	}
	
	err := product.DeleteProduct(req, tableName, dynaClient)
	if err != nil {
		return apiResponse(http.StatusBadRequest, ErrorBody{
			aws.String(err.Error()),
		})
	}
	return apiResponse(http.StatusOK, nil)
}
