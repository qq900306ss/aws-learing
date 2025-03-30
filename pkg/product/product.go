package product

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
)

var (
	ErrorFailedToFetchRecord     = "無法獲取記錄"
	ErrorFailedToUnmarshalMap    = "無法解析映射"
	ErrorFailedToCreateProduct   = "無法創建商品"
	ErrorInvalidProductData      = "無效的商品數據"
	ErrorCouldNotMarshalItem     = "無法序列化項目"
	ErrorCouldNotDeleteItem      = "無法刪除項目"
	ErrorCouldNotDynamoPutItem   = "無法將項目放入 DynamoDB"
	ErrorProductAlreadyExists    = "商品已存在"
	ErrorProductDoesNotExist     = "商品不存在"
	ErrorInsufficientPermissions = "權限不足"
)

// Product 表示商店中的商品
type Product struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Price     float64   `json:"price"`
	Stock     int       `json:"stock"`
	Category  string    `json:"category"`
	ImageURL  string    `json:"image"` // 修改為 image 而不是 image_url
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FetchProduct 通過 ID 獲取商品
func FetchProduct(id string, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*Product, error) {
	input := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(id),
			},
		},
		TableName: aws.String(tableName),
	}

	result, err := dynaClient.GetItem(input)
	if err != nil {
		return nil, errors.New(ErrorFailedToFetchRecord)
	}

	if result.Item == nil {
		return nil, errors.New(ErrorProductDoesNotExist)
	}

	item := new(Product)
	err = dynamodbattribute.UnmarshalMap(result.Item, item)
	if err != nil {
		return nil, errors.New(ErrorFailedToUnmarshalMap)
	}
	return item, nil
}

// FetchProducts 獲取所有商品
func FetchProducts(tableName string, dynaClient dynamodbiface.DynamoDBAPI) ([]Product, error) {
	input := &dynamodb.ScanInput{
		TableName: aws.String(tableName),
	}
	result, err := dynaClient.Scan(input)
	if err != nil {
		return nil, errors.New(ErrorFailedToFetchRecord)
	}
	var products []Product
	err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &products)
	if err != nil {
		return nil, errors.New(ErrorFailedToUnmarshalMap)
	}
	return products, nil
}

// CreateProduct 創建新商品
func CreateProduct(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*Product, error) {
	var p Product
	err := json.Unmarshal([]byte(req.Body), &p)
	if err != nil {
		return nil, errors.New(ErrorInvalidProductData)
	}

	// 為商品生成新的 UUID
	p.ID = uuid.New().String()
	
	// 設置時間戳
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now

	av, err := dynamodbattribute.MarshalMap(p)
	if err != nil {
		return nil, errors.New(ErrorCouldNotMarshalItem)
	}
	
	input := &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      av,
	}
	
	_, err = dynaClient.PutItem(input)
	if err != nil {
		return nil, errors.New(ErrorCouldNotDynamoPutItem)
	}
	
	return &p, nil
}

// UpdateProduct 更新現有商品
func UpdateProduct(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*Product, error) {
	id := req.PathParameters["id"]
	if id == "" {
		return nil, errors.New("缺少商品 ID")
	}

	// 檢查商品是否存在
	existingProduct, err := FetchProduct(id, tableName, dynaClient)
	if err != nil {
		return nil, err
	}

	var updatedProduct Product
	err = json.Unmarshal([]byte(req.Body), &updatedProduct)
	if err != nil {
		return nil, errors.New(ErrorInvalidProductData)
	}

	// 保留原始 ID 和創建時間
	updatedProduct.ID = existingProduct.ID
	updatedProduct.CreatedAt = existingProduct.CreatedAt
	updatedProduct.UpdatedAt = time.Now()

	av, err := dynamodbattribute.MarshalMap(updatedProduct)
	if err != nil {
		return nil, errors.New(ErrorCouldNotMarshalItem)
	}
	
	input := &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      av,
	}
	
	_, err = dynaClient.PutItem(input)
	if err != nil {
		return nil, errors.New(ErrorCouldNotDynamoPutItem)
	}
	
	return &updatedProduct, nil
}

// DeleteProduct 通過 ID 刪除商品
func DeleteProduct(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) error {
	id := req.PathParameters["id"]
	if id == "" {
		return errors.New("缺少商品 ID")
	}

	input := &dynamodb.DeleteItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(id),
			},
		},
	}
	
	_, err := dynaClient.DeleteItem(input)
	if err != nil {
		return errors.New(ErrorCouldNotDeleteItem)
	}
	
	return nil
}
