package product

import (
	"encoding/json"
	"errors"
	"log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
)

// CartItem 表示購物車中的一個項目
type CartItem struct {
	ProductID string `json:"product_id"`
	Quantity  int    `json:"quantity"`
}

// CartRequest 表示計算總價的請求
type CartRequest struct {
	Items []CartItem `json:"items"`
}

// CartItemDetail 表示購物車項目的詳細信息
type CartItemDetail struct {
	ProductID   string  `json:"product_id"`
	Name        string  `json:"name"`
	Price       float64 `json:"price"`
	Quantity    int     `json:"quantity"`
	Category    string  `json:"category"`
	ImageURL    string  `json:"image_url"`
	Subtotal    float64 `json:"subtotal"`
}

// CartResponse 表示計算總價的響應
type CartResponse struct {
	Items      []CartItemDetail `json:"items"`
	TotalPrice float64          `json:"total_price"`
	ItemCount  int              `json:"item_count"`
}

// CalculateCart 計算購物車中商品的總價
func CalculateCart(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*CartResponse, error) {
	var cartReq CartRequest
	if err := json.Unmarshal([]byte(req.Body), &cartReq); err != nil {
		log.Printf("解析購物車請求失敗: %v", err)
		return nil, errors.New("無效的購物車數據")
	}

	if len(cartReq.Items) == 0 {
		return &CartResponse{
			Items:      []CartItemDetail{},
			TotalPrice: 0,
			ItemCount:  0,
		}, nil
	}

	response := CartResponse{
		Items:      []CartItemDetail{},
		TotalPrice: 0,
		ItemCount:  0,
	}

	// 獲取每個商品的詳細信息並計算小計
	for _, item := range cartReq.Items {
		if item.Quantity <= 0 {
			continue // 跳過數量為零或負數的項目
		}

		// 從數據庫獲取商品信息
		product, err := FetchProduct(item.ProductID, tableName, dynaClient)
		if err != nil {
			log.Printf("獲取商品 %s 失敗: %v", item.ProductID, err)
			continue // 跳過無法獲取的商品
		}

		// 計算小計
		subtotal := product.Price * float64(item.Quantity)

		// 添加到響應中
		detail := CartItemDetail{
			ProductID:   product.ID,
			Name:        product.Name,
			Price:       product.Price,
			Quantity:    item.Quantity,
			Category:    product.Category,
			ImageURL:    product.ImageURL,
			Subtotal:    subtotal,
		}
		response.Items = append(response.Items, detail)
		response.TotalPrice += subtotal
		response.ItemCount += item.Quantity
	}

	return &response, nil
}
