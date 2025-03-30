package router

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/gin-gonic/gin"
	"github.com/qq900306/pkg/auth"
	"github.com/qq900306/pkg/product"
)

// 前端應用程式 URL
const frontendURL = "https://main.d37j5zzkd2621x.amplifyapp.com"

// 設置 Gin 路由器
func SetupRouter(userTableName, productTableName string, dynaClient dynamodbiface.DynamoDBAPI) *gin.Engine {
	// 設置為發布模式
	gin.SetMode(gin.ReleaseMode)

	// 創建一個默認的路由器
	r := gin.Default()

	// 添加 CORS 中間件
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", frontendURL)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// 基礎路徑
	base := r.Group("/")

	// 健康檢查
	base.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	// OAuth 認證
	base.POST("/oauth", func(c *gin.Context) {
		handleOAuth(c, userTableName, dynaClient)
	})

	// OAuth 回調處理
	base.GET("/oauth/callback", func(c *gin.Context) {
		HandleOAuthCallback(c, userTableName, dynaClient)
	})

	// 用戶資料 API
	base.GET("/user/profile", func(c *gin.Context) {
		getUserProfile(c, userTableName, dynaClient)
	})

	// 商品相關路由
	products := base.Group("/products")
	{
		// 獲取所有商品或單個商品（通過查詢參數）
		products.GET("", func(c *gin.Context) {
			// 檢查是否有 id 查詢參數
			id := c.Query("id")
			if id != "" {
				// 如果有 id 參數，獲取單個商品
				getProduct(c, productTableName, dynaClient)
			} else {
				// 否則獲取所有商品
				getProducts(c, productTableName, dynaClient)
			}
		})

		// 計算購物車總價
		products.POST("/calculate-cart", func(c *gin.Context) {
			calculateCart(c, productTableName, dynaClient)
		})

		// 需要管理員權限的路由
		admin := products.Group("")
		admin.Use(adminAuthMiddleware())
		{
			// 創建商品
			admin.POST("", func(c *gin.Context) {
				createProduct(c, productTableName, dynaClient)
			})

			// 更新商品（通過查詢參數）
			admin.PUT("", func(c *gin.Context) {
				updateProduct(c, productTableName, dynaClient)
			})

			// 刪除商品（通過查詢參數）
			admin.DELETE("", func(c *gin.Context) {
				deleteProduct(c, productTableName, dynaClient)
			})
		}
	}

	return r
}

// 處理 OAuth 認證
func handleOAuth(c *gin.Context, tableName string, dynaClient dynamodbiface.DynamoDBAPI) {
	var requestBody struct {
		Code string `json:"code"`
	}

	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無效的授權碼"})
		return
	}

	// 處理 OAuth 認證
	user, token, err := auth.ProcessOAuth(requestBody.Code, tableName, dynaClient)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  user,
	})
}

// 處理 OAuth 回調
func HandleOAuthCallback(c *gin.Context, tableName string, dynaClient dynamodbiface.DynamoDBAPI) {
	// 從查詢參數獲取授權碼
	code := c.Query("code")
	if code == "" {
		// 如果沒有授權碼，重定向到前端錯誤頁面
		c.Redirect(http.StatusTemporaryRedirect, frontendURL+"/auth-error")
		return
	}

	// 處理 OAuth 認證
	user, token, err := auth.ProcessOAuth(code, tableName, dynaClient)
	if err != nil {
		// 如果認證失敗，重定向到前端錯誤頁面
		c.Redirect(http.StatusTemporaryRedirect, frontendURL+"/auth-error?error="+err.Error())
		return
	}

	// 將令牌和用戶信息作為查詢參數添加到重定向 URL
	redirectURL := frontendURL + "/auth-success?token=" + token + "&userId=" + user.ID

	// 重定向到前端成功頁面
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// 獲取所有商品
func getProducts(c *gin.Context, tableName string, dynaClient dynamodbiface.DynamoDBAPI) {
	products, err := product.FetchProducts(tableName, dynaClient)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, products)
}

// 獲取單個商品
func getProduct(c *gin.Context, tableName string, dynaClient dynamodbiface.DynamoDBAPI) {
	// 嘗試從路徑參數獲取 ID
	id := c.Query("id")

	// 如果路徑參數中沒有 ID，嘗試從查詢參數獲取
	if id == "" {
		id = c.Query("id")
	}

	// 如果仍然沒有 ID，返回錯誤
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少商品 ID"})
		return
	}

	log.Printf("獲取商品，ID: %s", id)

	product, err := product.FetchProduct(id, tableName, dynaClient)
	if err != nil {
		log.Printf("獲取商品失敗: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	log.Printf("成功獲取商品: %s", product.Name)
	c.JSON(http.StatusOK, product)
}

// 創建商品
func createProduct(c *gin.Context, tableName string, dynaClient dynamodbiface.DynamoDBAPI) {
	var p product.Product
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無效的商品數據"})
		return
	}

	// 使用 AWS Lambda 版本的函數，但先準備好請求
	reqBody, _ := json.Marshal(p)
	req := events.APIGatewayProxyRequest{
		Body: string(reqBody),
	}

	newProduct, err := product.CreateProduct(req, tableName, dynaClient)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, newProduct)
}

// 更新商品
func updateProduct(c *gin.Context, tableName string, dynaClient dynamodbiface.DynamoDBAPI) {
	id := c.Query("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少商品 ID"})
		return
	}

	var p product.Product
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無效的商品數據"})
		return
	}

	// 使用 AWS Lambda 版本的函數，但先準備好請求
	reqBody, _ := json.Marshal(p)
	req := events.APIGatewayProxyRequest{
		Body: string(reqBody),
		PathParameters: map[string]string{
			"id": id,
		},
	}

	updatedProduct, err := product.UpdateProduct(req, tableName, dynaClient)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, updatedProduct)
}

// 刪除商品
func deleteProduct(c *gin.Context, tableName string, dynaClient dynamodbiface.DynamoDBAPI) {
	id := c.Query("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少商品 ID"})
		return
	}

	// 使用 AWS Lambda 版本的函數，但先準備好請求
	req := events.APIGatewayProxyRequest{
		PathParameters: map[string]string{
			"id": id,
		},
	}

	err := product.DeleteProduct(req, tableName, dynaClient)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "商品已成功刪除"})
}

// 獲取用戶資料
func getUserProfile(c *gin.Context, tableName string, dynaClient dynamodbiface.DynamoDBAPI) {
	// 從請求頭獲取 Authorization 標頭
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		log.Println("獲取用戶資料失敗: 未提供認證令牌")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "需要認證"})
		return
	}

	log.Printf("獲取用戶資料: 收到認證頭: %s", authHeader[:10]+"...")
	log.Printf("使用表名: %s", tableName)

	// 驗證 JWT 令牌
	claims, err := auth.ValidateTokenGin(authHeader)
	if err != nil {
		log.Printf("獲取用戶資料失敗: 令牌驗證錯誤: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	log.Printf("令牌驗證成功, 用戶ID: %s", claims.UserID)

	// 獲取用戶資料
	user, err := auth.GetUserProfile(claims.UserID, tableName, dynaClient)
	if err != nil {
		log.Printf("獲取用戶資料失敗: 數據庫查詢錯誤: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("成功獲取用戶資料: %s (%s)", user.Name, user.Email)
	c.JSON(http.StatusOK, user)
}

// 管理員認證中間件
func adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 從請求頭獲取 Authorization 標頭
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "需要認證"})
			c.Abort()
			return
		}

		// 驗證 JWT 令牌
		claims, err := auth.ValidateTokenGin(authHeader)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// 檢查管理員權限
		if !claims.Admin {
			c.JSON(http.StatusForbidden, gin.H{"error": "需要管理員權限"})
			c.Abort()
			return
		}

		// 將用戶信息存儲在上下文中
		c.Set("userId", claims.UserID)
		c.Set("userEmail", claims.Email)
		c.Set("isAdmin", claims.Admin)

		c.Next()
	}
}

// 計算購物車總價
func calculateCart(c *gin.Context, tableName string, dynaClient dynamodbiface.DynamoDBAPI) {
	// 從請求體讀取數據
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Printf("讀取請求體失敗: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "無效的請求"})
		return
	}
	
	// 準備 Lambda 請求
	req := events.APIGatewayProxyRequest{
		Body: string(body),
	}
	
	// 調用計算函數
	response, err := product.CalculateCart(req, tableName, dynaClient)
	if err != nil {
		log.Printf("計算購物車失敗: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, response)
}
