package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
	"github.com/gin-gonic/gin"
	"github.com/qq900306/pkg/auth"
	"github.com/qq900306/pkg/router"
)

var (
	dynaClient dynamodbiface.DynamoDBAPI
	ginLambda  *ginadapter.GinLambda
)

const (
	userTableName    = "LamdaInGoUser"
	productTableName = "LamdaInGoProduct"
	cartTableName    = "carts"
)

// 初始化函數，在 Lambda 冷啟動時執行
func init() {
	// 設置 AWS 區域
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-west-2" // 默認區域
	}

	// 創建 AWS 會話
	awsSession, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		log.Fatalf("無法創建 AWS 會話: %v", err)
	}

	// 初始化 DynamoDB 客戶端
	dynaClient = dynamodb.New(awsSession)

	// 確保購物車表格存在
	ensureCartTableExists()

	// 設置 Gin 路由器
	r := router.SetupRouter(userTableName, productTableName, dynaClient)

	// 添加一個通配符路由，用於處理可能的路徑前綴問題
	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		// 記錄請求路徑，幫助診斷
		log.Printf("收到未匹配的路徑請求: %s", path)
		log.Printf("請求方法: %s", c.Request.Method)
		log.Printf("完整 URL: %s", c.Request.URL.String())

		// 檢查是否是 oauth/callback 路徑（可能帶有前綴）
		if strings.Contains(path, "/oauth/callback") {
			log.Printf("檢測到 OAuth 回調路徑，嘗試處理")
			// 處理 OAuth 回調
			router.HandleOAuthCallback(c, userTableName, dynaClient)
			return
		}

		// 其他未匹配的路徑返回 404
		c.JSON(http.StatusNotFound, gin.H{"error": "路徑不存在"})
	})

	// 初始化 Gin Lambda 適配器
	ginLambda = ginadapter.New(r)
}

// 確保購物車表格存在
func ensureCartTableExists() {
	// 檢查表格是否存在
	_, err := dynaClient.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: aws.String(cartTableName),
	})

	// 如果表格不存在，創建它
	if err != nil {
		log.Printf("購物車表格不存在，正在創建: %v", err)

		// 創建表格
		_, err = dynaClient.CreateTable(&dynamodb.CreateTableInput{
			TableName: aws.String(cartTableName),
			AttributeDefinitions: []*dynamodb.AttributeDefinition{
				{
					AttributeName: aws.String("id"),
					AttributeType: aws.String("S"),
				},
				{
					AttributeName: aws.String("user_id"),
					AttributeType: aws.String("S"),
				},
			},
			KeySchema: []*dynamodb.KeySchemaElement{
				{
					AttributeName: aws.String("id"),
					KeyType:       aws.String("HASH"),
				},
			},
			GlobalSecondaryIndexes: []*dynamodb.GlobalSecondaryIndex{
				{
					IndexName: aws.String("UserIDIndex"),
					KeySchema: []*dynamodb.KeySchemaElement{
						{
							AttributeName: aws.String("user_id"),
							KeyType:       aws.String("HASH"),
						},
					},
					Projection: &dynamodb.Projection{
						ProjectionType: aws.String("ALL"),
					},
					ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
						ReadCapacityUnits:  aws.Int64(5),
						WriteCapacityUnits: aws.Int64(5),
					},
				},
			},
			ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(5),
				WriteCapacityUnits: aws.Int64(5),
			},
		})

		if err != nil {
			log.Printf("創建購物車表格失敗: %v", err)
		} else {
			log.Printf("成功創建購物車表格")
		}
	} else {
		log.Printf("購物車表格已存在")
	}
}

// 處理 Lambda 請求
func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// 打印完整的請求信息，幫助診斷
	reqJSON, _ := json.Marshal(req)
	log.Printf("完整的 API Gateway 事件: %s", string(reqJSON))

	// 檢查 requestContext 中的路徑信息
	if req.RequestContext.Path != "" {
		log.Printf("RequestContext.Path = %s", req.RequestContext.Path)
	}
	if req.RequestContext.Stage != "" {
		log.Printf("RequestContext.Stage = %s", req.RequestContext.Stage)
	}
	if req.RequestContext.ResourcePath != "" {
		log.Printf("RequestContext.ResourcePath = %s", req.RequestContext.ResourcePath)
	}

	// 記錄請求信息，幫助診斷
	log.Printf("收到請求: 路徑=%s, 方法=%s, 查詢參數=%v", req.Path, req.HTTPMethod, req.QueryStringParameters)

	// 檢查各種可能的路徑
	if req.Path == "/" {
		log.Printf("檢測到根路徑 '/'")
	}
	if req.Path == "/oauth" {
		log.Printf("檢測到 OAuth 路徑 '/oauth'")
	}
	if req.Path == "/oauth/callback" {
		log.Printf("檢測到 OAuth 回調路徑 '/oauth/callback'")
	}
	if strings.HasPrefix(req.Path, "/staging") {
		log.Printf("檢測到帶有 staging 前綴的路徑: '%s'", req.Path)
	}
	if strings.HasPrefix(req.Path, "/staging/oauth") {
		log.Printf("檢測到帶有 staging 前綴的 OAuth 路徑: '%s'", req.Path)
	}
	if strings.Contains(req.Path, "/oauth/callback") {
		log.Printf("檢測到包含 '/oauth/callback' 的路徑: '%s'", req.Path)
	}

	// 直接處理 /test 路徑
	if req.Path == "/test" || strings.HasSuffix(req.RequestContext.Path, "/test") || req.Path == "/staging/test" {
		log.Printf("直接處理 /test 路徑")
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusOK,
			Body:       `{"message":"測試成功 - 直接從 Lambda 處理函數返回","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	// 直接處理 /oauth 測試端點
	if (req.Path == "/oauth" || strings.HasSuffix(req.RequestContext.Path, "/oauth")) && req.HTTPMethod == "POST" {
		log.Printf("處理 OAuth 測試端點")
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusOK,
			Body:       `{"message":"OAuth 測試端點成功響應","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	// 直接處理 /oauth 測試端點 (GET 方法)
	if (req.Path == "/oauth" || strings.HasSuffix(req.RequestContext.Path, "/oauth")) && req.HTTPMethod == "GET" {
		log.Printf("處理 OAuth 測試端點 (GET)")
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusOK,
			Body:       `{"message":"OAuth GET 測試端點成功響應","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil
	}

	// 檢查是否是 OAuth 回調請求（通過查詢參數判斷）
	if _, ok := req.QueryStringParameters["code"]; ok {
		log.Printf("檢測到包含 code 參數的請求，可能是 OAuth 回調")

		// 從查詢參數獲取授權碼
		code := req.QueryStringParameters["code"]
		log.Printf("獲取到授權碼: %s", code)

		// 處理 OAuth 認證
		user, token, err := auth.ProcessOAuth(code, userTableName, dynaClient)
		if err != nil {
			log.Printf("處理 OAuth 失敗: %v", err)
			// 如果認證失敗，重定向到前端錯誤頁面
			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusTemporaryRedirect,
				Headers: map[string]string{
					"Location": "https://main.d37j5zzkd2621x.amplifyapp.com/auth-error?error=" + url.QueryEscape(err.Error()),
				},
			}, nil
		}

		log.Printf("認證成功，用戶 ID: %s", user.ID)

		// 將令牌和用戶信息作為查詢參數添加到重定向 URL
		redirectURL := "https://main.d37j5zzkd2621x.amplifyapp.com/auth-success?token=" + url.QueryEscape(token) + "&userId=" + url.QueryEscape(user.ID)

		log.Printf("重定向到: %s", redirectURL)

		// 重定向到前端成功頁面
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusTemporaryRedirect,
			Headers: map[string]string{
				"Location": redirectURL,
			},
		}, nil
	}

	// 根據路徑和方法處理不同的請求
	switch {
	// 健康檢查
	case req.Path == "/health" && req.HTTPMethod == "GET":
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusOK,
			Body:       `{"status":"ok"}`,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}, nil

	// OAuth 回調處理 - 處理任何包含 /oauth/callback 的路徑
	case strings.Contains(req.Path, "/oauth/callback") && req.HTTPMethod == "GET":
		log.Printf("處理 OAuth 回調: %s", req.Path)

		// 從查詢參數獲取授權碼
		code, ok := req.QueryStringParameters["code"]
		if !ok || code == "" {
			log.Printf("未找到授權碼")
			// 如果沒有授權碼，重定向到前端錯誤頁面
			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusTemporaryRedirect,
				Headers: map[string]string{
					"Location": "https://main.d37j5zzkd2621x.amplifyapp.com/auth-error?error=missing_code",
				},
			}, nil
		}

		log.Printf("獲取到授權碼: %s", code)

		// 處理 OAuth 認證
		user, token, err := auth.ProcessOAuth(code, userTableName, dynaClient)
		if err != nil {
			log.Printf("處理 OAuth 失敗: %v", err)
			// 如果認證失敗，重定向到前端錯誤頁面
			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusTemporaryRedirect,
				Headers: map[string]string{
					"Location": "https://main.d37j5zzkd2621x.amplifyapp.com/auth-error?error=" + url.QueryEscape(err.Error()),
				},
			}, nil
		}

		log.Printf("認證成功，用戶 ID: %s", user.ID)

		// 將令牌和用戶信息作為查詢參數添加到重定向 URL
		redirectURL := "https://main.d37j5zzkd2621x.amplifyapp.com/auth-success?token=" + url.QueryEscape(token) + "&userId=" + url.QueryEscape(user.ID)

		log.Printf("重定向到: %s", redirectURL)

		// 重定向到前端成功頁面
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusTemporaryRedirect,
			Headers: map[string]string{
				"Location": redirectURL,
			},
		}, nil

	// 其他請求使用 Gin 路由器處理
	default:
		return ginLambda.ProxyWithContext(ctx, req)
	}
}

// 處理 Lambda 函數 URL 請求
func handlerFunctionURL(ctx context.Context, req events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	// 打印完整的請求信息，幫助診斷
	reqJSON, _ := json.Marshal(req)
	log.Printf("完整的 Lambda 函數 URL 事件: %s", string(reqJSON))

	// 記錄請求信息
	log.Printf("收到 Lambda 函數 URL 請求: 路徑=%s, 方法=%s", req.RequestContext.HTTP.Path, req.RequestContext.HTTP.Method)

	// 轉換為 API Gateway 格式的請求，以便重用現有代碼
	apiGatewayReq := events.APIGatewayProxyRequest{
		Path:                  req.RequestContext.HTTP.Path,
		HTTPMethod:            req.RequestContext.HTTP.Method,
		Headers:               req.Headers,
		QueryStringParameters: req.QueryStringParameters,
		Body:                  req.Body,
		IsBase64Encoded:       req.IsBase64Encoded,
	}

	// 使用現有的處理函數處理請求
	resp, err := handler(ctx, apiGatewayReq)
	if err != nil {
		return events.LambdaFunctionURLResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       `{"error":"內部服務器錯誤"}`,
		}, err
	}

	// 轉換為 Lambda 函數 URL 格式的響應
	return events.LambdaFunctionURLResponse{
		StatusCode:      resp.StatusCode,
		Headers:         resp.Headers,
		Body:            resp.Body,
		IsBase64Encoded: resp.IsBase64Encoded,
	}, nil
}

func main() {
	// 判斷是使用 API Gateway 還是 Lambda 函數 URL
	if os.Getenv("AWS_LAMBDA_FUNCTION_URL") != "" {
		// 使用 Lambda 函數 URL
		lambda.Start(handlerFunctionURL)
	} else {
		// 使用 API Gateway
		lambda.Start(handler)
	}
}
