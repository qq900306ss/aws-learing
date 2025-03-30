package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/dgrijalva/jwt-go"
)

var (
	ErrorInvalidCode           = "無效的授權碼"
	ErrorExchangingToken       = "交換令牌時出錯"
	ErrorFetchingUserInfo      = "獲取用戶信息時出錯"
	ErrorCreatingUser          = "創建用戶時出錯"
	ErrorGeneratingToken       = "生成令牌時出錯"
	ErrorInvalidToken          = "無效的令牌"
	ErrorTokenExpired          = "令牌已過期"
	ErrorCouldNotMarshalItem   = "無法序列化項目"
	ErrorCouldNotDynamoPutItem = "無法將項目放入 DynamoDB"
)

// User 表示系統中的用戶
type User struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	Phone       string    `json:"phone,omitempty"`
	GoogleID    string    `json:"google_id"`
	ResourceKey string    `json:"resource_key,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	IsAdmin     bool      `json:"is_admin"`
}

// GoogleUserInfo 表示 Google 返回的用戶信息
type GoogleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

// TokenResponse 表示 Google 令牌端點的響應
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
}

// Claims 表示 JWT 聲明
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Admin  bool   `json:"admin"`
	jwt.StandardClaims
}

// HandleOAuth 處理 OAuth 代碼並返回 JWT 令牌
func HandleOAuth(req events.APIGatewayProxyRequest, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*events.APIGatewayProxyResponse, error) {
	var requestBody struct {
		Code string `json:"code"`
	}

	err := json.Unmarshal([]byte(req.Body), &requestBody)
	if err != nil {
		return createErrorResponse(http.StatusBadRequest, ErrorInvalidCode), nil
	}

	// 處理 OAuth 認證
	user, token, err := ProcessOAuth(requestBody.Code, tableName, dynaClient)
	if err != nil {
		return createErrorResponse(http.StatusBadRequest, err.Error()), nil
	}

	// 返回令牌
	response := struct {
		Token string `json:"token"`
		User  User   `json:"user"`
	}{
		Token: token,
		User:  *user,
	}

	jsonResponse, _ := json.Marshal(response)
	return &events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(jsonResponse),
	}, nil
}

// ProcessOAuth 處理 OAuth 代碼並返回用戶和令牌
func ProcessOAuth(code string, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*User, string, error) {
	log.Printf("開始處理 OAuth 代碼: %s", code)

	if code == "" {
		log.Printf("OAuth 代碼為空")
		return nil, "", errors.New(ErrorInvalidCode)
	}

	if tableName == "" {
		tableName = "LamdaInGoUser"
		log.Printf("使用默認表名: %s", tableName)
	}

	// 交換代碼獲取令牌
	log.Printf("嘗試交換代碼獲取令牌")
	tokenResponse, err := exchangeCodeForToken(code)
	if err != nil {
		log.Printf("交換令牌失敗: %v", err)
		return nil, "", errors.New(ErrorExchangingToken)
	}

	if tokenResponse == nil || tokenResponse.AccessToken == "" {
		log.Printf("令牌響應為空或訪問令牌為空")
		return nil, "", errors.New(ErrorExchangingToken)
	}

	log.Printf("成功獲取訪問令牌")

	// 從 Google 獲取用戶信息
	log.Printf("嘗試從 Google 獲取用戶信息")
	userInfo, err := getUserInfo(tokenResponse.AccessToken)
	if err != nil {
		log.Printf("獲取用戶信息失敗: %v", err)
		return nil, "", errors.New(ErrorFetchingUserInfo)
	}

	if userInfo == nil {
		log.Printf("用戶信息為空")
		return nil, "", errors.New(ErrorFetchingUserInfo)
	}

	log.Printf("成功獲取用戶信息: ID=%s, Email=%s", userInfo.Sub, userInfo.Email)

	// 檢查用戶是否存在，如果不存在則創建
	log.Printf("嘗試查找或創建用戶")
	user, err := findOrCreateUser(userInfo, tableName, dynaClient)
	if err != nil {
		log.Printf("查找或創建用戶失敗: %v", err)
		return nil, "", errors.New(ErrorCreatingUser)
	}

	if user == nil {
		log.Printf("用戶對象為空")
		return nil, "", errors.New(ErrorCreatingUser)
	}

	log.Printf("成功查找或創建用戶: ID=%s, Email=%s", user.ID, user.Email)

	// 生成 JWT 令牌
	log.Printf("嘗試生成 JWT 令牌")
	token, err := generateJWT(user)
	if err != nil {
		log.Printf("生成 JWT 令牌失敗: %v", err)
		return nil, "", errors.New(ErrorGeneratingToken)
	}

	if token == "" {
		log.Printf("JWT 令牌為空")
		return nil, "", errors.New(ErrorGeneratingToken)
	}

	log.Printf("成功生成 JWT 令牌")
	return user, token, nil
}

// exchangeCodeForToken 交換授權碼獲取訪問令牌
func exchangeCodeForToken(code string) (*TokenResponse, error) {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURI := os.Getenv("GOOGLE_REDIRECT_URI")

	// 如果環境變量未設置，使用默認值
	if clientID == "" {
		clientID = ""
		log.Printf("使用默認的 GOOGLE_CLIENT_ID: %s", clientID)
	}
	if clientSecret == "" {
		clientSecret = ""
		log.Printf("使用默認的 GOOGLE_CLIENT_SECRET")
	}
	if redirectURI == "" {
		// 使用 API Gateway 的回調 URL
		redirectURI = "https://0d2f8bryih.execute-api.us-west-2.amazonaws.com/staging/oauth/callback"
		log.Printf("使用默認的 GOOGLE_REDIRECT_URI: %s", redirectURI)
	}

	log.Printf("嘗試交換授權碼獲取訪問令牌")
	log.Printf("授權碼: %s", code)
	log.Printf("Client ID: %s", clientID)
	log.Printf("Redirect URI: %s", redirectURI)

	if clientID == "" || clientSecret == "" || redirectURI == "" {
		log.Printf("環境變量未設置: GOOGLE_CLIENT_ID=%s, GOOGLE_CLIENT_SECRET=%s, GOOGLE_REDIRECT_URI=%s",
			clientID, clientSecret, redirectURI)
		return nil, fmt.Errorf("OAuth 配置不完整")
	}

	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	log.Printf("發送請求到 Google OAuth 令牌端點")
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", data)
	if err != nil {
		log.Printf("發送請求時出錯: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("Google OAuth 令牌端點響應狀態碼: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Google OAuth 令牌端點錯誤響應: %s", string(bodyBytes))
		return nil, fmt.Errorf("Google OAuth 令牌端點返回錯誤: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("讀取響應體時出錯: %v", err)
		return nil, err
	}

	log.Printf("Google OAuth 令牌端點響應: %s", string(body))

	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		log.Printf("解析 JSON 時出錯: %v", err)
		return nil, err
	}

	if tokenResponse.AccessToken == "" {
		log.Printf("訪問令牌為空")
		return nil, fmt.Errorf("訪問令牌為空")
	}

	log.Printf("成功獲取訪問令牌: %s", tokenResponse.AccessToken)
	return &tokenResponse, nil
}

// getUserInfo 使用訪問令牌獲取 Google 用戶信息
func getUserInfo(accessToken string) (*GoogleUserInfo, error) {
	log.Printf("嘗試使用訪問令牌獲取 Google 用戶信息")
	log.Printf("訪問令牌: %s", accessToken)

	if accessToken == "" {
		log.Printf("訪問令牌為空")
		return nil, fmt.Errorf("訪問令牌為空")
	}

	// 創建請求
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		log.Printf("創建請求時出錯: %v", err)
		return nil, err
	}

	// 設置授權頭
	req.Header.Add("Authorization", "Bearer "+accessToken)
	log.Printf("發送請求到 Google 用戶信息 API，授權頭: %s", "Bearer "+accessToken)

	// 發送請求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("發送請求時出錯: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("Google API 響應狀態碼: %d", resp.StatusCode)

	// 讀取響應體
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("讀取響應體時出錯: %v", err)
		return nil, err
	}

	// 檢查狀態碼
	if resp.StatusCode != http.StatusOK {
		log.Printf("Google API 錯誤響應: %s", string(body))
		return nil, fmt.Errorf("Google API 返回錯誤: %d", resp.StatusCode)
	}

	log.Printf("Google API 響應: %s", string(body))

	// 解析 JSON
	var userInfo GoogleUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		log.Printf("解析 JSON 時出錯: %v", err)
		return nil, err
	}

	// 驗證必要的字段
	if userInfo.Sub == "" {
		log.Printf("Google 用戶 ID 為空")
		return nil, fmt.Errorf("Google 用戶 ID 為空")
	}

	log.Printf("成功獲取 Google 用戶信息: ID=%s, Email=%s, Name=%s",
		userInfo.Sub, userInfo.Email, userInfo.Name)
	return &userInfo, nil
}

// findOrCreateUser 在數據庫中查找或創建用戶
func findOrCreateUser(googleUser *GoogleUserInfo, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*User, error) {
	if googleUser == nil {
		log.Printf("Google 用戶信息為空")
		return nil, fmt.Errorf("Google 用戶信息為空")
	}

	if googleUser.Sub == "" {
		log.Printf("Google 用戶 ID 為空")
		return nil, fmt.Errorf("Google 用戶 ID 為空")
	}

	log.Printf("Google 用戶信息: ID=%s, Email=%s, Name=%s", googleUser.Sub, googleUser.Email, googleUser.Name)

	// 使用 GetItem 操作查詢具有特定 google_id 的用戶
	getItemInput := &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"google_id": {
				S: aws.String(googleUser.Sub),
			},
		},
	}

	log.Printf("嘗試從表 %s 中獲取 google_id=%s 的用戶", tableName, googleUser.Sub)
	result, err := dynaClient.GetItem(getItemInput)
	if err != nil {
		log.Printf("獲取用戶時出錯: %v", err)
		return nil, err
	}

	// 如果用戶存在，返回它
	if result.Item != nil && len(result.Item) > 0 {
		var user User
		err = dynamodbattribute.UnmarshalMap(result.Item, &user)
		if err != nil {
			log.Printf("反序列化用戶時出錯: %v", err)
			return nil, err
		}

		log.Printf("找到現有用戶: ID=%s, Email=%s", user.ID, user.Email)

		// 更新最後登錄時間
		user.UpdatedAt = time.Now()

		// 保存更新後的用戶
		av, err := dynamodbattribute.MarshalMap(user)
		if err != nil {
			log.Printf("序列化用戶時出錯: %v", err)
			return nil, errors.New(ErrorCouldNotMarshalItem)
		}

		updateInput := &dynamodb.PutItemInput{
			TableName: aws.String(tableName),
			Item:      av,
		}

		log.Printf("嘗試更新用戶: ID=%s", user.ID)
		_, err = dynaClient.PutItem(updateInput)
		if err != nil {
			log.Printf("更新用戶時出錯: %v", err)
			return nil, errors.New(ErrorCouldNotDynamoPutItem)
		}

		return &user, nil
	}

	// 創建新用戶
	now := time.Now()
	newID := fmt.Sprintf("user_%s", time.Now().Format("20060102150405"))
	user := User{
		ID:        newID,
		Name:      googleUser.Name,
		Email:     googleUser.Email,
		GoogleID:  googleUser.Sub,
		CreatedAt: now,
		UpdatedAt: now,
		IsAdmin:   false, // 默認為非管理員
	}

	log.Printf("創建新用戶: ID=%s, Email=%s, GoogleID=%s", user.ID, user.Email, user.GoogleID)

	// 將用戶保存到數據庫
	av, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		log.Printf("序列化新用戶時出錯: %v", err)
		return nil, errors.New(ErrorCouldNotMarshalItem)
	}

	// 打印序列化後的項目，用於調試
	avJSON, _ := json.Marshal(av)
	log.Printf("序列化後的項目: %s", string(avJSON))

	putItemInput := &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      av,
	}

	log.Printf("嘗試將新用戶保存到表 %s", tableName)
	_, err = dynaClient.PutItem(putItemInput)
	if err != nil {
		log.Printf("保存新用戶時出錯: %v", err)
		return nil, errors.New(ErrorCouldNotDynamoPutItem)
	}

	log.Printf("新用戶創建成功: ID=%s", user.ID)
	return &user, nil
}

// generateJWT 為用戶生成 JWT 令牌
func generateJWT(user *User) (string, error) {
	// 從環境獲取 JWT 密鑰
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "default_secret_key_change_in_production" // 開發環境的默認值
	}

	// 創建聲明
	claims := Claims{
		UserID: user.ID,
		Email:  user.Email,
		Admin:  user.IsAdmin,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // 令牌在 24 小時後過期
			IssuedAt:  time.Now().Unix(),
			Issuer:    "winsurf-api",
		},
	}

	// 創建令牌
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 簽名令牌
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateToken 驗證 JWT 令牌
func ValidateToken(tokenString string) (*Claims, error) {
	// 從環境獲取 JWT 密鑰
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "default_secret_key_change_in_production" // 開發環境的默認值
	}

	// 解析令牌
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// 驗證簽名方法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	// 驗證聲明
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// 檢查令牌是否過期
		if claims.ExpiresAt < time.Now().Unix() {
			return nil, errors.New(ErrorTokenExpired)
		}
		return claims, nil
	}

	return nil, errors.New(ErrorInvalidToken)
}

// ValidateTokenGin 驗證來自 Gin 請求的 JWT 令牌
func ValidateTokenGin(authHeader string) (*Claims, error) {
	// 檢查是否是 Bearer 令牌
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New(ErrorInvalidToken)
	}

	// 提取令牌
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// 驗證令牌
	return ValidateToken(tokenString)
}

// GetUserProfile 根據用戶 ID 獲取用戶資料
func GetUserProfile(userID string, tableName string, dynaClient dynamodbiface.DynamoDBAPI) (*User, error) {
	log.Printf("嘗試獲取用戶資料，用戶ID: %s, 表名: %s", userID, tableName)

	// 從數據庫獲取用戶資料
	result, err := dynaClient.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(userID),
			},
		},
	})

	if err != nil {
		log.Printf("獲取用戶資料時出錯: %v", err)

		// 嘗試使用不同的主鍵結構
		log.Printf("嘗試使用替代主鍵結構...")
		result, err = dynaClient.GetItem(&dynamodb.GetItemInput{
			TableName: aws.String(tableName),
			Key: map[string]*dynamodb.AttributeValue{
				"ID": {
					S: aws.String(userID),
				},
			},
		})

		if err != nil {
			log.Printf("第二次嘗試獲取用戶資料時出錯: %v", err)

			// 再嘗試使用 email 作為主鍵
			// 由於我們沒有用戶的電子郵件，這裡我們需要先查詢所有用戶
			scanResult, scanErr := dynaClient.Scan(&dynamodb.ScanInput{
				TableName: aws.String(tableName),
			})

			if scanErr != nil {
				log.Printf("掃描用戶表時出錯: %v", scanErr)
				return nil, errors.New("獲取用戶資料時出錯")
			}

			// 遍歷所有用戶，查找匹配的 ID
			for _, item := range scanResult.Items {
				var u User
				if unmarshalErr := dynamodbattribute.UnmarshalMap(item, &u); unmarshalErr != nil {
					continue
				}

				if u.ID == userID {
					log.Printf("通過掃描找到用戶: %s", u.Name)
					return &u, nil
				}
			}

			return nil, errors.New("獲取用戶資料時出錯")
		}
	}

	// 如果用戶不存在
	if result.Item == nil {
		log.Printf("用戶不存在: %s", userID)
		return nil, errors.New("用戶不存在")
	}

	// 反序列化用戶資料
	var user User
	err = dynamodbattribute.UnmarshalMap(result.Item, &user)
	if err != nil {
		log.Printf("解析用戶資料時出錯: %v", err)
		return nil, errors.New("解析用戶資料時出錯")
	}

	log.Printf("成功獲取用戶資料: %s", user.Name)
	return &user, nil
}

// createErrorResponse 創建錯誤響應
func createErrorResponse(statusCode int, errorMessage string) *events.APIGatewayProxyResponse {
	// 如果是認證相關錯誤，重定向到前端頁面
	if statusCode == http.StatusUnauthorized ||
		statusCode == http.StatusForbidden ||
		errorMessage == ErrorInvalidToken ||
		errorMessage == ErrorExchangingToken ||
		errorMessage == ErrorFetchingUserInfo ||
		errorMessage == ErrorCreatingUser ||
		errorMessage == ErrorGeneratingToken {

		redirectURL := "https://main.d37j5zzkd2621x.amplifyapp.com/?error=" + url.QueryEscape(errorMessage)
		log.Printf("認證錯誤，重定向到: %s", redirectURL)

		return &events.APIGatewayProxyResponse{
			StatusCode: http.StatusFound,
			Headers: map[string]string{
				"Location": redirectURL,
			},
			Body: "",
		}
	}

	// 其他錯誤返回 JSON 響應
	errorResponse := struct {
		Error string `json:"error"`
	}{
		Error: errorMessage,
	}

	jsonResponse, _ := json.Marshal(errorResponse)
	return &events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(jsonResponse),
	}
}
