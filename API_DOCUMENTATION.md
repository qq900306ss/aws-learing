# AWS Lambda API 串接文檔

## 基本信息

- API 基礎路徑: `https://0d2f8bryih.execute-api.us-west-2.amazonaws.com/staging`
- 前端應用程式 URL: `https://main.d37j5zzkd2621x.amplifyapp.com/`

## 認證流程

### OAuth 登入

1. 重定向用戶到 Google OAuth 登入頁面:
   ```
   https://accounts.google.com/o/oauth2/auth?client_id=970174882826-6mau4p0nl1vha8uqg4h1ofqmembi4jl3.apps.googleusercontent.com&redirect_uri=https://0d2f8bryih.execute-api.us-west-2.amazonaws.com/staging/oauth/callback&response_type=code&scope=email profile openid&access_type=offline
   ```

2. 用戶授權後，Google 會重定向到回調 URL:
   ```
   https://0d2f8bryih.execute-api.us-west-2.amazonaws.com/staging/oauth/callback?code=<授權碼>
   ```

3. 後端處理回調，創建或查找用戶，並生成 JWT 令牌

4. 用戶被重定向回前端應用，URL 中包含令牌:
   ```
   https://main.d37j5zzkd2621x.amplifyapp.com/?token=<JWT令牌>
   ```

5. 前端應用保存令牌，用於後續 API 請求的授權

### 使用 JWT 令牌

所有需要認證的 API 請求都應在 HTTP 頭中包含 JWT 令牌:

```
Authorization: Bearer <JWT令牌>
```

## 商品 API

### 獲取所有商品

- **URL**: `/products`
- **方法**: `GET`
- **認證**: 不需要
- **響應**:
  ```json
  [
    {
      "id": "商品ID",
      "name": "商品名稱",
      "price": 100.0,
      "stock": 10,
      "image_url": "圖片URL",
      "created_at": "2025-03-30T12:00:00Z",
      "updated_at": "2025-03-30T12:00:00Z"
    }
  ]
  ```

### 獲取單個商品

- **URL**: `/products/{id}`
- **方法**: `GET`
- **認證**: 不需要
- **響應**:
  ```json
  {
    "id": "商品ID",
    "name": "商品名稱",
    "price": 100.0,
    "stock": 10,
    "image_url": "圖片URL",
    "created_at": "2025-03-30T12:00:00Z",
    "updated_at": "2025-03-30T12:00:00Z"
  }
  ```

### 創建商品 (僅管理員)

- **URL**: `/products`
- **方法**: `POST`
- **認證**: 需要 (管理員)
- **請求體**:
  ```json
  {
    "name": "商品名稱",
    "price": 100.0,
    "stock": 10,
    "image_url": "圖片URL"
  }
  ```
- **響應**:
  ```json
  {
    "id": "商品ID",
    "name": "商品名稱",
    "price": 100.0,
    "stock": 10,
    "image_url": "圖片URL",
    "created_at": "2025-03-30T12:00:00Z",
    "updated_at": "2025-03-30T12:00:00Z"
  }
  ```

### 更新商品 (僅管理員)

- **URL**: `/products/{id}`
- **方法**: `PUT`
- **認證**: 需要 (管理員)
- **請求體**:
  ```json
  {
    "name": "更新的商品名稱",
    "price": 120.0,
    "stock": 15,
    "image_url": "更新的圖片URL"
  }
  ```
- **響應**:
  ```json
  {
    "id": "商品ID",
    "name": "更新的商品名稱",
    "price": 120.0,
    "stock": 15,
    "image_url": "更新的圖片URL",
    "created_at": "2025-03-30T12:00:00Z",
    "updated_at": "2025-03-30T13:00:00Z"
  }
  ```

### 刪除商品 (僅管理員)

- **URL**: `/products/{id}`
- **方法**: `DELETE`
- **認證**: 需要 (管理員)
- **響應**:
  ```json
  {
    "message": "商品已刪除"
  }
  ```

## 錯誤處理

所有 API 錯誤都會返回適當的 HTTP 狀態碼和 JSON 格式的錯誤信息:

```json
{
  "error": "錯誤信息"
}
```

常見的錯誤狀態碼:

- `400 Bad Request`: 請求參數無效
- `401 Unauthorized`: 未提供認證或認證無效
- `403 Forbidden`: 無權訪問 (非管理員嘗試訪問管理員 API)
- `404 Not Found`: 資源不存在
- `500 Internal Server Error`: 服務器內部錯誤

## 認證錯誤重定向

當認證相關錯誤發生時，用戶會被重定向到前端應用，URL 中包含錯誤信息:

```
https://main.d37j5zzkd2621x.amplifyapp.com/?error=<錯誤信息>
```

前端應用應處理這些錯誤並向用戶顯示適當的信息。

## 注意事項

1. API Gateway 使用 `/staging` 作為階段名稱前綴，但在將請求傳遞給 Lambda 函數時，這個前綴被移除。
2. 所有 API 請求和響應都使用 JSON 格式。
3. 日期時間字段使用 ISO 8601 格式 (UTC)。
4. 管理員權限是在用戶創建時設置的，目前沒有提供 API 來更改用戶的管理員狀態。
