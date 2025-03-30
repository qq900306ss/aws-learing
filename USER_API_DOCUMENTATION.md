# 用戶 API 文檔

## 基本信息

- API 基礎路徑: `https://0d2f8bryih.execute-api.us-west-2.amazonaws.com/staging`
- 前端應用程式 URL: `https://main.d37j5zzkd2621x.amplifyapp.com/`

## 認證流程

### 獲取 JWT 令牌

1. 用戶通過 Google OAuth 登入後，前端會收到包含 JWT 令牌的 URL 參數：
   ```
   https://main.d37j5zzkd2621x.amplifyapp.com/auth-success?token=<JWT令牌>&userId=<用戶ID>
   ```

2. 前端應用應保存此令牌，用於後續 API 請求的授權。

### 使用 JWT 令牌

所有需要認證的 API 請求都應在 HTTP 頭中包含 JWT 令牌:

```
Authorization: Bearer <JWT令牌>
```

## 用戶 API

### 獲取用戶資料

- **URL**: `/user/profile`
- **方法**: `GET`
- **認證**: 需要 (JWT 令牌)
- **請求頭**:
  ```
  Authorization: Bearer <JWT令牌>
  ```
- **響應**:
  ```json
  {
    "id": "用戶ID",
    "name": "用戶姓名",
    "email": "用戶電子郵件",
    "phone": "用戶電話號碼（可能為空）",
    "google_id": "Google用戶ID",
    "resource_key": "資源密鑰（可能為空）",
    "created_at": "2025-03-30T12:00:00Z",
    "updated_at": "2025-03-30T12:00:00Z",
    "is_admin": true或false
  }
  ```

## 錯誤處理

API 錯誤會返回適當的 HTTP 狀態碼和 JSON 格式的錯誤信息:

```json
{
  "error": "錯誤信息"
}
```

常見的錯誤狀態碼:

- `401 Unauthorized`: 未提供認證或認證無效
- `403 Forbidden`: 無權訪問 (非管理員嘗試訪問管理員 API)
- `404 Not Found`: 資源不存在
- `500 Internal Server Error`: 服務器內部錯誤

## 前端整合示例

### 保存 JWT 令牌

```javascript
// 從 URL 參數獲取令牌
const urlParams = new URLSearchParams(window.location.search);
const token = urlParams.get('token');
const userId = urlParams.get('userId');

if (token && userId) {
  // 保存令牌到 localStorage
  localStorage.setItem('token', token);
  localStorage.setItem('userId', userId);
  
  // 重定向到主頁或儀表板
  window.location.href = '/dashboard';
}
```

### 獲取用戶資料

```javascript
async function getUserProfile() {
  const token = localStorage.getItem('token');
  
  if (!token) {
    console.error('未找到令牌，請先登入');
    return;
  }
  
  try {
    const response = await fetch('https://0d2f8bryih.execute-api.us-west-2.amazonaws.com/staging/user/profile', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (!response.ok) {
      throw new Error('獲取用戶資料失敗');
    }
    
    const userData = await response.json();
    
    // 處理用戶資料
    console.log('用戶資料:', userData);
    
    // 顯示用戶資料
    document.getElementById('userName').textContent = userData.name;
    document.getElementById('userEmail').textContent = userData.email;
    
    // 如果是管理員，顯示管理員選項
    if (userData.is_admin) {
      document.getElementById('adminPanel').style.display = 'block';
    }
    
    return userData;
  } catch (error) {
    console.error('獲取用戶資料時出錯:', error);
    
    // 如果令牌無效，重定向到登入頁面
    if (error.message.includes('401')) {
      localStorage.removeItem('token');
      localStorage.removeItem('userId');
      window.location.href = '/login';
    }
  }
}

// 頁面加載時獲取用戶資料
document.addEventListener('DOMContentLoaded', getUserProfile);
```

### 檢查用戶是否為管理員

```javascript
function checkAdminStatus() {
  const userData = JSON.parse(localStorage.getItem('userData'));
  
  if (userData && userData.is_admin) {
    // 用戶是管理員，顯示管理員選項
    document.getElementById('adminPanel').style.display = 'block';
    return true;
  } else {
    // 用戶不是管理員，隱藏管理員選項
    document.getElementById('adminPanel').style.display = 'none';
    return false;
  }
}
```

## 注意事項

1. 令牌有效期為 24 小時，過期後需要重新登入。
2. 請確保在每個需要認證的 API 請求中都包含有效的 JWT 令牌。
3. 如果用戶登出，請清除前端保存的令牌：
   ```javascript
   function logout() {
     localStorage.removeItem('token');
     localStorage.removeItem('userId');
     window.location.href = '/login';
   }
   ```
4. 前端應處理令牌過期的情況，通常是收到 401 狀態碼時重定向到登入頁面。
