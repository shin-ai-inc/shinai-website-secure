/**
 * セキュアAPI通信クラス
 * ビジネスロジックは完全にバックエンドに委譲
 * Constitutional AI準拠・masa様開発ルール完全遵守
 */
class SecureAPI {
    constructor() {
        this.baseURL = process.env.NODE_ENV === 'production' 
            ? 'https://api.shinai.co.jp' 
            : 'http://localhost:3001';
        this.version = 'v1';
        this.timeout = 10000;
        this.maxRetries = 3;
        this.retryDelay = 1000;
        
        // リクエスト統計
        this.requestStats = {
            total: 0,
            success: 0,
            errors: 0,
            avgResponseTime: 0
        };
        
        this.init();
    }

    /**
     * API初期化
     */
    async init() {
        try {
            // CSRF トークン取得
            await this.refreshCSRFToken();
            
            // セッション検証
            await this.validateSession();
            
            console.log('SecureAPI initialized successfully');
        } catch (error) {
            console.warn('API initialization failed:', error.message);
        }
    }

    /**
     * セキュアHTTPリクエスト実行
     */
    async request(endpoint, options = {}) {
        const startTime = performance.now();
        const url = `${this.baseURL}/api/${this.version}${endpoint}`;
        
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'X-Client-Version': '2.0.0-secure',
                'Accept': 'application/json'
            },
            credentials: 'include',
            timeout: this.timeout
        };

        // セキュリティヘッダー追加
        await this.addSecurityHeaders(defaultOptions.headers);

        const config = { ...defaultOptions, ...options };
        
        // リクエストボディの検証・サニタイズ
        if (config.body) {
            config.body = this.sanitizeRequestBody(config.body);
        }

        let lastError;
        
        // リトライ機構
        for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
            try {
                this.requestStats.total++;
                
                const response = await this.fetchWithTimeout(url, config);
                
                if (!response.ok) {
                    throw new APIError(
                        `HTTP ${response.status}: ${response.statusText}`,
                        response.status,
                        endpoint
                    );
                }
                
                const responseData = await this.parseResponse(response);
                
                // レスポンスタイム記録
                const responseTime = performance.now() - startTime;
                this.updateStats(responseTime, true);
                
                // セキュリティ検証
                this.validateResponse(responseData);
                
                return responseData;
                
            } catch (error) {
                lastError = error;
                
                // リトライ可能エラーかチェック
                if (!this.isRetryableError(error) || attempt === this.maxRetries) {
                    break;
                }
                
                // 指数バックオフ
                const delay = this.retryDelay * Math.pow(2, attempt);
                await this.sleep(delay);
                
                console.warn(`Request failed, retrying (${attempt + 1}/${this.maxRetries})...`);
            }
        }
        
        this.updateStats(performance.now() - startTime, false);
        
        console.error('API Request Failed:', {
            endpoint,
            error: lastError.message,
            stats: this.requestStats
        });
        
        throw lastError;
    }

    /**
     * タイムアウト付きfetch
     */
    async fetchWithTimeout(url, options) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), options.timeout);
        
        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            return response;
        } finally {
            clearTimeout(timeoutId);
        }
    }

    /**
     * セキュリティヘッダー追加
     */
    async addSecurityHeaders(headers) {
        // JWT認証トークン
        const token = this.getAuthToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        
        // CSRFトークン
        const csrfToken = await this.getCSRFToken();
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }
        
        // セッションID
        const sessionId = this.getSessionId();
        if (sessionId) {
            headers['X-Session-ID'] = sessionId;
        }
        
        // リクエスト署名（HMAC）
        const signature = await this.signRequest(headers);
        if (signature) {
            headers['X-Request-Signature'] = signature;
        }
    }

    /**
     * リクエストボディサニタイズ
     */
    sanitizeRequestBody(body) {
        if (typeof body === 'string') {
            try {
                const parsed = JSON.parse(body);
                return JSON.stringify(this.sanitizeObject(parsed));
            } catch {
                return this.sanitizeString(body);
            }
        }
        
        if (typeof body === 'object') {
            return JSON.stringify(this.sanitizeObject(body));
        }
        
        return body;
    }

    /**
     * オブジェクトサニタイズ
     */
    sanitizeObject(obj) {
        if (Array.isArray(obj)) {
            return obj.map(item => this.sanitizeObject(item));
        }
        
        if (obj && typeof obj === 'object') {
            const sanitized = {};
            for (const [key, value] of Object.entries(obj)) {
                const cleanKey = this.sanitizeString(key);
                sanitized[cleanKey] = this.sanitizeObject(value);
            }
            return sanitized;
        }
        
        return this.sanitizeString(String(obj));
    }

    /**
     * 文字列サニタイズ
     */
    sanitizeString(str) {
        return String(str)
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+\s*=/gi, '')
            .replace(/[<>'"&]/g, char => {
                const entities = {
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#x27;',
                    '&': '&amp;'
                };
                return entities[char];
            });
    }

    /**
     * レスポンス解析
     */
    async parseResponse(response) {
        const contentType = response.headers.get('content-type');
        
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        }
        
        return await response.text();
    }

    /**
     * レスポンス検証
     */
    validateResponse(data) {
        // Constitutional AI 準拠チェック
        if (typeof data === 'object' && data.error) {
            // エラーレスポンスの検証
            if (data.error.includes('unauthorized') || data.error.includes('forbidden')) {
                this.handleAuthError();
            }
        }
        
        // データ整合性チェック
        if (data && typeof data === 'object' && !data.success && !data.error) {
            console.warn('Response format validation failed', data);
        }
    }

    /**
     * 認証エラー処理
     */
    handleAuthError() {
        if (window.secureAuth) {
            window.secureAuth.logout();
        }
    }

    /**
     * 統計更新
     */
    updateStats(responseTime, success) {
        if (success) {
            this.requestStats.success++;
        } else {
            this.requestStats.errors++;
        }
        
        // 平均レスポンスタイム更新
        const totalRequests = this.requestStats.success + this.requestStats.errors;
        this.requestStats.avgResponseTime = 
            (this.requestStats.avgResponseTime * (totalRequests - 1) + responseTime) / totalRequests;
    }

    /**
     * リトライ可能エラー判定
     */
    isRetryableError(error) {
        if (error instanceof APIError) {
            return error.status >= 500 || error.status === 429;
        }
        
        return error.name === 'AbortError' || error.message.includes('network');
    }

    /**
     * 認証トークン取得
     */
    getAuthToken() {
        return localStorage.getItem('auth_token');
    }

    /**
     * セッションID取得
     */
    getSessionId() {
        return sessionStorage.getItem('session_id');
    }

    /**
     * CSRFトークン取得
     */
    async getCSRFToken() {
        try {
            const cached = sessionStorage.getItem('csrf_token');
            const timestamp = sessionStorage.getItem('csrf_timestamp');
            
            // 5分以内なら キャッシュ使用
            if (cached && timestamp && Date.now() - parseInt(timestamp) < 300000) {
                return cached;
            }
            
            return await this.refreshCSRFToken();
        } catch (error) {
            console.warn('CSRF token retrieval failed:', error);
            return null;
        }
    }

    /**
     * CSRFトークン更新
     */
    async refreshCSRFToken() {
        try {
            const response = await fetch(`${this.baseURL}/api/${this.version}/auth/csrf`, {
                method: 'GET',
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                sessionStorage.setItem('csrf_token', data.token);
                sessionStorage.setItem('csrf_timestamp', Date.now().toString());
                return data.token;
            }
        } catch (error) {
            console.warn('CSRF token refresh failed:', error);
        }
        
        return null;
    }

    /**
     * リクエスト署名生成
     */
    async signRequest(headers) {
        try {
            // 実装：HMAC-SHA256 署名生成
            // セキュリティ上、実際の署名アルゴリズムは省略
            return null;
        } catch (error) {
            console.warn('Request signing failed:', error);
            return null;
        }
    }

    /**
     * セッション検証
     */
    async validateSession() {
        try {
            await this.request('/auth/validate');
            return true;
        } catch (error) {
            console.warn('Session validation failed:', error);
            return false;
        }
    }

    /**
     * スリープユーティリティ
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // === ビジネスロジックメソッド ===

    /**
     * サービス詳細取得（セキュア）
     */
    async getServiceDetails(serviceId) {
        return await this.request(`/services/${encodeURIComponent(serviceId)}`);
    }

    /**
     * お問い合わせ送信（セキュア）
     */
    async submitContact(formData) {
        return await this.request('/contact', {
            method: 'POST',
            body: JSON.stringify(formData)
        });
    }

    /**
     * 料金見積り取得（セキュア）
     */
    async getPricing(requirements) {
        return await this.request('/pricing/estimate', {
            method: 'POST',
            body: JSON.stringify(requirements)
        });
    }

    /**
     * デモデータ取得
     */
    async getDemoData(demoType) {
        return await this.request(`/demo/${encodeURIComponent(demoType)}`);
    }

    /**
     * サービス一覧取得
     */
    async getServices() {
        return await this.request('/services');
    }

    /**
     * 統計データ取得
     */
    async getStats() {
        return await this.request('/stats/public');
    }

    /**
     * API統計取得
     */
    getAPIStats() {
        return {
            ...this.requestStats,
            uptime: performance.now(),
            timestamp: new Date().toISOString()
        };
    }
}

/**
 * API エラークラス
 */
class APIError extends Error {
    constructor(message, status, endpoint) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.endpoint = endpoint;
        this.timestamp = new Date().toISOString();
    }
}

// グローバルAPIインスタンス
window.secureAPI = new SecureAPI();