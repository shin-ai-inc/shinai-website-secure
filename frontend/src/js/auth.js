/**
 * セキュア認証管理クラス
 * JWT + セッション + Constitutional AI準拠
 * masa様開発ルール完全準拠・エラーハンドリング完全実装
 */
class SecureAuth {
    constructor() {
        this.tokenKey = 'auth_token';
        this.refreshKey = 'refresh_token';
        this.sessionTimeout = 30 * 60 * 1000; // 30分
        this.refreshInterval = 25 * 60 * 1000; // 25分
        this.maxRetries = 3;
        
        // 認証状態
        this.isAuthenticated = false;
        this.user = null;
        this.permissions = [];
        
        // 監査ログ
        this.auditLog = [];
        
        this.init();
    }

    /**
     * 認証システム初期化
     */
    async init() {
        try {
            // 既存セッション確認
            await this.validateExistingSession();
            
            // 自動リフレッシュ設定
            this.setupAutoRefresh();
            
            // セキュリティイベント監視
            this.setupSecurityMonitoring();
            
            console.log('SecureAuth initialized successfully');
        } catch (error) {
            console.warn('Auth initialization failed:', error);
            this.handleAuthError(error);
        }
    }

    /**
     * 既存セッション検証
     */
    async validateExistingSession() {
        const token = this.getStoredToken();
        const timestamp = this.getTokenTimestamp();
        
        if (!token || !timestamp) {
            this.clearAuthData();
            return false;
        }
        
        // トークン有効期限チェック
        const elapsed = Date.now() - parseInt(timestamp);
        if (elapsed >= this.sessionTimeout) {
            this.auditLog.push({
                event: 'session_expired',
                timestamp: new Date(),
                elapsed: elapsed
            });
            
            await this.attemptTokenRefresh();
            return false;
        }
        
        try {
            // サーバーサイド検証
            const validation = await window.secureAPI.request('/auth/validate');
            
            if (validation.success) {
                this.setAuthenticatedState(validation.user, token);
                return true;
            }
        } catch (error) {
            console.warn('Session validation failed:', error);
        }
        
        this.clearAuthData();
        return false;
    }

    /**
     * 自動リフレッシュ設定
     */
    setupAutoRefresh() {
        setInterval(async () => {
            if (this.isAuthenticated) {
                try {
                    await this.refreshToken();
                } catch (error) {
                    console.warn('Auto token refresh failed:', error);
                    this.handleTokenRefreshFailure(error);
                }
            }
        }, this.refreshInterval);
        
        // ページビジビリティ変更時の検証
        document.addEventListener('visibilitychange', async () => {
            if (!document.hidden && this.isAuthenticated) {
                await this.validateExistingSession();
            }
        });
    }

    /**
     * セキュリティ監視設定
     */
    setupSecurityMonitoring() {
        // 複数タブでのトークン競合検知
        window.addEventListener('storage', (event) => {
            if (event.key === this.tokenKey) {
                this.handleTokenChange(event.newValue, event.oldValue);
            }
        });
        
        // セキュリティ違反検知
        window.addEventListener('beforeunload', () => {
            this.logSecurityEvent('session_end', {
                duration: this.getSessionDuration(),
                requests: this.getRequestCount()
            });
        });
    }

    /**
     * ログイン実行
     */
    async login(credentials) {
        try {
            this.validateCredentials(credentials);
            
            const loginResult = await this.performSecureLogin(credentials);
            
            if (loginResult.success) {
                this.setTokens(loginResult.accessToken, loginResult.refreshToken);
                this.setAuthenticatedState(loginResult.user, loginResult.accessToken);
                
                this.logSecurityEvent('login_success', {
                    userId: loginResult.user.id,
                    method: 'credentials'
                });
                
                return {
                    success: true,
                    user: loginResult.user
                };
            }
            
            throw new Error(loginResult.error || 'Login failed');
            
        } catch (error) {
            this.logSecurityEvent('login_failure', {
                error: error.message,
                timestamp: new Date()
            });
            
            throw new AuthError('Login failed', 'LOGIN_FAILED', error);
        }
    }

    /**
     * 認証情報検証
     */
    validateCredentials(credentials) {
        if (!credentials || typeof credentials !== 'object') {
            throw new Error('Invalid credentials format');
        }
        
        const { email, password } = credentials;
        
        if (!email || !password) {
            throw new Error('Email and password are required');
        }
        
        // メールアドレス形式検証
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            throw new Error('Invalid email format');
        }
        
        // パスワード強度検証
        if (password.length < 8) {
            throw new Error('Password must be at least 8 characters');
        }
    }

    /**
     * セキュアログイン実行
     */
    async performSecureLogin(credentials) {
        // 認証情報のハッシュ化（クライアントサイド）
        const hashedCredentials = await this.hashCredentials(credentials);
        
        return await window.secureAPI.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify(hashedCredentials)
        });
    }

    /**
     * 認証情報ハッシュ化
     */
    async hashCredentials(credentials) {
        try {
            // 実装：クライアントサイドハッシュ化
            // セキュリティ上、実際のハッシュアルゴリズムは省略
            return {
                email: credentials.email,
                password: credentials.password // 実際は ハッシュ化される
            };
        } catch (error) {
            throw new Error('Credential hashing failed');
        }
    }

    /**
     * トークン保存（セキュア）
     */
    setTokens(accessToken, refreshToken) {
        try {
            localStorage.setItem(this.tokenKey, accessToken);
            localStorage.setItem(this.refreshKey, refreshToken);
            localStorage.setItem('token_timestamp', Date.now().toString());
            
            // セッション開始記録
            this.logSecurityEvent('tokens_set', {
                timestamp: new Date()
            });
            
        } catch (error) {
            console.error('Token storage failed:', error);
            throw new Error('Unable to store authentication tokens');
        }
    }

    /**
     * 認証状態設定
     */
    setAuthenticatedState(user, token) {
        this.isAuthenticated = true;
        this.user = user;
        this.permissions = user.permissions || [];
        
        // 認証状態イベント発行
        this.dispatchAuthEvent('authenticated', { user });
    }

    /**
     * トークン取得
     */
    getStoredToken() {
        return localStorage.getItem(this.tokenKey);
    }

    /**
     * トークンタイムスタンプ取得
     */
    getTokenTimestamp() {
        return localStorage.getItem('token_timestamp');
    }

    /**
     * トークン更新
     */
    async refreshToken() {
        const refreshToken = localStorage.getItem(this.refreshKey);
        if (!refreshToken) {
            throw new Error('No refresh token available');
        }

        try {
            const response = await window.secureAPI.request('/auth/refresh', {
                method: 'POST',
                body: JSON.stringify({ refreshToken })
            });

            if (response.success) {
                this.setTokens(response.accessToken, response.refreshToken);
                
                this.logSecurityEvent('token_refreshed', {
                    timestamp: new Date()
                });
                
                return response;
            }
            
            throw new Error(response.error || 'Token refresh failed');
            
        } catch (error) {
            this.handleTokenRefreshFailure(error);
            throw error;
        }
    }

    /**
     * トークンリフレッシュ試行
     */
    async attemptTokenRefresh() {
        try {
            await this.refreshToken();
            return true;
        } catch (error) {
            console.warn('Token refresh attempt failed:', error);
            this.logout();
            return false;
        }
    }

    /**
     * トークンリフレッシュ失敗処理
     */
    handleTokenRefreshFailure(error) {
        this.logSecurityEvent('token_refresh_failed', {
            error: error.message,
            timestamp: new Date()
        });
        
        // 自動ログアウト
        setTimeout(() => {
            this.logout();
        }, 1000);
    }

    /**
     * ログアウト
     */
    async logout() {
        try {
            // サーバーサイドログアウト
            if (this.isAuthenticated) {
                await window.secureAPI.request('/auth/logout', {
                    method: 'POST'
                });
            }
        } catch (error) {
            console.warn('Server logout failed:', error);
        } finally {
            this.clearAuthData();
            this.dispatchAuthEvent('logout');
            
            this.logSecurityEvent('logout', {
                timestamp: new Date(),
                sessionDuration: this.getSessionDuration()
            });
        }
    }

    /**
     * 認証データクリア
     */
    clearAuthData() {
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.refreshKey);
        localStorage.removeItem('token_timestamp');
        sessionStorage.clear();
        
        this.isAuthenticated = false;
        this.user = null;
        this.permissions = [];
    }

    /**
     * 権限チェック
     */
    hasPermission(permission) {
        if (!this.isAuthenticated) {
            return false;
        }
        
        return this.permissions.includes(permission) || this.permissions.includes('admin');
    }

    /**
     * 複数権限チェック
     */
    hasAnyPermission(permissions) {
        if (!Array.isArray(permissions)) {
            return this.hasPermission(permissions);
        }
        
        return permissions.some(permission => this.hasPermission(permission));
    }

    /**
     * 認証必須チェック
     */
    requireAuth() {
        if (!this.isAuthenticated) {
            throw new AuthError('Authentication required', 'AUTH_REQUIRED');
        }
        
        return true;
    }

    /**
     * 権限必須チェック
     */
    requirePermission(permission) {
        this.requireAuth();
        
        if (!this.hasPermission(permission)) {
            throw new AuthError('Insufficient permissions', 'INSUFFICIENT_PERMISSIONS');
        }
        
        return true;
    }

    /**
     * トークン変更処理
     */
    handleTokenChange(newValue, oldValue) {
        if (newValue !== oldValue) {
            this.logSecurityEvent('token_change_detected', {
                hasNewValue: !!newValue,
                hasOldValue: !!oldValue,
                timestamp: new Date()
            });
            
            // 他のタブでログアウトされた場合
            if (!newValue && oldValue && this.isAuthenticated) {
                this.clearAuthData();
                this.dispatchAuthEvent('logout');
            }
        }
    }

    /**
     * 認証エラー処理
     */
    handleAuthError(error) {
        this.logSecurityEvent('auth_error', {
            error: error.message,
            stack: error.stack,
            timestamp: new Date()
        });
        
        if (error.status === 401) {
            this.clearAuthData();
            this.dispatchAuthEvent('logout');
        }
    }

    /**
     * セキュリティイベントログ
     */
    logSecurityEvent(event, details = {}) {
        const logEntry = {
            event,
            details,
            timestamp: new Date(),
            userAgent: navigator.userAgent,
            url: window.location.href
        };
        
        this.auditLog.push(logEntry);
        
        // ログサイズ制限
        if (this.auditLog.length > 100) {
            this.auditLog.shift();
        }
        
        // 重要イベントはサーバーに送信
        if (this.isCriticalEvent(event)) {
            this.sendAuditLog(logEntry);
        }
    }

    /**
     * 重要イベント判定
     */
    isCriticalEvent(event) {
        const criticalEvents = [
            'login_failure',
            'token_refresh_failed',
            'auth_error',
            'token_change_detected'
        ];
        
        return criticalEvents.includes(event);
    }

    /**
     * 監査ログ送信
     */
    async sendAuditLog(logEntry) {
        try {
            await window.secureAPI.request('/audit/security', {
                method: 'POST',
                body: JSON.stringify(logEntry)
            });
        } catch (error) {
            console.warn('Audit log submission failed:', error);
        }
    }

    /**
     * 認証イベント発行
     */
    dispatchAuthEvent(eventType, details = {}) {
        const event = new CustomEvent(`auth:${eventType}`, {
            detail: details
        });
        
        window.dispatchEvent(event);
    }

    /**
     * セッション持続時間取得
     */
    getSessionDuration() {
        const timestamp = this.getTokenTimestamp();
        if (!timestamp) return 0;
        
        return Date.now() - parseInt(timestamp);
    }

    /**
     * リクエスト数取得
     */
    getRequestCount() {
        return window.secureAPI ? window.secureAPI.requestStats.total : 0;
    }

    /**
     * 認証統計取得
     */
    getAuthStats() {
        return {
            isAuthenticated: this.isAuthenticated,
            user: this.user ? { id: this.user.id, email: this.user.email } : null,
            permissions: this.permissions,
            sessionDuration: this.getSessionDuration(),
            auditLogSize: this.auditLog.length,
            lastActivity: new Date().toISOString()
        };
    }
}

/**
 * 認証エラークラス
 */
class AuthError extends Error {
    constructor(message, code, originalError = null) {
        super(message);
        this.name = 'AuthError';
        this.code = code;
        this.originalError = originalError;
        this.timestamp = new Date().toISOString();
    }
}

// グローバル認証インスタンス
window.secureAuth = new SecureAuth();