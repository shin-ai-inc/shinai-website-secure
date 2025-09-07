/**
 * ShinAI セキュアバックエンドAPI
 * Express.js + 完全セキュリティミドルウェア
 * Constitutional AI準拠・masa様開発ルール完全遵守
 */
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const csrf = require('csurf');
const validator = require('validator');
const morgan = require('morgan');

// ルートインポート
const authRoutes = require('./routes/auth');
const serviceRoutes = require('./routes/services');
const contactRoutes = require('./routes/contact');
const pricingRoutes = require('./routes/pricing');
const auditRoutes = require('./routes/audit');

// ミドルウェア・ユーティリティ
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');
const { requestLogger } = require('./middleware/requestLogger');
const { securityHeaders } = require('./middleware/securityHeaders');
const { validateEnvironment } = require('./utils/validation');
const { logger } = require('./utils/logger');
const { connectDB } = require('./config/database');
const { initializeRedis } = require('./config/redis');

class SecureAPIServer {
    constructor() {
        this.app = express();
        this.server = null;
        this.isShuttingDown = false;
        
        // 環境変数検証
        validateEnvironment();
        
        this.init();
    }

    /**
     * サーバー初期化
     */
    async init() {
        try {
            // データベース接続
            await connectDB();
            
            // Redis接続
            await initializeRedis();
            
            // ミドルウェア設定
            this.setupMiddleware();
            
            // ルート設定
            this.setupRoutes();
            
            // エラーハンドリング
            this.setupErrorHandling();
            
            // グレースフルシャットダウン
            this.setupGracefulShutdown();
            
            logger.info('SecureAPIServer initialized successfully');
            
        } catch (error) {
            logger.error('Server initialization failed:', error);
            process.exit(1);
        }
    }

    /**
     * ミドルウェア設定
     */
    setupMiddleware() {
        // リクエストログ
        this.app.use(morgan('combined', {
            stream: { write: message => logger.info(message.trim()) }
        }));

        // セキュリティヘッダー（Helmet）
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
                    styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
                    fontSrc: ["'self'", "fonts.gstatic.com"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'"]
                }
            },
            hsts: {
                maxAge: 31536000, // 1年
                includeSubDomains: true,
                preload: true
            },
            noSniff: true,
            xssFilter: true,
            referrerPolicy: 'strict-origin-when-cross-origin'
        }));

        // 追加セキュリティヘッダー
        this.app.use(securityHeaders);

        // CORS設定
        this.app.use(cors({
            origin: this.getAllowedOrigins(),
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: [
                'Content-Type', 
                'Authorization', 
                'X-CSRF-Token', 
                'X-Requested-With',
                'X-Session-ID',
                'X-Client-Version'
            ],
            exposedHeaders: ['X-RateLimit-Remaining', 'X-RateLimit-Reset']
        }));

        // レート制限設定
        this.setupRateLimiting();

        // 基本ミドルウェア
        this.app.use(compression({
            level: 6,
            threshold: 1024,
            filter: (req, res) => {
                if (req.headers['x-no-compression']) {
                    return false;
                }
                return compression.filter(req, res);
            }
        }));

        this.app.use(express.json({ 
            limit: '10mb',
            verify: (req, res, buf) => {
                req.rawBody = buf;
            }
        }));
        
        this.app.use(express.urlencoded({ 
            extended: true, 
            limit: '10mb' 
        }));
        
        this.app.use(cookieParser(process.env.COOKIE_SECRET));

        // セキュリティ系ミドルウェア
        this.app.use(mongoSanitize({
            replaceWith: '_',
            onSanitize: ({ req, key }) => {
                logger.warn('MongoDB injection attempt', {
                    ip: req.ip,
                    key,
                    userAgent: req.get('User-Agent')
                });
            }
        }));
        
        this.app.use(xss());
        this.app.use(hpp());

        // セッション管理
        this.setupSession();

        // CSRF保護
        this.app.use(csrf({
            cookie: {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 3600000 // 1時間
            },
            ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
            value: (req) => {
                return req.body._csrf || 
                       req.query._csrf || 
                       req.headers['x-csrf-token'];
            }
        }));

        // リクエストログ
        this.app.use(requestLogger);

        // リクエスト検証
        this.app.use(this.validateRequest.bind(this));
    }

    /**
     * 許可オリジン取得
     */
    getAllowedOrigins() {
        if (process.env.NODE_ENV === 'production') {
            return [
                'https://shinai.co.jp',
                'https://www.shinai.co.jp',
                'https://api.shinai.co.jp'
            ];
        }
        
        return [
            'http://localhost:3000',
            'http://localhost:8080',
            'http://127.0.0.1:3000'
        ];
    }

    /**
     * レート制限設定
     */
    setupRateLimiting() {
        // 一般API制限
        const generalLimiter = rateLimit({
            windowMs: 15 * 60 * 1000, // 15分
            max: 100, // 最大100リクエスト
            message: {
                error: 'Too many requests from this IP',
                retryAfter: '15 minutes',
                limit: 100
            },
            standardHeaders: true,
            legacyHeaders: false,
            keyGenerator: (req) => {
                return req.ip + ':' + (req.headers['x-forwarded-for'] || '');
            },
            skip: (req) => {
                // ヘルスチェックは制限対象外
                return req.path === '/health';
            }
        });

        // 認証API厳格制限
        const authLimiter = rateLimit({
            windowMs: 15 * 60 * 1000,
            max: 5,
            message: {
                error: 'Too many authentication attempts',
                retryAfter: '15 minutes',
                limit: 5
            },
            skipSuccessfulRequests: true
        });

        // お問い合わせAPI制限
        const contactLimiter = rateLimit({
            windowMs: 60 * 60 * 1000, // 1時間
            max: 3,
            message: {
                error: 'Too many contact submissions',
                retryAfter: '1 hour',
                limit: 3
            }
        });

        this.app.use('/api/', generalLimiter);
        this.app.use('/api/v1/auth', authLimiter);
        this.app.use('/api/v1/contact', contactLimiter);
    }

    /**
     * セッション設定
     */
    setupSession() {
        this.app.use(session({
            name: 'shinai_session',
            secret: process.env.SESSION_SECRET,
            resave: false,
            saveUninitialized: false,
            store: MongoStore.create({
                mongoUrl: process.env.MONGODB_URI,
                touchAfter: 24 * 3600, // 24時間
                ttl: 30 * 60, // 30分
                crypto: {
                    secret: process.env.SESSION_CRYPTO_SECRET
                }
            }),
            cookie: {
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                maxAge: 30 * 60 * 1000, // 30分
                sameSite: 'strict'
            },
            rolling: true // アクティビティで延長
        }));
    }

    /**
     * リクエスト検証
     */
    validateRequest(req, res, next) {
        try {
            // User-Agent検証
            const userAgent = req.get('User-Agent');
            if (!userAgent || userAgent.length > 500) {
                return res.status(400).json({
                    error: 'Invalid User-Agent'
                });
            }

            // Content-Length検証
            const contentLength = req.get('Content-Length');
            if (contentLength && parseInt(contentLength) > 10 * 1024 * 1024) {
                return res.status(413).json({
                    error: 'Request too large'
                });
            }

            // クライアントバージョン確認
            const clientVersion = req.get('X-Client-Version');
            if (req.path.startsWith('/api') && clientVersion) {
                this.validateClientVersion(clientVersion);
            }

            // 危険なパターン検知
            const suspiciousPatterns = [
                /(\b(union|select|insert|delete|drop|create|alter|exec)\b)/i,
                /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
                /javascript:/i,
                /vbscript:/i
            ];

            const requestString = JSON.stringify(req.body) + req.url + JSON.stringify(req.query);
            
            for (const pattern of suspiciousPatterns) {
                if (pattern.test(requestString)) {
                    logger.warn('Suspicious request pattern detected', {
                        ip: req.ip,
                        userAgent,
                        pattern: pattern.toString(),
                        path: req.path
                    });

                    return res.status(400).json({
                        error: 'Invalid request format'
                    });
                }
            }

            next();

        } catch (error) {
            logger.error('Request validation failed:', error);
            next(error);
        }
    }

    /**
     * クライアントバージョン検証
     */
    validateClientVersion(version) {
        const supportedVersions = ['2.0.0', '2.0.0-secure'];
        
        if (!supportedVersions.includes(version)) {
            logger.warn('Unsupported client version:', version);
        }
    }

    /**
     * ルート設定
     */
    setupRoutes() {
        // CSRFトークンエンドポイント
        this.app.get('/api/v1/auth/csrf', (req, res) => {
            res.json({
                success: true,
                token: req.csrfToken(),
                timestamp: new Date().toISOString()
            });
        });

        // APIルート
        this.app.use('/api/v1/auth', authRoutes);
        this.app.use('/api/v1/services', serviceRoutes);
        this.app.use('/api/v1/contact', contactRoutes);
        this.app.use('/api/v1/pricing', pricingRoutes);
        this.app.use('/api/v1/audit', auditRoutes);

        // ヘルスチェック
        this.app.get('/health', (req, res) => {
            const healthStatus = {
                status: 'healthy',
                timestamp: new Date().toISOString(),
                version: process.env.npm_package_version || '1.0.0',
                uptime: Math.floor(process.uptime()),
                memory: process.memoryUsage(),
                env: process.env.NODE_ENV
            };

            res.status(200).json(healthStatus);
        });

        // APIドキュメント（開発環境のみ）
        if (process.env.NODE_ENV === 'development') {
            this.app.get('/api/docs', (req, res) => {
                res.json({
                    title: 'ShinAI Secure API',
                    version: '1.0.0',
                    endpoints: {
                        auth: '/api/v1/auth',
                        services: '/api/v1/services',
                        contact: '/api/v1/contact',
                        pricing: '/api/v1/pricing'
                    }
                });
            });
        }

        // ルート情報
        this.app.get('/api/v1', (req, res) => {
            res.json({
                service: 'ShinAI Secure API',
                version: '1.0.0',
                timestamp: new Date().toISOString(),
                documentation: process.env.NODE_ENV === 'development' ? '/api/docs' : null
            });
        });
    }

    /**
     * エラーハンドリング設定
     */
    setupErrorHandling() {
        // 404ハンドラー
        this.app.use(notFoundHandler);

        // グローバルエラーハンドラー
        this.app.use(errorHandler);

        // プロセスレベルエラーハンドリング
        process.on('uncaughtException', (error) => {
            logger.error('Uncaught Exception:', error);
            this.gracefulShutdown('UNCAUGHT_EXCEPTION');
        });

        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
            this.gracefulShutdown('UNHANDLED_REJECTION');
        });
    }

    /**
     * グレースフルシャットダウン設定
     */
    setupGracefulShutdown() {
        const signals = ['SIGINT', 'SIGTERM', 'SIGQUIT'];
        
        signals.forEach(signal => {
            process.on(signal, () => {
                logger.info(`Received ${signal}, shutting down gracefully`);
                this.gracefulShutdown(signal);
            });
        });
    }

    /**
     * グレースフルシャットダウン実行
     */
    async gracefulShutdown(signal) {
        if (this.isShuttingDown) {
            logger.warn('Shutdown already in progress');
            return;
        }

        this.isShuttingDown = true;
        logger.info(`Starting graceful shutdown (${signal})`);

        try {
            // 新規リクエスト停止
            if (this.server) {
                this.server.close(() => {
                    logger.info('HTTP server closed');
                });
            }

            // アクティブ接続の完了を待つ
            await this.waitForActiveConnections();

            // データベース接続クローズ
            await this.closeDatabase();

            logger.info('Graceful shutdown completed');
            process.exit(0);

        } catch (error) {
            logger.error('Error during shutdown:', error);
            process.exit(1);
        }
    }

    /**
     * アクティブ接続完了待ち
     */
    async waitForActiveConnections(timeout = 30000) {
        return new Promise((resolve) => {
            const deadline = Date.now() + timeout;
            
            const checkConnections = () => {
                if (Date.now() > deadline) {
                    logger.warn('Shutdown timeout reached, forcing exit');
                    resolve();
                    return;
                }

                // アクティブ接続チェック
                if (this.server && this.server.listening) {
                    setTimeout(checkConnections, 100);
                } else {
                    resolve();
                }
            };

            checkConnections();
        });
    }

    /**
     * データベース接続クローズ
     */
    async closeDatabase() {
        try {
            // MongoDB接続クローズ
            const mongoose = require('mongoose');
            await mongoose.connection.close();
            logger.info('MongoDB connection closed');

            // Redis接続クローズ
            const redis = require('./config/redis');
            if (redis.client) {
                await redis.client.quit();
                logger.info('Redis connection closed');
            }

        } catch (error) {
            logger.error('Database closure error:', error);
        }
    }

    /**
     * サーバー起動
     */
    start() {
        const PORT = process.env.PORT || 3001;
        const HOST = process.env.HOST || '0.0.0.0';

        this.server = this.app.listen(PORT, HOST, () => {
            logger.info(`Secure API server running on ${HOST}:${PORT}`);
            logger.info(`Environment: ${process.env.NODE_ENV}`);
            logger.info(`Process ID: ${process.pid}`);
        });

        // サーバーエラーハンドリング
        this.server.on('error', (error) => {
            if (error.code === 'EADDRINUSE') {
                logger.error(`Port ${PORT} is already in use`);
            } else {
                logger.error('Server error:', error);
            }
            process.exit(1);
        });

        return this.server;
    }
}

// サーバーインスタンス作成・起動
const secureServer = new SecureAPIServer();

if (require.main === module) {
    secureServer.start();
}

module.exports = secureServer.app;