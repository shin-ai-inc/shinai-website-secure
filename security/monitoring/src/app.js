/**
 * ShinAI セキュリティ監視システム
 * 侵入検知・脅威分析・Constitutional AI準拠監視
 * masa様開発ルール完全遵守・リアルタイム監視実装
 */
const express = require('express');
const winston = require('winston');
const mongoose = require('mongoose');
const redis = require('redis');
const cron = require('node-cron');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const validator = require('validator');

// セキュリティ監視モジュール
const SecurityMonitor = require('./monitors/securityMonitor');
const ThreatDetector = require('./detectors/threatDetector');
const ComplianceChecker = require('./checkers/complianceChecker');
const AlertManager = require('./alerts/alertManager');
const AuditLogger = require('./loggers/auditLogger');

class ShinAISecurityMonitoringSystem {
    constructor() {
        this.app = express();
        this.isShuttingDown = false;
        
        // 統計情報
        this.stats = {
            threats_detected: 0,
            alerts_sent: 0,
            uptime: Date.now(),
            processed_events: 0,
            constitutional_violations: 0
        };
        
        this.init();
    }

    /**
     * システム初期化
     */
    async init() {
        try {
            // データベース接続
            await this.connectDatabase();
            
            // Redis接続
            await this.connectRedis();
            
            // ログシステム設定
            this.setupLogging();
            
            // セキュリティ監視設定
            this.setupSecurityMonitoring();
            
            // Express設定
            this.setupExpress();
            
            // スケジュール設定
            this.setupScheduledTasks();
            
            // グレースフルシャットダウン
            this.setupGracefulShutdown();
            
            this.logger.info('ShinAI Security Monitoring System initialized successfully');
            
        } catch (error) {
            console.error('System initialization failed:', error);
            process.exit(1);
        }
    }

    /**
     * データベース接続
     */
    async connectDatabase() {
        const mongoUri = process.env.MONGODB_URI;
        if (!mongoUri) {
            throw new Error('MONGODB_URI environment variable is required');
        }

        await mongoose.connect(mongoUri, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000
        });

        this.logger.info('MongoDB connected successfully');
    }

    /**
     * Redis接続
     */
    async connectRedis() {
        this.redisClient = redis.createClient({
            url: process.env.REDIS_URL,
            password: process.env.REDIS_PASSWORD
        });

        this.redisClient.on('error', (err) => {
            this.logger.error('Redis connection error:', err);
        });

        await this.redisClient.connect();
        this.logger.info('Redis connected successfully');
    }

    /**
     * ログシステム設定
     */
    setupLogging() {
        this.logger = winston.createLogger({
            level: process.env.LOG_LEVEL || 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.json()
            ),
            defaultMeta: { 
                service: 'shinai-security-monitoring',
                environment: process.env.NODE_ENV 
            },
            transports: [
                new winston.transports.File({ 
                    filename: '/var/log/security/error.log', 
                    level: 'error' 
                }),
                new winston.transports.File({ 
                    filename: '/var/log/security/security.log' 
                }),
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.colorize(),
                        winston.format.simple()
                    )
                })
            ]
        });

        // MongoDB ログ設定
        if (process.env.MONGODB_URI) {
            this.logger.add(new winston.transports.MongoDB({
                db: process.env.MONGODB_URI,
                collection: 'security_logs',
                options: { useUnifiedTopology: true }
            }));
        }
    }

    /**
     * セキュリティ監視設定
     */
    setupSecurityMonitoring() {
        // セキュリティ監視器初期化
        this.securityMonitor = new SecurityMonitor({
            logger: this.logger,
            redis: this.redisClient
        });

        // 脅威検知器初期化
        this.threatDetector = new ThreatDetector({
            logger: this.logger,
            redis: this.redisClient,
            geoip: geoip,
            uaParser: UAParser
        });

        // Constitutional AI準拠チェッカー初期化
        this.complianceChecker = new ComplianceChecker({
            logger: this.logger,
            redis: this.redisClient
        });

        // アラート管理器初期化
        this.alertManager = new AlertManager({
            logger: this.logger,
            redis: this.redisClient,
            webhookUrl: process.env.ALERT_WEBHOOK,
            emailAddress: process.env.ALERT_EMAIL
        });

        // 監査ログ管理器初期化
        this.auditLogger = new AuditLogger({
            logger: this.logger,
            mongodb: mongoose.connection
        });
    }

    /**
     * Express設定
     */
    setupExpress() {
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'"],
                    styleSrc: ["'self'"],
                    imgSrc: ["'self'", "data:"]
                }
            }
        }));

        this.app.use(express.json({ limit: '1mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '1mb' }));

        // セキュリティイベント受信エンドポイント
        this.app.post('/security/event', async (req, res) => {
            try {
                await this.processSecurityEvent(req.body);
                res.json({ success: true, timestamp: new Date().toISOString() });
            } catch (error) {
                this.logger.error('Security event processing failed:', error);
                res.status(500).json({ 
                    error: 'Event processing failed',
                    timestamp: new Date().toISOString()
                });
            }
        });

        // 統計情報エンドポイント
        this.app.get('/security/stats', (req, res) => {
            res.json({
                ...this.stats,
                uptime_seconds: Math.floor((Date.now() - this.stats.uptime) / 1000),
                timestamp: new Date().toISOString()
            });
        });

        // ヘルスチェック
        this.app.get('/health', (req, res) => {
            const health = {
                status: 'healthy',
                timestamp: new Date().toISOString(),
                mongodb: mongoose.connection.readyState === 1,
                redis: this.redisClient.isReady,
                memory: process.memoryUsage(),
                stats: this.stats
            };

            res.json(health);
        });

        // Constitutional AI準拠チェック
        this.app.post('/security/compliance/check', async (req, res) => {
            try {
                const result = await this.complianceChecker.checkCompliance(req.body);
                res.json(result);
            } catch (error) {
                this.logger.error('Compliance check failed:', error);
                res.status(500).json({
                    error: 'Compliance check failed',
                    timestamp: new Date().toISOString()
                });
            }
        });
    }

    /**
     * セキュリティイベント処理
     */
    async processSecurityEvent(eventData) {
        try {
            this.stats.processed_events++;
            
            // イベント検証
            if (!this.validateSecurityEvent(eventData)) {
                this.logger.warn('Invalid security event received:', eventData);
                return;
            }

            // 脅威検知
            const threatResult = await this.threatDetector.analyzeThreat(eventData);
            if (threatResult.isThreat) {
                this.stats.threats_detected++;
                
                // アラート送信
                await this.alertManager.sendThreatAlert(threatResult);
                this.stats.alerts_sent++;
                
                // 監査ログ記録
                await this.auditLogger.logSecurityEvent('threat_detected', {
                    event: eventData,
                    threat: threatResult,
                    timestamp: new Date()
                });
            }

            // Constitutional AI準拠チェック
            const complianceResult = await this.complianceChecker.checkEventCompliance(eventData);
            if (!complianceResult.compliant) {
                this.stats.constitutional_violations++;
                
                // コンプライアンス違反アラート
                await this.alertManager.sendComplianceAlert(complianceResult);
                
                // 監査ログ記録
                await this.auditLogger.logSecurityEvent('constitutional_violation', {
                    event: eventData,
                    violation: complianceResult,
                    timestamp: new Date()
                });
            }

            // セキュリティ監視データ更新
            await this.securityMonitor.updateSecurityMetrics(eventData);

        } catch (error) {
            this.logger.error('Security event processing error:', error);
            throw error;
        }
    }

    /**
     * セキュリティイベント検証
     */
    validateSecurityEvent(eventData) {
        if (!eventData || typeof eventData !== 'object') {
            return false;
        }

        const requiredFields = ['timestamp', 'type', 'source', 'data'];
        for (const field of requiredFields) {
            if (!eventData[field]) {
                return false;
            }
        }

        // IP アドレス検証
        if (eventData.source.ip && !validator.isIP(eventData.source.ip)) {
            return false;
        }

        // タイムスタンプ検証
        if (!validator.isISO8601(eventData.timestamp)) {
            return false;
        }

        return true;
    }

    /**
     * スケジュール済みタスク設定
     */
    setupScheduledTasks() {
        // 定期セキュリティスキャン（1時間毎）
        cron.schedule('0 * * * *', async () => {
            try {
                await this.performSecurityScan();
            } catch (error) {
                this.logger.error('Scheduled security scan failed:', error);
            }
        });

        // 統計レポート生成（日次）
        cron.schedule('0 6 * * *', async () => {
            try {
                await this.generateDailyReport();
            } catch (error) {
                this.logger.error('Daily report generation failed:', error);
            }
        });

        // 古いログクリーンアップ（週次）
        cron.schedule('0 3 * * 0', async () => {
            try {
                await this.cleanupOldLogs();
            } catch (error) {
                this.logger.error('Log cleanup failed:', error);
            }
        });
    }

    /**
     * 定期セキュリティスキャン実行
     */
    async performSecurityScan() {
        this.logger.info('Starting scheduled security scan');
        
        try {
            // システムヘルスチェック
            const healthStatus = await this.securityMonitor.checkSystemHealth();
            
            // 脅威パターン更新
            await this.threatDetector.updateThreatPatterns();
            
            // Constitutional AI準拠状態チェック
            const complianceStatus = await this.complianceChecker.performComplianceScan();
            
            // レポート生成
            const scanReport = {
                timestamp: new Date(),
                health: healthStatus,
                compliance: complianceStatus,
                stats: this.stats
            };

            await this.auditLogger.logSecurityEvent('security_scan', scanReport);
            
            this.logger.info('Scheduled security scan completed successfully');
            
        } catch (error) {
            this.logger.error('Security scan failed:', error);
        }
    }

    /**
     * 日次レポート生成
     */
    async generateDailyReport() {
        this.logger.info('Generating daily security report');
        
        try {
            const report = {
                date: new Date().toISOString().split('T')[0],
                stats: this.stats,
                threats: await this.threatDetector.getDailyThreatSummary(),
                compliance: await this.complianceChecker.getDailyComplianceSummary(),
                alerts: await this.alertManager.getDailyAlertSummary()
            };

            // レポートをデータベースに保存
            await this.auditLogger.logSecurityEvent('daily_report', report);
            
            // 管理者にレポート送信
            await this.alertManager.sendDailyReport(report);
            
            this.logger.info('Daily security report generated and sent');
            
        } catch (error) {
            this.logger.error('Daily report generation failed:', error);
        }
    }

    /**
     * 古いログクリーンアップ
     */
    async cleanupOldLogs() {
        this.logger.info('Starting log cleanup');
        
        try {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - 30); // 30日前
            
            // 古いセキュリティログ削除
            await this.auditLogger.cleanupOldLogs(cutoffDate);
            
            // Redis キャッシュクリーンアップ
            await this.redisClient.eval(`
                local keys = redis.call('keys', ARGV[1])
                for i=1,#keys,5000 do
                    redis.call('del', unpack(keys, i, math.min(i+4999, #keys)))
                end
                return #keys
            `, 0, 'security:*');
            
            this.logger.info('Log cleanup completed');
            
        } catch (error) {
            this.logger.error('Log cleanup failed:', error);
        }
    }

    /**
     * グレースフルシャットダウン設定
     */
    setupGracefulShutdown() {
        const signals = ['SIGINT', 'SIGTERM', 'SIGQUIT'];
        
        signals.forEach(signal => {
            process.on(signal, () => {
                this.logger.info(`Received ${signal}, shutting down gracefully`);
                this.gracefulShutdown(signal);
            });
        });
    }

    /**
     * グレースフルシャットダウン実行
     */
    async gracefulShutdown(signal) {
        if (this.isShuttingDown) {
            this.logger.warn('Shutdown already in progress');
            return;
        }

        this.isShuttingDown = true;
        this.logger.info(`Starting graceful shutdown (${signal})`);

        try {
            // HTTP サーバークローズ
            if (this.server) {
                this.server.close(() => {
                    this.logger.info('HTTP server closed');
                });
            }

            // データベース接続クローズ
            await mongoose.connection.close();
            this.logger.info('MongoDB connection closed');

            // Redis接続クローズ
            await this.redisClient.quit();
            this.logger.info('Redis connection closed');

            this.logger.info('Graceful shutdown completed');
            process.exit(0);

        } catch (error) {
            this.logger.error('Error during shutdown:', error);
            process.exit(1);
        }
    }

    /**
     * サーバー起動
     */
    start() {
        const PORT = process.env.PORT || 3002;
        const HOST = process.env.HOST || '0.0.0.0';

        this.server = this.app.listen(PORT, HOST, () => {
            this.logger.info(`ShinAI Security Monitoring System running on ${HOST}:${PORT}`);
            this.logger.info(`Environment: ${process.env.NODE_ENV}`);
            this.logger.info(`Process ID: ${process.pid}`);
        });

        this.server.on('error', (error) => {
            if (error.code === 'EADDRINUSE') {
                this.logger.error(`Port ${PORT} is already in use`);
            } else {
                this.logger.error('Server error:', error);
            }
            process.exit(1);
        });

        return this.server;
    }
}

// システムインスタンス作成・起動
const securityMonitoring = new ShinAISecurityMonitoringSystem();

if (require.main === module) {
    securityMonitoring.start();
}

module.exports = securityMonitoring;