/**
 * アラート管理システム
 * 脅威・違反検知時の即座通知・エスカレーション管理
 * masa様開発ルール完全遵守・多チャンネル通知実装
 */
const nodemailer = require('nodemailer');
const axios = require('axios');
const crypto = require('crypto');
const moment = require('moment');

class AlertManager {
    constructor(options = {}) {
        this.logger = options.logger;
        this.redis = options.redis;
        this.webhookUrl = options.webhookUrl;
        this.emailAddress = options.emailAddress;
        
        // アラート設定
        this.alertConfig = {
            threat: {
                enabled: true,
                cooldown: 300, // 5分間のクールダウン
                escalation_levels: ['low', 'medium', 'high', 'critical'],
                channels: ['email', 'webhook', 'log']
            },
            compliance: {
                enabled: true,
                cooldown: 600, // 10分間のクールダウン
                escalation_levels: ['medium', 'high', 'critical'],
                channels: ['email', 'webhook', 'log', 'audit']
            },
            system: {
                enabled: true,
                cooldown: 900, // 15分間のクールダウン
                escalation_levels: ['low', 'medium', 'high'],
                channels: ['email', 'log']
            }
        };
        
        // メール設定
        this.mailTransporter = null;
        
        // 統計情報
        this.stats = {
            alerts_sent: 0,
            emails_sent: 0,
            webhooks_sent: 0,
            failed_deliveries: 0,
            last_alert: null
        };
        
        this.init();
    }

    /**
     * アラート管理システム初期化
     */
    async init() {
        try {
            // メール設定初期化
            await this.setupEmailTransporter();
            
            // Webhook設定検証
            await this.validateWebhookConfig();
            
            this.logger.info('AlertManager initialized successfully');
        } catch (error) {
            this.logger.error('AlertManager initialization failed:', error);
            throw error;
        }
    }

    /**
     * メール設定初期化
     */
    async setupEmailTransporter() {
        try {
            if (!process.env.EMAIL_HOST || !process.env.EMAIL_USER) {
                this.logger.warn('Email configuration missing, email alerts disabled');
                return;
            }

            this.mailTransporter = nodemailer.createTransporter({
                host: process.env.EMAIL_HOST,
                port: parseInt(process.env.EMAIL_PORT) || 587,
                secure: process.env.EMAIL_PORT === '465',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                },
                pool: true,
                maxConnections: 3,
                maxMessages: 10,
                tls: {
                    rejectUnauthorized: false
                }
            });

            // 接続テスト
            await this.mailTransporter.verify();
            this.logger.info('Email transporter configured successfully');

        } catch (error) {
            this.logger.warn('Email transporter setup failed:', error);
            this.mailTransporter = null;
        }
    }

    /**
     * Webhook設定検証
     */
    async validateWebhookConfig() {
        try {
            if (!this.webhookUrl) {
                this.logger.warn('Webhook URL not configured, webhook alerts disabled');
                return;
            }

            // Webhook テスト送信
            const testPayload = {
                type: 'test',
                message: 'AlertManager webhook test',
                timestamp: new Date().toISOString()
            };

            await axios.post(this.webhookUrl, testPayload, {
                timeout: 5000,
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'ShinAI-SecurityMonitoring/2.0'
                }
            });

            this.logger.info('Webhook configuration validated successfully');

        } catch (error) {
            this.logger.warn('Webhook validation failed:', error);
        }
    }

    /**
     * 脅威アラート送信
     */
    async sendThreatAlert(threatResult) {
        try {
            const alertType = 'threat';
            const alertLevel = this.mapSeverityToLevel(threatResult.severity);
            
            // クールダウンチェック
            if (await this.isInCooldown(alertType, threatResult.metadata.source_ip)) {
                this.logger.debug('Threat alert in cooldown period, skipping');
                return;
            }

            const alertData = {
                id: crypto.randomUUID(),
                type: alertType,
                level: alertLevel,
                severity: threatResult.severity,
                timestamp: new Date().toISOString(),
                threat_types: threatResult.threatTypes,
                confidence: threatResult.confidence,
                source: {
                    ip: threatResult.metadata.source_ip,
                    geolocation: threatResult.metadata.geolocation,
                    user_agent: threatResult.metadata.user_agent
                },
                constitutional_compliant: threatResult.constitutional_compliant,
                metadata: threatResult.metadata,
                recommended_actions: this.getRecommendedActions('threat', threatResult)
            };

            // アラート送信実行
            await this.executeAlert(alertType, alertData);
            
            // クールダウン設定
            await this.setCooldown(alertType, threatResult.metadata.source_ip);
            
            this.stats.alerts_sent++;
            this.stats.last_alert = new Date();
            
            this.logger.info('Threat alert sent successfully:', {
                id: alertData.id,
                severity: alertData.severity,
                types: alertData.threat_types
            });

        } catch (error) {
            this.stats.failed_deliveries++;
            this.logger.error('Threat alert sending failed:', error);
            throw error;
        }
    }

    /**
     * コンプライアンスアラート送信
     */
    async sendComplianceAlert(complianceResult) {
        try {
            const alertType = 'compliance';
            const alertLevel = this.mapComplianceToLevel(complianceResult);
            
            // 重要違反は常に送信
            const isCriticalViolation = complianceResult.violations.some(v => v.severity === 'critical');
            
            if (!isCriticalViolation && await this.isInCooldown(alertType)) {
                this.logger.debug('Compliance alert in cooldown period, skipping');
                return;
            }

            const alertData = {
                id: crypto.randomUUID(),
                type: alertType,
                level: alertLevel,
                timestamp: new Date().toISOString(),
                compliance_score: complianceResult.score,
                violations: complianceResult.violations.map(v => ({
                    principle: v.principle,
                    description: v.description,
                    severity: v.severity,
                    confidence: v.confidence,
                    context: v.context?.slice(0, 200) // コンテキストを制限
                })),
                principles_checked: complianceResult.principles_checked,
                metadata: complianceResult.metadata,
                recommended_actions: this.getRecommendedActions('compliance', complianceResult)
            };

            // Constitutional AI違反の特別処理
            if (!complianceResult.compliant) {
                alertData.priority = 'high';
                alertData.requires_immediate_attention = true;
            }

            await this.executeAlert(alertType, alertData);
            
            if (!isCriticalViolation) {
                await this.setCooldown(alertType);
            }
            
            this.stats.alerts_sent++;
            this.stats.last_alert = new Date();
            
            this.logger.error('Constitutional AI compliance violation alert sent:', {
                id: alertData.id,
                score: alertData.compliance_score,
                violations: alertData.violations.length
            });

        } catch (error) {
            this.stats.failed_deliveries++;
            this.logger.error('Compliance alert sending failed:', error);
            throw error;
        }
    }

    /**
     * システムアラート送信
     */
    async sendSystemAlert(systemStatus, message) {
        try {
            const alertType = 'system';
            const alertLevel = systemStatus === 'error' ? 'high' : 'medium';
            
            if (await this.isInCooldown(alertType)) {
                return;
            }

            const alertData = {
                id: crypto.randomUUID(),
                type: alertType,
                level: alertLevel,
                timestamp: new Date().toISOString(),
                status: systemStatus,
                message: message,
                system_info: {
                    memory: process.memoryUsage(),
                    uptime: process.uptime(),
                    load_average: process.loadavg ? process.loadavg() : null
                },
                recommended_actions: this.getRecommendedActions('system', { status: systemStatus })
            };

            await this.executeAlert(alertType, alertData);
            await this.setCooldown(alertType);
            
            this.stats.alerts_sent++;
            
            this.logger.info('System alert sent:', {
                id: alertData.id,
                status: systemStatus,
                message: message
            });

        } catch (error) {
            this.stats.failed_deliveries++;
            this.logger.error('System alert sending failed:', error);
        }
    }

    /**
     * アラート実行
     */
    async executeAlert(alertType, alertData) {
        const config = this.alertConfig[alertType];
        const promises = [];

        // 各チャンネルでアラート送信
        for (const channel of config.channels) {
            switch (channel) {
                case 'email':
                    promises.push(this.sendEmailAlert(alertData));
                    break;
                case 'webhook':
                    promises.push(this.sendWebhookAlert(alertData));
                    break;
                case 'log':
                    promises.push(this.sendLogAlert(alertData));
                    break;
                case 'audit':
                    promises.push(this.sendAuditAlert(alertData));
                    break;
            }
        }

        // 全チャンネルで送信実行
        const results = await Promise.allSettled(promises);
        
        // 失敗したチャンネルをログ
        results.forEach((result, index) => {
            if (result.status === 'rejected') {
                const channel = config.channels[index];
                this.logger.warn(`Alert delivery failed for channel ${channel}:`, result.reason);
            }
        });
    }

    /**
     * メールアラート送信
     */
    async sendEmailAlert(alertData) {
        if (!this.mailTransporter || !this.emailAddress) {
            throw new Error('Email configuration not available');
        }

        const subject = this.generateEmailSubject(alertData);
        const htmlBody = this.generateEmailBody(alertData);

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: this.emailAddress,
            subject: subject,
            html: htmlBody,
            priority: alertData.level === 'critical' ? 'high' : 'normal'
        };

        await this.mailTransporter.sendMail(mailOptions);
        this.stats.emails_sent++;
        
        this.logger.debug('Email alert sent successfully');
    }

    /**
     * Webhookアラート送信
     */
    async sendWebhookAlert(alertData) {
        if (!this.webhookUrl) {
            throw new Error('Webhook URL not configured');
        }

        const payload = {
            ...alertData,
            service: 'ShinAI Security Monitoring',
            environment: process.env.NODE_ENV || 'production'
        };

        await axios.post(this.webhookUrl, payload, {
            timeout: 10000,
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'ShinAI-SecurityMonitoring/2.0',
                'X-Alert-Signature': this.generateWebhookSignature(payload)
            }
        });

        this.stats.webhooks_sent++;
        this.logger.debug('Webhook alert sent successfully');
    }

    /**
     * ログアラート送信
     */
    async sendLogAlert(alertData) {
        const logLevel = alertData.level === 'critical' ? 'error' : 'warn';
        
        this.logger[logLevel]('SECURITY ALERT:', {
            id: alertData.id,
            type: alertData.type,
            level: alertData.level,
            timestamp: alertData.timestamp,
            details: alertData
        });
    }

    /**
     * 監査アラート送信
     */
    async sendAuditAlert(alertData) {
        const auditKey = `audit:alert:${alertData.id}`;
        const auditData = {
            ...alertData,
            audit_timestamp: new Date().toISOString(),
            source_system: 'shinai-security-monitoring'
        };

        await this.redis.setEx(auditKey, 2592000, JSON.stringify(auditData)); // 30日間保存
        
        this.logger.info('Audit alert recorded');
    }

    /**
     * 日次レポート送信
     */
    async sendDailyReport(report) {
        try {
            if (!this.mailTransporter || !this.emailAddress) {
                this.logger.warn('Cannot send daily report: email not configured');
                return;
            }

            const subject = `ShinAI セキュリティ日次レポート - ${report.date}`;
            const htmlBody = this.generateDailyReportBody(report);

            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: this.emailAddress,
                subject: subject,
                html: htmlBody,
                attachments: [{
                    filename: `security-report-${report.date}.json`,
                    content: JSON.stringify(report, null, 2),
                    contentType: 'application/json'
                }]
            };

            await this.mailTransporter.sendMail(mailOptions);
            
            this.logger.info('Daily security report sent successfully');

        } catch (error) {
            this.logger.error('Daily report sending failed:', error);
        }
    }

    // === ユーティリティメソッド ===

    /**
     * 重要度レベルマッピング
     */
    mapSeverityToLevel(severity) {
        const mapping = {
            'low': 'low',
            'medium': 'medium', 
            'high': 'high',
            'critical': 'critical'
        };
        return mapping[severity] || 'medium';
    }

    mapComplianceToLevel(complianceResult) {
        if (complianceResult.score < 0.5) return 'critical';
        if (complianceResult.score < 0.7) return 'high';
        if (complianceResult.score < 0.9) return 'medium';
        return 'low';
    }

    /**
     * クールダウンチェック
     */
    async isInCooldown(alertType, identifier = 'general') {
        try {
            const key = `alert:cooldown:${alertType}:${identifier}`;
            const exists = await this.redis.exists(key);
            return exists === 1;
        } catch (error) {
            return false;
        }
    }

    /**
     * クールダウン設定
     */
    async setCooldown(alertType, identifier = 'general') {
        try {
            const key = `alert:cooldown:${alertType}:${identifier}`;
            const cooldown = this.alertConfig[alertType]?.cooldown || 300;
            await this.redis.setEx(key, cooldown, '1');
        } catch (error) {
            this.logger.warn('Cooldown setting failed:', error);
        }
    }

    /**
     * 推奨アクション生成
     */
    getRecommendedActions(alertType, data) {
        const actions = [];

        switch (alertType) {
            case 'threat':
                actions.push('IPアドレスのブロックを検討');
                if (data.threatTypes.includes('sql_injection')) {
                    actions.push('データベースアクセス権限の確認');
                }
                if (data.threatTypes.includes('constitutional_violation')) {
                    actions.push('Constitutional AI準拠の即座確認');
                }
                break;

            case 'compliance':
                actions.push('Constitutional AI準拠状態の確認');
                actions.push('違反内容の詳細分析');
                if (data.score < 0.5) {
                    actions.push('システム停止の検討');
                }
                break;

            case 'system':
                actions.push('システム状態の確認');
                if (data.status === 'error') {
                    actions.push('ログの詳細確認');
                }
                break;
        }

        return actions;
    }

    /**
     * メール件名生成
     */
    generateEmailSubject(alertData) {
        const prefix = '[ShinAI Security]';
        const urgency = alertData.level === 'critical' ? '[緊急]' : 
                       alertData.level === 'high' ? '[重要]' : '';
        
        let subject = `${prefix}${urgency} `;
        
        switch (alertData.type) {
            case 'threat':
                subject += `脅威検知 - ${alertData.threat_types.join(', ')}`;
                break;
            case 'compliance':
                subject += `Constitutional AI違反検知 - ${alertData.violations.length}件`;
                break;
            case 'system':
                subject += `システムアラート - ${alertData.status}`;
                break;
        }

        return subject;
    }

    /**
     * メール本文生成
     */
    generateEmailBody(alertData) {
        return `
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f44336; color: white; padding: 10px; border-radius: 5px; }
                .content { margin: 20px 0; }
                .details { background-color: #f9f9f9; padding: 15px; border-radius: 5px; }
                .actions { background-color: #e8f5e8; padding: 10px; border-radius: 5px; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>ShinAI セキュリティアラート</h2>
                <p>重要度: ${alertData.level.toUpperCase()} | 時刻: ${alertData.timestamp}</p>
            </div>
            
            <div class="content">
                <h3>アラート詳細</h3>
                <div class="details">
                    <p><strong>ID:</strong> ${alertData.id}</p>
                    <p><strong>タイプ:</strong> ${alertData.type}</p>
                    <p><strong>検知時刻:</strong> ${alertData.timestamp}</p>
                    ${alertData.threat_types ? `<p><strong>脅威タイプ:</strong> ${alertData.threat_types.join(', ')}</p>` : ''}
                    ${alertData.compliance_score !== undefined ? `<p><strong>準拠スコア:</strong> ${(alertData.compliance_score * 100).toFixed(1)}%</p>` : ''}
                </div>
            </div>
            
            <div class="actions">
                <h3>推奨アクション</h3>
                <ul>
                    ${alertData.recommended_actions.map(action => `<li>${action}</li>`).join('')}
                </ul>
            </div>
            
            <p><small>このメールは ShinAI Security Monitoring System により自動送信されました。</small></p>
        </body>
        </html>
        `;
    }

    /**
     * 日次レポート本文生成
     */
    generateDailyReportBody(report) {
        return `
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #2196F3; color: white; padding: 15px; border-radius: 5px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .stats { display: flex; justify-content: space-around; text-align: center; }
                .stat-item { padding: 10px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>ShinAI セキュリティ日次レポート</h1>
                <p>対象日: ${report.date}</p>
            </div>
            
            <div class="section">
                <h2>統計サマリー</h2>
                <div class="stats">
                    <div class="stat-item">
                        <h3>${report.stats.threats_detected || 0}</h3>
                        <p>脅威検知数</p>
                    </div>
                    <div class="stat-item">
                        <h3>${report.stats.alerts_sent || 0}</h3>
                        <p>送信アラート数</p>
                    </div>
                    <div class="stat-item">
                        <h3>${report.stats.processed_events || 0}</h3>
                        <p>処理イベント数</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Constitutional AI準拠状況</h2>
                <p>準拠スコア: <strong>${((report.compliance?.overall_compliance_score || 1.0) * 100).toFixed(1)}%</strong></p>
                <p>違反検知数: <strong>${report.compliance?.total_violations || 0}件</strong></p>
            </div>
            
            <p><small>詳細データは添付のJSONファイルをご確認ください。</small></p>
        </body>
        </html>
        `;
    }

    /**
     * Webhook署名生成
     */
    generateWebhookSignature(payload) {
        const secret = process.env.WEBHOOK_SECRET || 'default_secret';
        const data = JSON.stringify(payload);
        return crypto.createHmac('sha256', secret).update(data).digest('hex');
    }

    /**
     * 日次アラートサマリー取得
     */
    async getDailyAlertSummary() {
        try {
            const today = moment().format('YYYY-MM-DD');
            const key = `alerts:daily:${today}`;
            const summary = await this.redis.get(key);
            
            return summary ? JSON.parse(summary) : {
                date: today,
                total_alerts: 0,
                by_type: {},
                by_level: {}
            };

        } catch (error) {
            this.logger.warn('Daily alert summary error:', error);
            return {
                date: moment().format('YYYY-MM-DD'),
                total_alerts: 0
            };
        }
    }

    /**
     * アラート統計取得
     */
    getAlertStats() {
        return {
            ...this.stats,
            uptime: process.uptime(),
            timestamp: new Date().toISOString()
        };
    }
}

module.exports = AlertManager;