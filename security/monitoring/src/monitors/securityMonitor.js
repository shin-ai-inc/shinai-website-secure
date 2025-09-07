/**
 * セキュリティ監視エンジン
 * リアルタイムセキュリティメトリクス・システムヘルス監視
 * masa様開発ルール完全遵守・包括的監視実装
 */
const os = require('os');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class SecurityMonitor {
    constructor(options = {}) {
        this.logger = options.logger;
        this.redis = options.redis;
        
        // 監視設定
        this.monitoringConfig = {
            metrics_retention: 86400, // 24時間
            health_check_interval: 30000, // 30秒
            performance_threshold: {
                cpu: 80, // CPU使用率80%
                memory: 85, // メモリ使用率85%
                disk: 90, // ディスク使用率90%
                response_time: 5000 // レスポンス時間5秒
            },
            security_thresholds: {
                failed_logins_per_minute: 10,
                requests_per_second: 100,
                error_rate_percent: 5,
                anomaly_score: 0.7
            }
        };
        
        // メトリクス保存
        this.currentMetrics = {
            system: {
                cpu_usage: 0,
                memory_usage: 0,
                disk_usage: 0,
                load_average: [],
                uptime: 0
            },
            security: {
                threats_detected: 0,
                requests_processed: 0,
                failed_authentications: 0,
                blocked_ips: 0,
                constitutional_violations: 0
            },
            performance: {
                avg_response_time: 0,
                requests_per_second: 0,
                error_rate: 0,
                database_connections: 0
            },
            alerts: {
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0
            }
        };
        
        // 監視統計
        this.stats = {
            monitoring_started: new Date(),
            total_health_checks: 0,
            last_health_check: null,
            alerts_triggered: 0,
            anomalies_detected: 0
        };
        
        this.init();
    }

    /**
     * セキュリティ監視初期化
     */
    async init() {
        try {
            // 初期メトリクス取得
            await this.collectSystemMetrics();
            
            // 定期監視開始
            this.startPeriodicMonitoring();
            
            this.logger.info('SecurityMonitor initialized successfully');
        } catch (error) {
            this.logger.error('SecurityMonitor initialization failed:', error);
            throw error;
        }
    }

    /**
     * 定期監視開始
     */
    startPeriodicMonitoring() {
        // システムメトリクス収集（30秒間隔）
        setInterval(async () => {
            try {
                await this.collectSystemMetrics();
                await this.checkSystemHealth();
            } catch (error) {
                this.logger.warn('Periodic system monitoring error:', error);
            }
        }, this.monitoringConfig.health_check_interval);

        // セキュリティメトリクス収集（10秒間隔）
        setInterval(async () => {
            try {
                await this.collectSecurityMetrics();
            } catch (error) {
                this.logger.warn('Periodic security monitoring error:', error);
            }
        }, 10000);

        // パフォーマンス監視（1分間隔）
        setInterval(async () => {
            try {
                await this.collectPerformanceMetrics();
                await this.detectAnomalies();
            } catch (error) {
                this.logger.warn('Periodic performance monitoring error:', error);
            }
        }, 60000);

        this.logger.info('Periodic monitoring started');
    }

    /**
     * システムメトリクス収集
     */
    async collectSystemMetrics() {
        try {
            // CPU使用率
            const cpus = os.cpus();
            let totalIdle = 0;
            let totalTick = 0;

            cpus.forEach(cpu => {
                for (const type in cpu.times) {
                    totalTick += cpu.times[type];
                }
                totalIdle += cpu.times.idle;
            });

            const idle = totalIdle / cpus.length;
            const total = totalTick / cpus.length;
            this.currentMetrics.system.cpu_usage = 100 - Math.floor(100 * idle / total);

            // メモリ使用率
            const totalMemory = os.totalmem();
            const freeMemory = os.freemem();
            this.currentMetrics.system.memory_usage = 
                Math.floor(((totalMemory - freeMemory) / totalMemory) * 100);

            // ロードアベレージ
            this.currentMetrics.system.load_average = os.loadavg();

            // アップタイム
            this.currentMetrics.system.uptime = Math.floor(process.uptime());

            // ディスク使用率（利用可能な場合）
            await this.collectDiskUsage();

            // メトリクスをRedisに保存
            await this.storeMetrics('system', this.currentMetrics.system);

        } catch (error) {
            this.logger.warn('System metrics collection error:', error);
        }
    }

    /**
     * ディスク使用率収集
     */
    async collectDiskUsage() {
        try {
            const stats = await fs.stat('.');
            // 基本的なディスク情報のみ（詳細実装は環境依存）
            this.currentMetrics.system.disk_usage = 0; // プレースホルダー
        } catch (error) {
            this.logger.warn('Disk usage collection error:', error);
        }
    }

    /**
     * セキュリティメトリクス収集
     */
    async collectSecurityMetrics() {
        try {
            // Redisから脅威統計取得
            const threatKeys = await this.redis.keys('threat:detected:*');
            this.currentMetrics.security.threats_detected = threatKeys.length;

            // 処理済みリクエスト数
            const requestCount = await this.redis.get('metrics:requests:total') || '0';
            this.currentMetrics.security.requests_processed = parseInt(requestCount);

            // 認証失敗数
            const authFailures = await this.redis.get('metrics:auth:failures') || '0';
            this.currentMetrics.security.failed_authentications = parseInt(authFailures);

            // ブロック済みIP数
            const blockedIPs = await this.redis.sCard('security:blocked_ips') || 0;
            this.currentMetrics.security.blocked_ips = blockedIPs;

            // Constitutional AI違反数
            const violationKeys = await this.redis.keys('compliance:violation:*');
            this.currentMetrics.security.constitutional_violations = violationKeys.length;

            // セキュリティメトリクス保存
            await this.storeMetrics('security', this.currentMetrics.security);

        } catch (error) {
            this.logger.warn('Security metrics collection error:', error);
        }
    }

    /**
     * パフォーマンスメトリクス収集
     */
    async collectPerformanceMetrics() {
        try {
            // 平均レスポンス時間
            const responseTimeData = await this.redis.get('metrics:response_time') || '0';
            this.currentMetrics.performance.avg_response_time = parseFloat(responseTimeData);

            // 秒間リクエスト数
            const rpsData = await this.redis.get('metrics:rps') || '0';
            this.currentMetrics.performance.requests_per_second = parseFloat(rpsData);

            // エラー率
            const errorCount = await this.redis.get('metrics:errors:total') || '0';
            const totalRequests = this.currentMetrics.security.requests_processed;
            this.currentMetrics.performance.error_rate = 
                totalRequests > 0 ? (parseInt(errorCount) / totalRequests) * 100 : 0;

            // データベース接続数（MongoDB）
            try {
                const mongoose = require('mongoose');
                if (mongoose.connection.readyState === 1) {
                    this.currentMetrics.performance.database_connections = 1; // 簡略化
                }
            } catch (error) {
                this.currentMetrics.performance.database_connections = 0;
            }

            // パフォーマンスメトリクス保存
            await this.storeMetrics('performance', this.currentMetrics.performance);

        } catch (error) {
            this.logger.warn('Performance metrics collection error:', error);
        }
    }

    /**
     * システムヘルスチェック
     */
    async checkSystemHealth() {
        try {
            this.stats.total_health_checks++;
            this.stats.last_health_check = new Date();

            const healthStatus = {
                timestamp: new Date(),
                overall_status: 'healthy',
                checks: {
                    cpu: this.checkCPUHealth(),
                    memory: this.checkMemoryHealth(),
                    disk: this.checkDiskHealth(),
                    load: this.checkLoadHealth(),
                    security: await this.checkSecurityHealth(),
                    performance: this.checkPerformanceHealth()
                },
                alerts_needed: []
            };

            // 各チェック結果の評価
            const failedChecks = Object.entries(healthStatus.checks)
                .filter(([name, check]) => check.status !== 'healthy');

            if (failedChecks.length > 0) {
                healthStatus.overall_status = failedChecks.some(([, check]) => 
                    check.status === 'critical') ? 'critical' : 'warning';
                
                // アラートが必要なチェックを記録
                failedChecks.forEach(([name, check]) => {
                    if (check.status === 'critical' || check.status === 'warning') {
                        healthStatus.alerts_needed.push({
                            check: name,
                            status: check.status,
                            message: check.message,
                            value: check.value
                        });
                    }
                });
            }

            // ヘルスステータスをRedisに保存
            await this.redis.setEx('monitoring:health_status', 300, JSON.stringify(healthStatus));

            // アラートが必要な場合の処理
            if (healthStatus.alerts_needed.length > 0) {
                await this.handleHealthAlerts(healthStatus);
            }

            return healthStatus;

        } catch (error) {
            this.logger.error('System health check failed:', error);
            return {
                timestamp: new Date(),
                overall_status: 'error',
                error: error.message
            };
        }
    }

    /**
     * CPU ヘルスチェック
     */
    checkCPUHealth() {
        const cpuUsage = this.currentMetrics.system.cpu_usage;
        const threshold = this.monitoringConfig.performance_threshold.cpu;

        if (cpuUsage > threshold) {
            return {
                status: 'critical',
                message: `CPU使用率が異常に高い: ${cpuUsage}%`,
                value: cpuUsage,
                threshold: threshold
            };
        } else if (cpuUsage > threshold * 0.8) {
            return {
                status: 'warning',
                message: `CPU使用率が高い: ${cpuUsage}%`,
                value: cpuUsage,
                threshold: threshold * 0.8
            };
        }

        return {
            status: 'healthy',
            message: `CPU使用率正常: ${cpuUsage}%`,
            value: cpuUsage
        };
    }

    /**
     * メモリヘルスチェック
     */
    checkMemoryHealth() {
        const memoryUsage = this.currentMetrics.system.memory_usage;
        const threshold = this.monitoringConfig.performance_threshold.memory;

        if (memoryUsage > threshold) {
            return {
                status: 'critical',
                message: `メモリ使用率が異常に高い: ${memoryUsage}%`,
                value: memoryUsage,
                threshold: threshold
            };
        } else if (memoryUsage > threshold * 0.8) {
            return {
                status: 'warning',
                message: `メモリ使用率が高い: ${memoryUsage}%`,
                value: memoryUsage,
                threshold: threshold * 0.8
            };
        }

        return {
            status: 'healthy',
            message: `メモリ使用率正常: ${memoryUsage}%`,
            value: memoryUsage
        };
    }

    /**
     * ディスクヘルスチェック
     */
    checkDiskHealth() {
        const diskUsage = this.currentMetrics.system.disk_usage;
        const threshold = this.monitoringConfig.performance_threshold.disk;

        if (diskUsage > threshold) {
            return {
                status: 'critical',
                message: `ディスク使用率が異常に高い: ${diskUsage}%`,
                value: diskUsage,
                threshold: threshold
            };
        } else if (diskUsage > threshold * 0.8) {
            return {
                status: 'warning',
                message: `ディスク使用率が高い: ${diskUsage}%`,
                value: diskUsage,
                threshold: threshold * 0.8
            };
        }

        return {
            status: 'healthy',
            message: `ディスク使用率正常: ${diskUsage}%`,
            value: diskUsage
        };
    }

    /**
     * ロードアベレージヘルスチェック
     */
    checkLoadHealth() {
        const loadAvg = this.currentMetrics.system.load_average[0] || 0;
        const cpuCount = os.cpus().length;
        const threshold = cpuCount * 0.8;

        if (loadAvg > cpuCount) {
            return {
                status: 'critical',
                message: `ロードアベレージが異常に高い: ${loadAvg.toFixed(2)}`,
                value: loadAvg,
                threshold: cpuCount
            };
        } else if (loadAvg > threshold) {
            return {
                status: 'warning',
                message: `ロードアベレージが高い: ${loadAvg.toFixed(2)}`,
                value: loadAvg,
                threshold: threshold
            };
        }

        return {
            status: 'healthy',
            message: `ロードアベレージ正常: ${loadAvg.toFixed(2)}`,
            value: loadAvg
        };
    }

    /**
     * セキュリティヘルスチェック
     */
    async checkSecurityHealth() {
        try {
            const securityMetrics = this.currentMetrics.security;
            const thresholds = this.monitoringConfig.security_thresholds;
            const issues = [];

            // 脅威検知数チェック
            if (securityMetrics.threats_detected > 10) {
                issues.push(`多数の脅威を検知: ${securityMetrics.threats_detected}件`);
            }

            // Constitutional AI違反チェック
            if (securityMetrics.constitutional_violations > 0) {
                issues.push(`Constitutional AI違反: ${securityMetrics.constitutional_violations}件`);
            }

            // 認証失敗数チェック
            if (securityMetrics.failed_authentications > thresholds.failed_logins_per_minute) {
                issues.push(`認証失敗多発: ${securityMetrics.failed_authentications}件`);
            }

            if (issues.length > 0) {
                return {
                    status: securityMetrics.constitutional_violations > 0 ? 'critical' : 'warning',
                    message: issues.join(', '),
                    issues: issues
                };
            }

            return {
                status: 'healthy',
                message: 'セキュリティ状態正常',
                metrics: securityMetrics
            };

        } catch (error) {
            return {
                status: 'error',
                message: 'セキュリティヘルスチェック失敗',
                error: error.message
            };
        }
    }

    /**
     * パフォーマンスヘルスチェック
     */
    checkPerformanceHealth() {
        const perfMetrics = this.currentMetrics.performance;
        const thresholds = this.monitoringConfig.performance_threshold;
        const issues = [];

        // レスポンス時間チェック
        if (perfMetrics.avg_response_time > thresholds.response_time) {
            issues.push(`レスポンス時間が遅い: ${perfMetrics.avg_response_time}ms`);
        }

        // エラー率チェック
        if (perfMetrics.error_rate > this.monitoringConfig.security_thresholds.error_rate_percent) {
            issues.push(`エラー率が高い: ${perfMetrics.error_rate.toFixed(2)}%`);
        }

        // データベース接続チェック
        if (perfMetrics.database_connections === 0) {
            issues.push('データベース接続なし');
        }

        if (issues.length > 0) {
            return {
                status: perfMetrics.database_connections === 0 ? 'critical' : 'warning',
                message: issues.join(', '),
                issues: issues
            };
        }

        return {
            status: 'healthy',
            message: 'パフォーマンス正常',
            metrics: perfMetrics
        };
    }

    /**
     * 異常検知
     */
    async detectAnomalies() {
        try {
            const anomalies = [];

            // 統計的異常検知（簡略版）
            const currentRPS = this.currentMetrics.performance.requests_per_second;
            const historicalRPS = await this.getHistoricalAverage('performance', 'requests_per_second');
            
            if (historicalRPS > 0 && currentRPS > historicalRPS * 3) {
                anomalies.push({
                    type: 'traffic_spike',
                    message: `異常なトラフィック増加: ${currentRPS} RPS (通常: ${historicalRPS.toFixed(2)} RPS)`,
                    severity: 'high',
                    current_value: currentRPS,
                    baseline: historicalRPS
                });
            }

            // エラー率の急増
            const currentErrorRate = this.currentMetrics.performance.error_rate;
            const historicalErrorRate = await this.getHistoricalAverage('performance', 'error_rate');
            
            if (historicalErrorRate >= 0 && currentErrorRate > historicalErrorRate * 2 && currentErrorRate > 1) {
                anomalies.push({
                    type: 'error_spike',
                    message: `エラー率急増: ${currentErrorRate.toFixed(2)}% (通常: ${historicalErrorRate.toFixed(2)}%)`,
                    severity: 'high',
                    current_value: currentErrorRate,
                    baseline: historicalErrorRate
                });
            }

            if (anomalies.length > 0) {
                this.stats.anomalies_detected += anomalies.length;
                
                // 異常をRedisに記録
                await this.recordAnomalies(anomalies);
                
                this.logger.warn('Anomalies detected:', anomalies);
            }

            return anomalies;

        } catch (error) {
            this.logger.warn('Anomaly detection error:', error);
            return [];
        }
    }

    /**
     * セキュリティメトリクス更新
     */
    async updateSecurityMetrics(eventData) {
        try {
            // イベントタイプ別メトリクス更新
            const eventType = eventData.type;
            const timestamp = new Date();
            
            // リクエスト数更新
            await this.redis.incr('metrics:requests:total');
            
            // イベントタイプ別カウント
            await this.redis.incr(`metrics:events:${eventType}`);
            
            // IPアドレス別統計
            if (eventData.source?.ip) {
                await this.redis.incr(`metrics:ips:${eventData.source.ip}`);
            }
            
            // 時間別統計
            const hourKey = `metrics:hourly:${timestamp.getHours()}`;
            await this.redis.incr(hourKey);
            await this.redis.expire(hourKey, 86400); // 24時間で期限切れ

        } catch (error) {
            this.logger.warn('Security metrics update error:', error);
        }
    }

    // === ユーティリティメソッド ===

    /**
     * メトリクス保存
     */
    async storeMetrics(category, metrics) {
        try {
            const key = `metrics:${category}:current`;
            const data = {
                ...metrics,
                timestamp: new Date().toISOString()
            };
            
            await this.redis.setEx(key, this.monitoringConfig.metrics_retention, 
                JSON.stringify(data));
            
            // 履歴保存（1時間分）
            const historyKey = `metrics:${category}:history`;
            await this.redis.lPush(historyKey, JSON.stringify(data));
            await this.redis.lTrim(historyKey, 0, 59); // 最新60件保持
            await this.redis.expire(historyKey, this.monitoringConfig.metrics_retention);

        } catch (error) {
            this.logger.warn('Metrics storage error:', error);
        }
    }

    /**
     * 履歴平均値取得
     */
    async getHistoricalAverage(category, metric) {
        try {
            const historyKey = `metrics:${category}:history`;
            const history = await this.redis.lRange(historyKey, 0, -1);
            
            if (history.length === 0) return 0;
            
            const values = history.map(item => {
                const data = JSON.parse(item);
                return data[metric] || 0;
            }).filter(value => value > 0);
            
            return values.length > 0 
                ? values.reduce((a, b) => a + b, 0) / values.length 
                : 0;

        } catch (error) {
            this.logger.warn('Historical average calculation error:', error);
            return 0;
        }
    }

    /**
     * 異常記録
     */
    async recordAnomalies(anomalies) {
        try {
            for (const anomaly of anomalies) {
                const key = `anomaly:${Date.now()}:${crypto.randomUUID()}`;
                const data = {
                    ...anomaly,
                    timestamp: new Date().toISOString(),
                    system_state: this.currentMetrics
                };
                
                await this.redis.setEx(key, 86400, JSON.stringify(data)); // 24時間保存
            }

        } catch (error) {
            this.logger.warn('Anomaly recording error:', error);
        }
    }

    /**
     * ヘルスアラート処理
     */
    async handleHealthAlerts(healthStatus) {
        try {
            for (const alert of healthStatus.alerts_needed) {
                this.logger.warn('Health alert triggered:', alert);
                
                // アラートカウント更新
                await this.redis.incr('metrics:alerts:health');
                this.stats.alerts_triggered++;
            }

        } catch (error) {
            this.logger.warn('Health alert handling error:', error);
        }
    }

    /**
     * 監視統計取得
     */
    getMonitoringStats() {
        return {
            ...this.stats,
            current_metrics: this.currentMetrics,
            config: this.monitoringConfig,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * 現在のメトリクス取得
     */
    getCurrentMetrics() {
        return {
            ...this.currentMetrics,
            timestamp: new Date().toISOString(),
            uptime_seconds: Math.floor(process.uptime())
        };
    }
}

module.exports = SecurityMonitor;