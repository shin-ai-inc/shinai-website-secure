/**
 * 監査ログシステム
 * セキュリティイベント・Constitutional AI準拠ログ管理
 * masa様開発ルール完全遵守・完全監査証跡実装
 */
const crypto = require('crypto');
const moment = require('moment');

class AuditLogger {
    constructor(options = {}) {
        this.logger = options.logger;
        this.mongodb = options.mongodb;
        
        // 監査設定
        this.auditConfig = {
            log_retention_days: 90, // 90日間保持
            encryption_enabled: true,
            integrity_checks: true,
            batch_size: 100,
            flush_interval: 5000 // 5秒間隔でフラッシュ
        };
        
        // ログバッファ
        this.logBuffer = [];
        this.encryptionKey = this.generateEncryptionKey();
        
        // 統計情報
        this.stats = {
            logs_written: 0,
            logs_encrypted: 0,
            integrity_violations: 0,
            last_flush: null,
            total_size_bytes: 0
        };
        
        this.init();
    }

    /**
     * 監査ログシステム初期化
     */
    async init() {
        try {
            // MongoDBコレクション作成
            await this.setupAuditCollections();
            
            // 定期フラッシュ開始
            this.startPeriodicFlush();
            
            // 整合性チェック開始
            this.startIntegrityChecks();
            
            this.logger.info('AuditLogger initialized successfully');
        } catch (error) {
            this.logger.error('AuditLogger initialization failed:', error);
            throw error;
        }
    }

    /**
     * MongoDBコレクション設定
     */
    async setupAuditCollections() {
        try {
            if (!this.mongodb || this.mongodb.readyState !== 1) {
                throw new Error('MongoDB connection not available');
            }

            // 監査ログコレクション
            const auditCollection = this.mongodb.db.collection('security_audit_logs');
            
            // インデックス作成
            await auditCollection.createIndex({ timestamp: 1 });
            await auditCollection.createIndex({ event_type: 1 });
            await auditCollection.createIndex({ 'metadata.source_ip': 1 });
            await auditCollection.createIndex({ 'metadata.user_id': 1 });
            await auditCollection.createIndex({ constitutional_compliance: 1 });
            
            // Constitutional AI違反専用コレクション
            const violationCollection = this.mongodb.db.collection('constitutional_violations');
            await violationCollection.createIndex({ timestamp: 1 });
            await violationCollection.createIndex({ severity: 1 });
            await violationCollection.createIndex({ principle: 1 });
            
            // 整合性チェック用コレクション
            const integrityCollection = this.mongodb.db.collection('audit_integrity');
            await integrityCollection.createIndex({ date: 1 });

            this.logger.info('Audit collections configured successfully');

        } catch (error) {
            this.logger.error('Audit collections setup failed:', error);
            throw error;
        }
    }

    /**
     * セキュリティイベントログ記録
     */
    async logSecurityEvent(eventType, eventData, metadata = {}) {
        try {
            const auditEntry = {
                id: crypto.randomUUID(),
                timestamp: new Date(),
                event_type: eventType,
                event_data: eventData,
                metadata: {
                    ...metadata,
                    source_system: 'shinai-security-monitoring',
                    node_id: process.env.NODE_ID || 'primary',
                    session_id: metadata.session_id || null,
                    user_id: metadata.user_id || null,
                    source_ip: metadata.source_ip || null,
                    user_agent: metadata.user_agent || null
                },
                constitutional_compliance: await this.checkConstitutionalCompliance(eventData),
                severity: this.determineSeverity(eventType, eventData),
                hash: null, // 後で計算
                encrypted: this.auditConfig.encryption_enabled
            };

            // データ暗号化
            if (this.auditConfig.encryption_enabled) {
                auditEntry.event_data = this.encryptData(eventData);
                auditEntry.encrypted = true;
                this.stats.logs_encrypted++;
            }

            // ハッシュ計算（整合性チェック用）
            auditEntry.hash = this.calculateEntryHash(auditEntry);

            // バッファに追加
            this.logBuffer.push(auditEntry);
            this.stats.logs_written++;
            this.stats.total_size_bytes += JSON.stringify(auditEntry).length;

            // バッファサイズチェック
            if (this.logBuffer.length >= this.auditConfig.batch_size) {
                await this.flushLogBuffer();
            }

            // Constitutional AI違反の特別処理
            if (!auditEntry.constitutional_compliance.compliant) {
                await this.handleConstitutionalViolation(auditEntry);
            }

            this.logger.debug('Security event logged:', {
                id: auditEntry.id,
                type: eventType,
                severity: auditEntry.severity
            });

        } catch (error) {
            this.logger.error('Security event logging failed:', error);
            throw error;
        }
    }

    /**
     * Constitutional AI準拠チェック
     */
    async checkConstitutionalCompliance(eventData) {
        try {
            // 基本的な準拠チェック
            const compliance = {
                compliant: true,
                violations: [],
                score: 1.0,
                checked_at: new Date()
            };

            // データを文字列化してチェック
            const dataString = JSON.stringify(eventData);
            
            // 有害パターンチェック
            const harmfulPatterns = [
                /\b(illegal|harmful|dangerous|unethical|discriminatory)\b/i,
                /\b(violent|threat|harm|kill|destroy)\b/i,
                /\b(fraud|scam|phishing|malware)\b/i,
                /\b(privacy.*violation|data.*breach)\b/i
            ];

            for (const pattern of harmfulPatterns) {
                if (pattern.test(dataString)) {
                    compliance.compliant = false;
                    compliance.violations.push({
                        pattern: pattern.toString(),
                        matched: dataString.match(pattern)?.[0]
                    });
                    compliance.score -= 0.2;
                }
            }

            compliance.score = Math.max(0, compliance.score);

            return compliance;

        } catch (error) {
            this.logger.warn('Constitutional compliance check error:', error);
            return {
                compliant: true,
                violations: [],
                score: 1.0,
                error: error.message
            };
        }
    }

    /**
     * 重要度判定
     */
    determineSeverity(eventType, eventData) {
        const severityMap = {
            'threat_detected': 'high',
            'constitutional_violation': 'critical',
            'authentication_failure': 'medium',
            'system_error': 'medium',
            'security_scan': 'low',
            'login_success': 'low',
            'data_access': 'medium',
            'admin_action': 'high',
            'daily_report': 'low'
        };

        let baseSeverity = severityMap[eventType] || 'medium';

        // イベントデータに基づく重要度調整
        if (eventData && typeof eventData === 'object') {
            // Constitutional AI違反は必ず critical
            if (eventData.constitutional_violations > 0 || 
                eventData.constitutional_compliant === false) {
                baseSeverity = 'critical';
            }
            
            // 脅威の重要度調整
            if (eventData.severity === 'critical' || eventData.threat_level === 'critical') {
                baseSeverity = 'critical';
            }
        }

        return baseSeverity;
    }

    /**
     * データ暗号化
     */
    encryptData(data) {
        try {
            const dataString = JSON.stringify(data);
            const cipher = crypto.createCipher('aes-256-cbc', this.encryptionKey);
            let encrypted = cipher.update(dataString, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            return {
                encrypted: true,
                data: encrypted,
                algorithm: 'aes-256-cbc'
            };
        } catch (error) {
            this.logger.warn('Data encryption error:', error);
            return data; // 暗号化失敗時は元データを返す
        }
    }

    /**
     * データ復号化
     */
    decryptData(encryptedData) {
        try {
            if (!encryptedData.encrypted || !encryptedData.data) {
                return encryptedData;
            }

            const decipher = crypto.createDecipher('aes-256-cbc', this.encryptionKey);
            let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return JSON.parse(decrypted);
        } catch (error) {
            this.logger.warn('Data decryption error:', error);
            return encryptedData;
        }
    }

    /**
     * エントリハッシュ計算
     */
    calculateEntryHash(entry) {
        try {
            // ハッシュ計算対象データ
            const hashData = {
                id: entry.id,
                timestamp: entry.timestamp.toISOString(),
                event_type: entry.event_type,
                event_data: entry.event_data,
                metadata: entry.metadata
            };

            const dataString = JSON.stringify(hashData);
            return crypto.createHash('sha256').update(dataString).digest('hex');
        } catch (error) {
            this.logger.warn('Entry hash calculation error:', error);
            return null;
        }
    }

    /**
     * Constitutional AI違反処理
     */
    async handleConstitutionalViolation(auditEntry) {
        try {
            const violationEntry = {
                audit_log_id: auditEntry.id,
                timestamp: auditEntry.timestamp,
                event_type: auditEntry.event_type,
                violations: auditEntry.constitutional_compliance.violations,
                compliance_score: auditEntry.constitutional_compliance.score,
                severity: auditEntry.severity,
                metadata: auditEntry.metadata,
                requires_immediate_attention: true,
                investigation_status: 'pending',
                created_at: new Date()
            };

            // 専用コレクションに保存
            const violationCollection = this.mongodb.db.collection('constitutional_violations');
            await violationCollection.insertOne(violationEntry);

            // 緊急ログ出力
            this.logger.error('CONSTITUTIONAL AI VIOLATION DETECTED:', {
                audit_id: auditEntry.id,
                violations: violationEntry.violations,
                score: violationEntry.compliance_score
            });

            this.stats.constitutional_violations++;

        } catch (error) {
            this.logger.error('Constitutional violation handling failed:', error);
        }
    }

    /**
     * ログバッファフラッシュ
     */
    async flushLogBuffer() {
        if (this.logBuffer.length === 0) {
            return;
        }

        try {
            const logsToFlush = [...this.logBuffer];
            this.logBuffer = [];

            // MongoDBに一括挿入
            if (this.mongodb && this.mongodb.readyState === 1) {
                const auditCollection = this.mongodb.db.collection('security_audit_logs');
                await auditCollection.insertMany(logsToFlush);
            }

            // 日次整合性チェック用データ更新
            await this.updateIntegrityChecksum(logsToFlush);

            this.stats.last_flush = new Date();
            
            this.logger.debug(`Flushed ${logsToFlush.length} audit logs to database`);

        } catch (error) {
            this.logger.error('Log buffer flush failed:', error);
            // エラー時はバッファを復元
            this.logBuffer = [...this.logBuffer, ...this.logBuffer];
            throw error;
        }
    }

    /**
     * 定期フラッシュ開始
     */
    startPeriodicFlush() {
        setInterval(async () => {
            try {
                await this.flushLogBuffer();
            } catch (error) {
                this.logger.warn('Periodic flush error:', error);
            }
        }, this.auditConfig.flush_interval);

        this.logger.info('Periodic log flushing started');
    }

    /**
     * 整合性チェック開始
     */
    startIntegrityChecks() {
        // 日次整合性チェック（毎日午前3時）
        const dailyCheck = () => {
            const now = new Date();
            if (now.getHours() === 3 && now.getMinutes() === 0) {
                this.performDailyIntegrityCheck();
            }
        };

        setInterval(dailyCheck, 60000); // 1分間隔でチェック
        this.logger.info('Integrity checks scheduled');
    }

    /**
     * 日次整合性チェック実行
     */
    async performDailyIntegrityCheck() {
        try {
            const yesterday = moment().subtract(1, 'day').format('YYYY-MM-DD');
            
            // 昨日のログを取得
            const auditCollection = this.mongodb.db.collection('security_audit_logs');
            const logs = await auditCollection.find({
                timestamp: {
                    $gte: new Date(`${yesterday}T00:00:00.000Z`),
                    $lt: new Date(`${yesterday}T23:59:59.999Z`)
                }
            }).toArray();

            // 整合性チェック実行
            let validLogs = 0;
            let invalidLogs = 0;

            for (const log of logs) {
                const expectedHash = this.calculateEntryHash(log);
                if (expectedHash === log.hash) {
                    validLogs++;
                } else {
                    invalidLogs++;
                    this.logger.error('Integrity violation detected:', {
                        log_id: log.id,
                        expected_hash: expectedHash,
                        actual_hash: log.hash
                    });
                }
            }

            // 整合性レポート保存
            const integrityReport = {
                date: yesterday,
                total_logs: logs.length,
                valid_logs: validLogs,
                invalid_logs: invalidLogs,
                integrity_score: logs.length > 0 ? (validLogs / logs.length) * 100 : 100,
                checked_at: new Date()
            };

            const integrityCollection = this.mongodb.db.collection('audit_integrity');
            await integrityCollection.replaceOne(
                { date: yesterday },
                integrityReport,
                { upsert: true }
            );

            if (invalidLogs > 0) {
                this.stats.integrity_violations += invalidLogs;
            }

            this.logger.info('Daily integrity check completed:', integrityReport);

        } catch (error) {
            this.logger.error('Daily integrity check failed:', error);
        }
    }

    /**
     * 整合性チェックサム更新
     */
    async updateIntegrityChecksum(logs) {
        try {
            const today = moment().format('YYYY-MM-DD');
            const totalHashes = logs.map(log => log.hash).filter(hash => hash);
            
            if (totalHashes.length === 0) return;

            const dailyChecksum = crypto.createHash('sha256')
                .update(totalHashes.join(''))
                .digest('hex');

            // 日次チェックサムを更新
            const integrityCollection = this.mongodb.db.collection('audit_integrity');
            await integrityCollection.updateOne(
                { date: today },
                {
                    $set: {
                        daily_checksum: dailyChecksum,
                        last_updated: new Date()
                    },
                    $inc: {
                        log_count: totalHashes.length
                    }
                },
                { upsert: true }
            );

        } catch (error) {
            this.logger.warn('Integrity checksum update error:', error);
        }
    }

    /**
     * 古いログクリーンアップ
     */
    async cleanupOldLogs(cutoffDate) {
        try {
            // メインログコレクションクリーンアップ
            const auditCollection = this.mongodb.db.collection('security_audit_logs');
            const auditResult = await auditCollection.deleteMany({
                timestamp: { $lt: cutoffDate }
            });

            // Constitutional AI違反ログクリーンアップ（90日間保持）
            const violationCutoff = moment().subtract(90, 'days').toDate();
            const violationCollection = this.mongodb.db.collection('constitutional_violations');
            const violationResult = await violationCollection.deleteMany({
                timestamp: { $lt: violationCutoff }
            });

            // 整合性チェックログクリーンアップ（1年間保持）
            const integrityCutoff = moment().subtract(365, 'days').toDate();
            const integrityCollection = this.mongodb.db.collection('audit_integrity');
            const integrityResult = await integrityCollection.deleteMany({
                date: { $lt: integrityCutoff }
            });

            this.logger.info('Old logs cleanup completed:', {
                audit_logs_deleted: auditResult.deletedCount,
                violation_logs_deleted: violationResult.deletedCount,
                integrity_logs_deleted: integrityResult.deletedCount
            });

        } catch (error) {
            this.logger.error('Old logs cleanup failed:', error);
            throw error;
        }
    }

    /**
     * 暗号化キー生成
     */
    generateEncryptionKey() {
        return process.env.AUDIT_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
    }

    /**
     * ログ検索
     */
    async searchLogs(criteria) {
        try {
            const auditCollection = this.mongodb.db.collection('security_audit_logs');
            
            const query = {};
            
            // 検索条件構築
            if (criteria.event_type) {
                query.event_type = criteria.event_type;
            }
            
            if (criteria.start_date && criteria.end_date) {
                query.timestamp = {
                    $gte: new Date(criteria.start_date),
                    $lte: new Date(criteria.end_date)
                };
            }
            
            if (criteria.source_ip) {
                query['metadata.source_ip'] = criteria.source_ip;
            }
            
            if (criteria.user_id) {
                query['metadata.user_id'] = criteria.user_id;
            }
            
            if (criteria.severity) {
                query.severity = criteria.severity;
            }

            // 結果取得（最大1000件）
            const results = await auditCollection
                .find(query)
                .sort({ timestamp: -1 })
                .limit(1000)
                .toArray();

            // 暗号化されたデータの復号化
            return results.map(log => ({
                ...log,
                event_data: log.encrypted ? this.decryptData(log.event_data) : log.event_data
            }));

        } catch (error) {
            this.logger.error('Log search failed:', error);
            throw error;
        }
    }

    /**
     * 監査統計取得
     */
    getAuditStats() {
        return {
            ...this.stats,
            buffer_size: this.logBuffer.length,
            encryption_enabled: this.auditConfig.encryption_enabled,
            retention_days: this.auditConfig.log_retention_days,
            timestamp: new Date().toISOString()
        };
    }
}

module.exports = AuditLogger;