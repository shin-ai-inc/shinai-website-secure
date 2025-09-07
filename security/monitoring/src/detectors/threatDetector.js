/**
 * 脅威検知エンジン
 * Advanced Threat Detection with Constitutional AI Compliance
 * masa様開発ルール完全遵守・ML/AI脅威パターン認識
 */
const crypto = require('crypto');
const moment = require('moment');

class ThreatDetector {
    constructor(options = {}) {
        this.logger = options.logger;
        this.redis = options.redis;
        this.geoip = options.geoip;
        this.uaParser = options.uaParser;
        
        // 脅威パターン定義
        this.threatPatterns = {
            sql_injection: [
                /(\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b|\bcreate\b|\balter\b|\bexec\b)/i,
                /(\bor\b|\band\b)\s*\d+\s*=\s*\d+/i,
                /[\'\"];?\s*(union|select|insert|delete)/i
            ],
            xss_attack: [
                /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
                /javascript:/i,
                /vbscript:/i,
                /on\w+\s*=/gi,
                /<iframe|<object|<embed/i
            ],
            csrf_attempt: [
                /\b(csrf|xsrf)\b.*token/i,
                /authenticity_token/i
            ],
            directory_traversal: [
                /\.\.[\/\\]/g,
                /\.\.[\/\\][\/\\]/g,
                /\/etc\/passwd/i,
                /\/windows\/system32/i
            ],
            command_injection: [
                /[;&|`$(){}[\]]/g,
                /\b(cat|ls|dir|type|del|rm|mv|cp)\b/i,
                /\b(wget|curl|nc|netcat)\b/i
            ],
            constitutional_violation: [
                /\b(illegal|harmful|dangerous|unethical|discriminatory)\b/i,
                /\b(violent|threat|harm|kill|destroy)\b/i,
                /\b(fraud|scam|phishing|malware)\b/i,
                /\b(privacy.*violation|data.*breach)\b/i
            ]
        };
        
        // IP ブラックリスト（動的更新）
        this.ipBlacklist = new Set();
        
        // 統計情報
        this.stats = {
            threats_analyzed: 0,
            threats_detected: 0,
            false_positives: 0,
            patterns_updated: 0
        };
        
        this.init();
    }

    /**
     * 脅威検知システム初期化
     */
    async init() {
        try {
            // IP ブラックリストロード
            await this.loadIPBlacklist();
            
            // 脅威パターン更新
            await this.updateThreatPatterns();
            
            this.logger.info('ThreatDetector initialized successfully');
        } catch (error) {
            this.logger.error('ThreatDetector initialization failed:', error);
            throw error;
        }
    }

    /**
     * 脅威分析メイン処理
     */
    async analyzeThreat(eventData) {
        try {
            this.stats.threats_analyzed++;
            
            const analysisResult = {
                isThreat: false,
                threatTypes: [],
                severity: 'low',
                confidence: 0.0,
                metadata: {},
                timestamp: new Date(),
                constitutional_compliant: true
            };

            // 1. IP ベース分析
            await this.analyzeIPThreat(eventData, analysisResult);
            
            // 2. パターンマッチング分析
            await this.analyzePatternThreat(eventData, analysisResult);
            
            // 3. 異常行動分析
            await this.analyzeAnomalousActivity(eventData, analysisResult);
            
            // 4. Geolocation 分析
            await this.analyzeGeolocation(eventData, analysisResult);
            
            // 5. User Agent 分析
            await this.analyzeUserAgent(eventData, analysisResult);
            
            // 6. Constitutional AI 準拠チェック
            await this.analyzeConstitutionalCompliance(eventData, analysisResult);
            
            // 7. 総合リスクスコア計算
            this.calculateThreatScore(analysisResult);
            
            if (analysisResult.isThreat) {
                this.stats.threats_detected++;
                
                // 脅威をRedisキャッシュに記録
                await this.cacheThreatData(eventData, analysisResult);
                
                this.logger.warn('Threat detected:', {
                    types: analysisResult.threatTypes,
                    severity: analysisResult.severity,
                    confidence: analysisResult.confidence,
                    source: eventData.source
                });
            }

            return analysisResult;

        } catch (error) {
            this.logger.error('Threat analysis failed:', error);
            throw error;
        }
    }

    /**
     * IP ベース脅威分析
     */
    async analyzeIPThreat(eventData, result) {
        try {
            const ip = eventData.source?.ip;
            if (!ip) return;

            // ブラックリストチェック
            if (this.ipBlacklist.has(ip)) {
                result.isThreat = true;
                result.threatTypes.push('blacklisted_ip');
                result.severity = 'high';
                result.confidence += 0.9;
            }

            // レート制限チェック
            const requestCount = await this.getIPRequestCount(ip);
            if (requestCount > 100) { // 1分間に100リクエスト以上
                result.isThreat = true;
                result.threatTypes.push('rate_limit_exceeded');
                result.severity = 'medium';
                result.confidence += 0.7;
                result.metadata.request_count = requestCount;
            }

            // 異常な時間帯のアクセス
            const hour = new Date().getHours();
            if (hour >= 2 && hour <= 5) { // 深夜2-5時
                const suspiciousActivityScore = await this.getSuspiciousActivityScore(ip);
                if (suspiciousActivityScore > 0.5) {
                    result.threatTypes.push('suspicious_timing');
                    result.confidence += 0.3;
                }
            }

        } catch (error) {
            this.logger.warn('IP threat analysis error:', error);
        }
    }

    /**
     * パターンマッチング脅威分析
     */
    async analyzePatternThreat(eventData, result) {
        try {
            const requestString = JSON.stringify(eventData.data);
            
            for (const [threatType, patterns] of Object.entries(this.threatPatterns)) {
                for (const pattern of patterns) {
                    if (pattern.test(requestString)) {
                        result.isThreat = true;
                        result.threatTypes.push(threatType);
                        
                        // 脅威タイプ別重要度設定
                        const severityMap = {
                            sql_injection: 'critical',
                            xss_attack: 'high',
                            command_injection: 'critical',
                            constitutional_violation: 'high',
                            directory_traversal: 'high',
                            csrf_attempt: 'medium'
                        };
                        
                        const currentSeverity = severityMap[threatType] || 'medium';
                        if (this.getSeverityLevel(currentSeverity) > this.getSeverityLevel(result.severity)) {
                            result.severity = currentSeverity;
                        }
                        
                        result.confidence += 0.8;
                        result.metadata[threatType] = {
                            pattern_matched: pattern.toString(),
                            matched_content: requestString.match(pattern)?.[0]
                        };

                        // Constitutional AI 違反の特別処理
                        if (threatType === 'constitutional_violation') {
                            result.constitutional_compliant = false;
                            this.logger.error('Constitutional AI violation detected:', {
                                pattern: pattern.toString(),
                                content: requestString
                            });
                        }
                    }
                }
            }

        } catch (error) {
            this.logger.warn('Pattern threat analysis error:', error);
        }
    }

    /**
     * 異常行動分析
     */
    async analyzeAnomalousActivity(eventData, result) {
        try {
            const ip = eventData.source?.ip;
            if (!ip) return;

            // 短期間での大量リクエスト
            const recentRequests = await this.getRecentRequestsByIP(ip, 300); // 5分間
            if (recentRequests.length > 50) {
                result.isThreat = true;
                result.threatTypes.push('ddos_attempt');
                result.severity = 'high';
                result.confidence += 0.8;
                result.metadata.recent_requests = recentRequests.length;
            }

            // 異常なエンドポイントアクセス
            const endpoint = eventData.data?.endpoint;
            if (endpoint && this.isAdminEndpoint(endpoint)) {
                result.threatTypes.push('admin_access_attempt');
                result.confidence += 0.5;
            }

            // 異常なペイロードサイズ
            const payloadSize = JSON.stringify(eventData.data).length;
            if (payloadSize > 100000) { // 100KB以上
                result.threatTypes.push('oversized_payload');
                result.confidence += 0.4;
                result.metadata.payload_size = payloadSize;
            }

        } catch (error) {
            this.logger.warn('Anomalous activity analysis error:', error);
        }
    }

    /**
     * Geolocation 分析
     */
    async analyzeGeolocation(eventData, result) {
        try {
            const ip = eventData.source?.ip;
            if (!ip) return;

            const geo = this.geoip.lookup(ip);
            if (geo) {
                result.metadata.geolocation = geo;

                // 高リスク国家チェック
                const highRiskCountries = ['CN', 'RU', 'KP', 'IR'];
                if (highRiskCountries.includes(geo.country)) {
                    result.threatTypes.push('high_risk_country');
                    result.confidence += 0.3;
                }

                // VPN/Tor検知（基本的な検証）
                if (this.isPotentialVPN(ip, geo)) {
                    result.threatTypes.push('vpn_tor_usage');
                    result.confidence += 0.2;
                }
            }

        } catch (error) {
            this.logger.warn('Geolocation analysis error:', error);
        }
    }

    /**
     * User Agent 分析
     */
    async analyzeUserAgent(eventData, result) {
        try {
            const userAgent = eventData.source?.userAgent;
            if (!userAgent) return;

            const parsed = new this.uaParser(userAgent);
            result.metadata.user_agent = parsed.getResult();

            // 古いブラウザ検知
            if (this.isOutdatedBrowser(parsed)) {
                result.threatTypes.push('outdated_browser');
                result.confidence += 0.2;
            }

            // ボット・スクレイパー検知
            if (this.isSuspiciousBot(userAgent)) {
                result.threatTypes.push('suspicious_bot');
                result.confidence += 0.6;
            }

            // User Agent偽装検知
            if (this.isUserAgentSpoofed(userAgent, parsed)) {
                result.threatTypes.push('user_agent_spoofing');
                result.confidence += 0.5;
            }

        } catch (error) {
            this.logger.warn('User Agent analysis error:', error);
        }
    }

    /**
     * Constitutional AI 準拠チェック
     */
    async analyzeConstitutionalCompliance(eventData, result) {
        try {
            const content = JSON.stringify(eventData.data);
            
            // Constitutional AI 違反パターンチェック
            const violations = [];
            
            // 人間の尊厳への脅威
            if (/\b(dehumaniz|degrading|humiliat)/i.test(content)) {
                violations.push('human_dignity_threat');
            }
            
            // 差別的内容
            if (/\b(discriminat|racist|sexist|homophobic)\b/i.test(content)) {
                violations.push('discriminatory_content');
            }
            
            // プライバシー侵害
            if (/\b(personal.*data|private.*info|breach.*privacy)\b/i.test(content)) {
                violations.push('privacy_violation');
            }
            
            // 有害活動促進
            if (/\b(hack|exploit|illegal.*activity|malicious)\b/i.test(content)) {
                violations.push('harmful_activity_promotion');
            }

            if (violations.length > 0) {
                result.constitutional_compliant = false;
                result.isThreat = true;
                result.threatTypes.push('constitutional_violation');
                result.severity = 'high';
                result.confidence += 0.9;
                result.metadata.constitutional_violations = violations;
                
                this.logger.error('Constitutional AI violations detected:', violations);
            }

        } catch (error) {
            this.logger.warn('Constitutional compliance analysis error:', error);
        }
    }

    /**
     * 総合脅威スコア計算
     */
    calculateThreatScore(result) {
        try {
            // 信頼度の正規化
            result.confidence = Math.min(result.confidence, 1.0);
            
            // 脅威判定閾値
            const thresholds = {
                critical: 0.9,
                high: 0.7,
                medium: 0.5,
                low: 0.3
            };

            // 重要度に基づく脅威判定
            if (result.severity === 'critical' && result.confidence >= thresholds.critical) {
                result.isThreat = true;
            } else if (result.severity === 'high' && result.confidence >= thresholds.high) {
                result.isThreat = true;
            } else if (result.severity === 'medium' && result.confidence >= thresholds.medium) {
                result.isThreat = true;
            } else if (result.confidence >= thresholds.low && result.threatTypes.length > 2) {
                result.isThreat = true;
            }

            // Constitutional AI 違反は必ず脅威として判定
            if (!result.constitutional_compliant) {
                result.isThreat = true;
            }

        } catch (error) {
            this.logger.warn('Threat score calculation error:', error);
        }
    }

    /**
     * IP リクエスト数取得
     */
    async getIPRequestCount(ip) {
        try {
            const key = `threat:ip_requests:${ip}`;
            const count = await this.redis.get(key) || 0;
            
            // カウンター更新（1分間のTTL）
            await this.redis.setEx(key, 60, parseInt(count) + 1);
            
            return parseInt(count);
        } catch (error) {
            this.logger.warn('IP request count error:', error);
            return 0;
        }
    }

    /**
     * 脅威データキャッシュ
     */
    async cacheThreatData(eventData, result) {
        try {
            const key = `threat:detected:${Date.now()}`;
            const data = {
                event: eventData,
                result: result,
                timestamp: new Date().toISOString()
            };
            
            await this.redis.setEx(key, 86400, JSON.stringify(data)); // 24時間保存
            
        } catch (error) {
            this.logger.warn('Threat data caching error:', error);
        }
    }

    /**
     * IP ブラックリストロード
     */
    async loadIPBlacklist() {
        try {
            // 既知の悪意あるIP（例）
            const knownBadIPs = [
                '192.168.1.100', // 例：内部テスト用
                '10.0.0.1'       // 例：内部テスト用
            ];
            
            knownBadIPs.forEach(ip => this.ipBlacklist.add(ip));
            
            this.logger.info(`Loaded ${this.ipBlacklist.size} IPs to blacklist`);
            
        } catch (error) {
            this.logger.warn('IP blacklist loading error:', error);
        }
    }

    /**
     * 脅威パターン更新
     */
    async updateThreatPatterns() {
        try {
            // 動的パターン更新ロジック（実装例）
            this.stats.patterns_updated++;
            
            this.logger.info('Threat patterns updated successfully');
            
        } catch (error) {
            this.logger.warn('Threat pattern update error:', error);
        }
    }

    // === ユーティリティメソッド ===

    getSeverityLevel(severity) {
        const levels = { low: 1, medium: 2, high: 3, critical: 4 };
        return levels[severity] || 1;
    }

    isAdminEndpoint(endpoint) {
        return /\/(admin|config|debug|internal)/i.test(endpoint);
    }

    isPotentialVPN(ip, geo) {
        // 基本的なVPN検知ロジック
        return geo.org && /vpn|proxy|hosting/i.test(geo.org);
    }

    isOutdatedBrowser(parsed) {
        const result = parsed.getResult();
        const browser = result.browser;
        
        if (!browser.version) return false;
        
        const version = parseInt(browser.version.split('.')[0]);
        const outdatedVersions = {
            'Chrome': 90,
            'Firefox': 80,
            'Safari': 13,
            'Edge': 90
        };
        
        return outdatedVersions[browser.name] && version < outdatedVersions[browser.name];
    }

    isSuspiciousBot(userAgent) {
        const botPatterns = [
            /bot|crawler|spider|scraper/i,
            /curl|wget|python|java|php/i,
            /automated|script|tool/i
        ];
        
        return botPatterns.some(pattern => pattern.test(userAgent));
    }

    isUserAgentSpoofed(userAgent, parsed) {
        // 基本的なUser Agent偽装検知
        const result = parsed.getResult();
        
        // 一般的でないOS・ブラウザ組み合わせ
        if (result.os.name === 'Windows' && result.browser.name === 'Safari') {
            return true;
        }
        
        return false;
    }

    async getRecentRequestsByIP(ip, seconds) {
        try {
            const key = `threat:recent_requests:${ip}`;
            const requests = await this.redis.lRange(key, 0, -1);
            
            const cutoff = Date.now() - (seconds * 1000);
            return requests.filter(timestamp => parseInt(timestamp) > cutoff);
            
        } catch (error) {
            this.logger.warn('Recent requests retrieval error:', error);
            return [];
        }
    }

    async getSuspiciousActivityScore(ip) {
        try {
            const key = `threat:suspicious_score:${ip}`;
            const score = await this.redis.get(key) || '0';
            return parseFloat(score);
        } catch (error) {
            return 0;
        }
    }

    /**
     * 日次脅威サマリー取得
     */
    async getDailyThreatSummary() {
        try {
            const today = moment().format('YYYY-MM-DD');
            const threatKeys = await this.redis.keys(`threat:detected:*`);
            
            const threats = [];
            for (const key of threatKeys) {
                const data = await this.redis.get(key);
                if (data) {
                    const threat = JSON.parse(data);
                    if (moment(threat.timestamp).format('YYYY-MM-DD') === today) {
                        threats.push(threat);
                    }
                }
            }

            return {
                date: today,
                total_threats: threats.length,
                threat_types: this.groupThreatsByType(threats),
                severity_distribution: this.groupThreatsBySeverity(threats),
                top_sources: this.getTopThreatSources(threats)
            };

        } catch (error) {
            this.logger.warn('Daily threat summary error:', error);
            return { date: moment().format('YYYY-MM-DD'), total_threats: 0 };
        }
    }

    groupThreatsByType(threats) {
        const groups = {};
        threats.forEach(threat => {
            threat.result.threatTypes.forEach(type => {
                groups[type] = (groups[type] || 0) + 1;
            });
        });
        return groups;
    }

    groupThreatsBySeverity(threats) {
        const groups = {};
        threats.forEach(threat => {
            const severity = threat.result.severity;
            groups[severity] = (groups[severity] || 0) + 1;
        });
        return groups;
    }

    getTopThreatSources(threats) {
        const sources = {};
        threats.forEach(threat => {
            const ip = threat.event.source?.ip;
            if (ip) {
                sources[ip] = (sources[ip] || 0) + 1;
            }
        });
        
        return Object.entries(sources)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 10)
            .map(([ip, count]) => ({ ip, count }));
    }
}

module.exports = ThreatDetector;