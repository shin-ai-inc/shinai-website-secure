/**
 * Constitutional AI準拠チェッカー
 * 完全Constitutional AI準拠監視・違反検知システム
 * masa様開発ルール完全遵守・99.98%準拠目標
 */
const crypto = require('crypto');
const moment = require('moment');

class ComplianceChecker {
    constructor(options = {}) {
        this.logger = options.logger;
        this.redis = options.redis;
        
        // Constitutional AI原則定義
        this.constitutionalPrinciples = {
            human_dignity: {
                weight: 1.0,
                patterns: [
                    /\b(dehumaniz|degrading|humiliat|objectif)/i,
                    /\b(treat.*like.*object|reduce.*to.*tool)/i,
                    /\b(disposable|worthless|subhuman)/i
                ],
                description: "人間の尊厳の保護"
            },
            individual_freedom: {
                weight: 0.9,
                patterns: [
                    /\b(coerce|force|manipulat|deceive)/i,
                    /\b(restrict.*freedom|control.*thought)/i,
                    /\b(brainwash|indoctrinat)/i
                ],
                description: "個人の自由の尊重"
            },
            equality_fairness: {
                weight: 0.95,
                patterns: [
                    /\b(discriminat|bias|prejudice|unfair)/i,
                    /\b(racist|sexist|ageist|homophobic)/i,
                    /\b(superior.*inferior|better.*worse.*race)/i
                ],
                description: "平等性と公平性"
            },
            justice_rule_of_law: {
                weight: 0.9,
                patterns: [
                    /\b(illegal|unlawful|criminal|illicit)/i,
                    /\b(violate.*law|break.*regulation)/i,
                    /\b(corruption|bribery|fraud)/i
                ],
                description: "正義と法の支配"
            },
            democratic_participation: {
                weight: 0.8,
                patterns: [
                    /\b(suppress.*vote|election.*fraud)/i,
                    /\b(authoritari|totalitari|dictator)/i,
                    /\b(silence.*opposition|censor.*dissent)/i
                ],
                description: "民主的参加"
            },
            accountability_transparency: {
                weight: 0.95,
                patterns: [
                    /\b(hide.*truth|conceal.*fact|cover.*up)/i,
                    /\b(deception|mislead|false.*information)/i,
                    /\b(secret.*agenda|hidden.*motive)/i
                ],
                description: "説明責任と透明性"
            },
            beneficence_non_maleficence: {
                weight: 1.0,
                patterns: [
                    /\b(harm|hurt|damage|destroy|kill)/i,
                    /\b(violence|attack|assault|abuse)/i,
                    /\b(poison|weapon|explosive|dangerous)/i
                ],
                description: "善行と無害性"
            },
            privacy_protection: {
                weight: 0.95,
                patterns: [
                    /\b(steal.*data|breach.*privacy|expose.*personal)/i,
                    /\b(surveillance|spy|monitor.*private)/i,
                    /\b(identity.*theft|personal.*information.*leak)/i
                ],
                description: "プライバシー保護"
            },
            truthfulness_honesty: {
                weight: 0.9,
                patterns: [
                    /\b(lie|false|fake|misinformation)/i,
                    /\b(propaganda|manipulation|deception)/i,
                    /\b(conspiracy.*theory|alternative.*fact)/i
                ],
                description: "真実性と誠実性"
            },
            sustainability: {
                weight: 0.8,
                patterns: [
                    /\b(environmental.*destruction|pollution)/i,
                    /\b(waste.*resource|unsustainable)/i,
                    /\b(climate.*denial|ecological.*damage)/i
                ],
                description: "持続可能性"
            }
        };
        
        // 統計情報
        this.stats = {
            checks_performed: 0,
            violations_detected: 0,
            compliance_score: 0.0,
            last_updated: new Date()
        };
        
        this.init();
    }

    /**
     * Constitutional AI準拠チェッカー初期化
     */
    async init() {
        try {
            // コンプライアンス履歴ロード
            await this.loadComplianceHistory();
            
            this.logger.info('ComplianceChecker initialized successfully');
        } catch (error) {
            this.logger.error('ComplianceChecker initialization failed:', error);
            throw error;
        }
    }

    /**
     * コンプライアンスチェック実行
     */
    async checkCompliance(data) {
        try {
            this.stats.checks_performed++;
            
            const result = {
                compliant: true,
                violations: [],
                score: 1.0,
                principles_checked: Object.keys(this.constitutionalPrinciples),
                timestamp: new Date(),
                metadata: {}
            };

            // 入力データの文字列化
            const content = typeof data === 'string' ? data : JSON.stringify(data);
            
            // 各Constitutional AI原則に対してチェック実行
            for (const [principle, config] of Object.entries(this.constitutionalPrinciples)) {
                const violationCheck = await this.checkPrincipleViolation(
                    principle, 
                    config, 
                    content
                );
                
                if (violationCheck.violated) {
                    result.compliant = false;
                    result.violations.push({
                        principle: principle,
                        description: config.description,
                        severity: violationCheck.severity,
                        confidence: violationCheck.confidence,
                        matched_patterns: violationCheck.matched_patterns,
                        context: violationCheck.context
                    });
                    
                    // スコア減算（重要度加重）
                    result.score -= (config.weight * violationCheck.confidence);
                }
            }

            // スコア正規化
            result.score = Math.max(0, Math.min(1, result.score));
            
            // 違反統計更新
            if (!result.compliant) {
                this.stats.violations_detected++;
                
                // 違反をRedisに記録
                await this.recordViolation(result);
            }
            
            // 全体コンプライアンススコア更新
            this.updateComplianceScore(result.score);
            
            this.logger.info('Compliance check completed:', {
                compliant: result.compliant,
                score: result.score,
                violations: result.violations.length
            });

            return result;

        } catch (error) {
            this.logger.error('Compliance check failed:', error);
            throw error;
        }
    }

    /**
     * イベントコンプライアンスチェック
     */
    async checkEventCompliance(eventData) {
        try {
            // イベントデータから関連コンテンツ抽出
            const contents = [
                eventData.data ? JSON.stringify(eventData.data) : '',
                eventData.source?.userAgent || '',
                eventData.source?.referer || '',
                eventData.metadata ? JSON.stringify(eventData.metadata) : ''
            ].filter(content => content.length > 0);

            const combinedContent = contents.join(' ');
            
            const result = await this.checkCompliance(combinedContent);
            
            // イベント固有のメタデータ追加
            result.metadata = {
                ...result.metadata,
                event_type: eventData.type,
                source_ip: eventData.source?.ip,
                timestamp: eventData.timestamp,
                event_id: eventData.id
            };

            return result;

        } catch (error) {
            this.logger.error('Event compliance check failed:', error);
            throw error;
        }
    }

    /**
     * 原則違反チェック
     */
    async checkPrincipleViolation(principle, config, content) {
        try {
            const violation = {
                violated: false,
                severity: 'low',
                confidence: 0.0,
                matched_patterns: [],
                context: []
            };

            // パターンマッチング実行
            for (const pattern of config.patterns) {
                const matches = content.match(pattern);
                if (matches) {
                    violation.violated = true;
                    violation.matched_patterns.push({
                        pattern: pattern.toString(),
                        matches: matches
                    });
                    
                    // マッチしたコンテキスト抽出
                    const contextStart = Math.max(0, content.indexOf(matches[0]) - 50);
                    const contextEnd = Math.min(content.length, content.indexOf(matches[0]) + matches[0].length + 50);
                    violation.context.push(content.substring(contextStart, contextEnd));
                    
                    // 信頼度計算
                    violation.confidence += 0.3; // ベース信頼度
                    
                    // パターン固有の信頼度調整
                    if (pattern.source.includes('\\b')) { // 単語境界あり
                        violation.confidence += 0.2;
                    }
                    
                    if (matches[0].length > 10) { // 長いマッチ
                        violation.confidence += 0.1;
                    }
                }
            }

            // 信頼度正規化
            violation.confidence = Math.min(1.0, violation.confidence);
            
            // 重要度判定
            if (violation.confidence > 0.8) {
                violation.severity = 'critical';
            } else if (violation.confidence > 0.6) {
                violation.severity = 'high';
            } else if (violation.confidence > 0.4) {
                violation.severity = 'medium';
            }

            // 特定原則の重要度調整
            if (['human_dignity', 'beneficence_non_maleficence'].includes(principle)) {
                if (violation.violated) {
                    violation.severity = 'critical';
                    violation.confidence = Math.max(0.8, violation.confidence);
                }
            }

            return violation;

        } catch (error) {
            this.logger.warn(`Principle violation check error for ${principle}:`, error);
            return { violated: false, severity: 'low', confidence: 0.0, matched_patterns: [], context: [] };
        }
    }

    /**
     * コンプライアンススキャン実行
     */
    async performComplianceScan() {
        try {
            const scanResult = {
                timestamp: new Date(),
                overall_compliance: 0.0,
                principle_scores: {},
                recommendations: [],
                risk_level: 'low'
            };

            // 各原則の履歴スコア取得
            for (const principle of Object.keys(this.constitutionalPrinciples)) {
                const score = await this.getPrincipleHistoryScore(principle);
                scanResult.principle_scores[principle] = score;
            }

            // 全体コンプライアンススコア計算
            const scores = Object.values(scanResult.principle_scores);
            scanResult.overall_compliance = scores.length > 0 
                ? scores.reduce((a, b) => a + b, 0) / scores.length 
                : 1.0;

            // リスクレベル判定
            if (scanResult.overall_compliance < 0.7) {
                scanResult.risk_level = 'high';
            } else if (scanResult.overall_compliance < 0.85) {
                scanResult.risk_level = 'medium';
            }

            // 改善推奨事項生成
            scanResult.recommendations = await this.generateRecommendations(scanResult);

            this.logger.info('Compliance scan completed:', {
                overall_compliance: scanResult.overall_compliance,
                risk_level: scanResult.risk_level
            });

            return scanResult;

        } catch (error) {
            this.logger.error('Compliance scan failed:', error);
            throw error;
        }
    }

    /**
     * 違反記録
     */
    async recordViolation(result) {
        try {
            const key = `compliance:violation:${Date.now()}`;
            const violationData = {
                ...result,
                recorded_at: new Date().toISOString()
            };
            
            // 24時間保存
            await this.redis.setEx(key, 86400, JSON.stringify(violationData));
            
            // 違反統計更新
            const statsKey = 'compliance:stats:daily';
            const currentStats = await this.redis.get(statsKey);
            const stats = currentStats ? JSON.parse(currentStats) : {
                date: moment().format('YYYY-MM-DD'),
                total_violations: 0,
                principle_violations: {}
            };
            
            stats.total_violations++;
            
            result.violations.forEach(violation => {
                stats.principle_violations[violation.principle] = 
                    (stats.principle_violations[violation.principle] || 0) + 1;
            });
            
            await this.redis.setEx(statsKey, 86400, JSON.stringify(stats));

        } catch (error) {
            this.logger.warn('Violation recording error:', error);
        }
    }

    /**
     * コンプライアンススコア更新
     */
    updateComplianceScore(newScore) {
        try {
            // 移動平均でスコア更新
            const alpha = 0.1; // 平滑化係数
            this.stats.compliance_score = 
                (alpha * newScore) + ((1 - alpha) * this.stats.compliance_score);
            
            this.stats.last_updated = new Date();

        } catch (error) {
            this.logger.warn('Compliance score update error:', error);
        }
    }

    /**
     * 原則履歴スコア取得
     */
    async getPrincipleHistoryScore(principle) {
        try {
            const key = `compliance:principle:${principle}:score`;
            const score = await this.redis.get(key);
            return score ? parseFloat(score) : 1.0;
            
        } catch (error) {
            this.logger.warn(`Principle history score error for ${principle}:`, error);
            return 1.0;
        }
    }

    /**
     * 改善推奨事項生成
     */
    async generateRecommendations(scanResult) {
        try {
            const recommendations = [];
            
            // 低スコア原則の推奨事項
            for (const [principle, score] of Object.entries(scanResult.principle_scores)) {
                if (score < 0.8) {
                    const config = this.constitutionalPrinciples[principle];
                    recommendations.push({
                        type: 'principle_improvement',
                        principle: principle,
                        description: `${config.description}の準拠強化が必要`,
                        current_score: score,
                        target_score: 0.95,
                        priority: score < 0.6 ? 'high' : 'medium'
                    });
                }
            }
            
            // 全体的推奨事項
            if (scanResult.overall_compliance < 0.8) {
                recommendations.push({
                    type: 'overall_improvement',
                    description: 'Constitutional AI準拠の全体的改善が必要',
                    current_score: scanResult.overall_compliance,
                    target_score: 0.95,
                    priority: 'high'
                });
            }
            
            return recommendations;

        } catch (error) {
            this.logger.warn('Recommendations generation error:', error);
            return [];
        }
    }

    /**
     * コンプライアンス履歴ロード
     */
    async loadComplianceHistory() {
        try {
            const statsKey = 'compliance:stats:overall';
            const stats = await this.redis.get(statsKey);
            
            if (stats) {
                const parsedStats = JSON.parse(stats);
                this.stats = { ...this.stats, ...parsedStats };
            }
            
            this.logger.info('Compliance history loaded');

        } catch (error) {
            this.logger.warn('Compliance history loading error:', error);
        }
    }

    /**
     * 日次コンプライアンスサマリー取得
     */
    async getDailyComplianceSummary() {
        try {
            const today = moment().format('YYYY-MM-DD');
            const statsKey = 'compliance:stats:daily';
            const stats = await this.redis.get(statsKey);
            
            if (stats) {
                return JSON.parse(stats);
            }
            
            return {
                date: today,
                total_violations: 0,
                principle_violations: {},
                overall_compliance_score: this.stats.compliance_score
            };

        } catch (error) {
            this.logger.warn('Daily compliance summary error:', error);
            return {
                date: moment().format('YYYY-MM-DD'),
                total_violations: 0,
                principle_violations: {},
                overall_compliance_score: 0.0
            };
        }
    }

    /**
     * コンプライアンス統計取得
     */
    getComplianceStats() {
        return {
            ...this.stats,
            principles_count: Object.keys(this.constitutionalPrinciples).length,
            timestamp: new Date().toISOString()
        };
    }
}

module.exports = ComplianceChecker;