/**
 * サービスコントローラー
 * ビジネスロジックを安全に処理・Constitutional AI準拠
 * masa様開発ルール完全遵守・エラーハンドリング完全実装
 */
const Service = require('../models/Service');
const { encrypt, decrypt } = require('../utils/encryption');
const { validateInput, sanitizeInput } = require('../utils/validation');
const { logger } = require('../utils/logger');
const { createAuditLog } = require('../utils/auditLogger');
const { APIError } = require('../utils/errors');

class ServiceController {
    constructor() {
        this.cache = new Map();
        this.cacheTimeout = 5 * 60 * 1000; // 5分
        
        // サービスカテゴリ定義
        this.serviceCategories = {
            'ai-agent': 'AIエージェント開発',
            'rag': 'RAG構築サービス', 
            'aipro': 'アイプロ（企画書AI）',
            'consultation': '技術コンサルティング',
            'integration': 'システム統合'
        };
        
        // 価格設定基準
        this.pricingMatrix = {
            baseCost: 300000, // 基本30万円
            complexity: {
                simple: 1.0,
                medium: 1.5,
                complex: 2.5,
                enterprise: 4.0
            },
            timeline: {
                urgent: 1.3,     // 1週間以内
                fast: 1.1,       // 2週間
                standard: 1.0,   // 1ヶ月
                extended: 0.9    // 2ヶ月以上
            }
        };

        logger.info('ServiceController initialized');
    }

    /**
     * サービス一覧取得（公開情報）
     */
    async getServices(req, res, next) {
        try {
            const cacheKey = 'services:public';
            
            // キャッシュ確認
            const cached = this.getFromCache(cacheKey);
            if (cached) {
                return res.json({
                    success: true,
                    data: cached.data,
                    count: cached.data.length,
                    cached: true,
                    timestamp: cached.timestamp
                });
            }

            // データベースから取得
            const services = await Service.find({ 
                isActive: true,
                isPublic: true 
            })
            .select('name description features pricing category icon tags')
            .sort({ order: 1, createdAt: -1 })
            .lean();

            if (!services || services.length === 0) {
                logger.warn('No public services found');
                return res.status(404).json({
                    success: false,
                    error: 'No services available'
                });
            }

            // 公開用データ生成
            const publicServices = services.map(service => this.formatPublicService(service));

            // キャッシュに保存
            this.setCache(cacheKey, publicServices);

            // 監査ログ
            await createAuditLog({
                action: 'services_list_accessed',
                userId: req.user?.id || 'anonymous',
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                details: { count: publicServices.length }
            });

            res.json({
                success: true,
                data: publicServices,
                count: publicServices.length,
                categories: this.serviceCategories
            });

        } catch (error) {
            logger.error('Service listing failed:', {
                error: error.message,
                stack: error.stack,
                userId: req.user?.id
            });
            next(new APIError('Failed to fetch services', 500, 'SERVICE_FETCH_ERROR'));
        }
    }

    /**
     * サービス詳細取得
     */
    async getServiceDetails(req, res, next) {
        try {
            const { serviceId } = req.params;

            // 入力検証
            if (!validateInput.isValidServiceId(serviceId)) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid service ID format',
                    code: 'INVALID_SERVICE_ID'
                });
            }

            const cacheKey = `service:${serviceId}`;
            
            // キャッシュ確認
            const cached = this.getFromCache(cacheKey);
            if (cached) {
                await this.logServiceAccess(req, serviceId, 'cache_hit');
                return res.json({
                    success: true,
                    data: cached.data,
                    cached: true
                });
            }

            // データベースから取得
            const service = await this.findServiceById(serviceId);

            if (!service) {
                await this.logServiceAccess(req, serviceId, 'not_found');
                return res.status(404).json({
                    success: false,
                    error: 'Service not found',
                    code: 'SERVICE_NOT_FOUND'
                });
            }

            // 詳細データ構築
            const serviceDetails = await this.buildServiceDetails(service, req.user);

            // キャッシュに保存
            this.setCache(cacheKey, serviceDetails);

            // アクセスログ
            await this.logServiceAccess(req, serviceId, 'accessed');

            res.json({
                success: true,
                data: serviceDetails
            });

        } catch (error) {
            logger.error('Service details retrieval failed:', {
                serviceId: req.params.serviceId,
                error: error.message,
                userId: req.user?.id
            });
            next(new APIError('Failed to fetch service details', 500, 'SERVICE_DETAIL_ERROR'));
        }
    }

    /**
     * カスタム見積もり算出
     */
    async calculateEstimate(req, res, next) {
        try {
            const { requirements } = req.body;

            // 入力検証・サニタイズ
            const validationResult = await this.validateEstimateRequirements(requirements);
            if (!validationResult.isValid) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid requirements',
                    details: validationResult.errors,
                    code: 'INVALID_REQUIREMENTS'
                });
            }

            const sanitizedRequirements = sanitizeInput.deep(requirements);

            // Constitutional AI準拠チェック
            const complianceCheck = await this.validateConstitutionalCompliance(sanitizedRequirements);
            if (!complianceCheck.compliant) {
                logger.warn('Constitutional AI violation in estimate request', {
                    userId: req.user?.id,
                    violations: complianceCheck.violations
                });

                return res.status(400).json({
                    success: false,
                    error: 'Request does not meet our service standards',
                    code: 'COMPLIANCE_VIOLATION'
                });
            }

            // 見積もり算出実行
            const estimate = await this.performEstimateCalculation(
                sanitizedRequirements, 
                req.user
            );

            // 結果検証
            if (!estimate || !estimate.totalCost) {
                throw new Error('Estimate calculation failed');
            }

            // 見積もり保存
            await this.saveEstimate(estimate, req.user?.id, req.ip);

            // 監査ログ
            await createAuditLog({
                action: 'estimate_calculated',
                userId: req.user?.id || 'anonymous',
                ip: req.ip,
                details: {
                    estimateId: estimate.id,
                    totalCost: estimate.totalCost,
                    serviceType: sanitizedRequirements.serviceType
                }
            });

            res.json({
                success: true,
                data: {
                    estimateId: estimate.id,
                    totalCost: estimate.totalCost,
                    timeline: estimate.timeline,
                    breakdown: estimate.breakdown,
                    recommendations: estimate.recommendations,
                    validUntil: estimate.validUntil,
                    terms: estimate.terms
                }
            });

        } catch (error) {
            logger.error('Estimate calculation failed:', {
                error: error.message,
                userId: req.user?.id,
                requirements: req.body.requirements
            });
            next(new APIError('Failed to calculate estimate', 500, 'ESTIMATE_CALCULATION_ERROR'));
        }
    }

    /**
     * サービス検索
     */
    async searchServices(req, res, next) {
        try {
            const { query, category, priceRange, features } = req.query;

            // 検索パラメータ検証
            const searchParams = this.validateSearchParams({
                query, category, priceRange, features
            });

            if (!searchParams.isValid) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid search parameters',
                    details: searchParams.errors
                });
            }

            // 検索実行
            const searchResults = await this.performServiceSearch(searchParams.sanitized);

            // 検索ログ
            await createAuditLog({
                action: 'service_search',
                userId: req.user?.id || 'anonymous',
                ip: req.ip,
                details: {
                    query: searchParams.sanitized.query,
                    resultsCount: searchResults.length
                }
            });

            res.json({
                success: true,
                data: searchResults,
                count: searchResults.length,
                searchParams: searchParams.sanitized
            });

        } catch (error) {
            logger.error('Service search failed:', error);
            next(new APIError('Search failed', 500, 'SEARCH_ERROR'));
        }
    }

    /**
     * 見積もり要件検証
     */
    async validateEstimateRequirements(requirements) {
        const errors = [];

        // 必須フィールドチェック
        const requiredFields = ['serviceType', 'projectScale', 'timeline'];
        for (const field of requiredFields) {
            if (!requirements[field]) {
                errors.push(`${field} is required`);
            }
        }

        // サービスタイプ検証
        if (requirements.serviceType && !this.serviceCategories[requirements.serviceType]) {
            errors.push('Invalid service type');
        }

        // プロジェクト規模検証
        if (requirements.projectScale) {
            const validScales = ['small', 'medium', 'large', 'enterprise'];
            if (!validScales.includes(requirements.projectScale)) {
                errors.push('Invalid project scale');
            }
        }

        // タイムライン検証
        if (requirements.timeline && requirements.timeline < 7) {
            errors.push('Minimum timeline is 7 days');
        }

        // 予算検証
        if (requirements.budget && (requirements.budget < 100000 || requirements.budget > 10000000)) {
            errors.push('Budget must be between 100,000 and 10,000,000 yen');
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }

    /**
     * Constitutional AI準拠検証
     */
    async validateConstitutionalCompliance(requirements) {
        const violations = [];

        // 有害コンテンツ検知
        const harmfulPatterns = [
            /illegal|harmful|dangerous|unethical/i,
            /discrimination|bias|offensive/i,
            /privacy.*(violation|breach)/i,
            /misleading|deceptive|false/i
        ];

        const content = JSON.stringify(requirements);
        
        for (const pattern of harmfulPatterns) {
            if (pattern.test(content)) {
                violations.push(`Harmful pattern detected: ${pattern.toString()}`);
            }
        }

        // ポジティブ価値確認
        const positiveIndicators = [
            /improve|enhance|optimize|benefit|solution/i,
            /efficiency|productivity|innovation/i,
            /help|support|assist|facilitate/i
        ];

        const hasPositiveContent = positiveIndicators.some(pattern => pattern.test(content));

        if (!hasPositiveContent && requirements.description) {
            violations.push('Request should focus on positive value creation');
        }

        return {
            compliant: violations.length === 0,
            violations
        };
    }

    /**
     * 見積もり算出実行
     */
    async performEstimateCalculation(requirements, user = null) {
        try {
            const { serviceType, projectScale, timeline, features = [], budget } = requirements;

            // 基本コスト算出
            let baseCost = this.pricingMatrix.baseCost;

            // 複雑度調整
            const complexityMultiplier = this.pricingMatrix.complexity[projectScale] || 1.0;
            let totalCost = baseCost * complexityMultiplier;

            // タイムライン調整
            let timelineMultiplier = 1.0;
            if (timeline <= 7) {
                timelineMultiplier = this.pricingMatrix.timeline.urgent;
            } else if (timeline <= 14) {
                timelineMultiplier = this.pricingMatrix.timeline.fast;
            } else if (timeline <= 30) {
                timelineMultiplier = this.pricingMatrix.timeline.standard;
            } else {
                timelineMultiplier = this.pricingMatrix.timeline.extended;
            }

            totalCost *= timelineMultiplier;

            // サービス固有調整
            const serviceAdjustment = this.getServiceAdjustment(serviceType, features);
            totalCost += serviceAdjustment;

            // ユーザー特別価格（認証ユーザー）
            if (user && user.isPremium) {
                totalCost *= 0.9; // 10%割引
            }

            // 最終調整
            totalCost = Math.round(totalCost / 1000) * 1000; // 千円単位

            // 見積もりオブジェクト生成
            const estimate = {
                id: this.generateEstimateId(),
                totalCost,
                baseCost,
                adjustments: {
                    complexity: complexityMultiplier,
                    timeline: timelineMultiplier,
                    service: serviceAdjustment
                },
                timeline: this.calculateDeliveryTimeline(timeline, projectScale),
                breakdown: this.generateCostBreakdown(totalCost, requirements),
                recommendations: this.generateRecommendations(requirements, totalCost),
                terms: this.getEstimateTerms(),
                validUntil: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30日後
                createdAt: new Date(),
                requirements: this.sanitizeRequirementsForStorage(requirements)
            };

            return estimate;

        } catch (error) {
            logger.error('Estimate calculation error:', error);
            throw new Error('Failed to calculate estimate');
        }
    }

    /**
     * サービス固有調整取得
     */
    getServiceAdjustment(serviceType, features) {
        const adjustments = {
            'ai-agent': {
                base: 0,
                'advanced-nlp': 100000,
                'multi-language': 150000,
                'real-time': 200000
            },
            'rag': {
                base: 50000,
                'vector-optimization': 100000,
                'large-dataset': 200000,
                'real-time-updates': 150000
            },
            'aipro': {
                base: -50000, // 既存製品なので割引
                'custom-templates': 50000,
                'api-integration': 100000
            }
        };

        const serviceAdj = adjustments[serviceType] || { base: 0 };
        let totalAdjustment = serviceAdj.base;

        features.forEach(feature => {
            if (serviceAdj[feature]) {
                totalAdjustment += serviceAdj[feature];
            }
        });

        return totalAdjustment;
    }

    /**
     * 配送タイムライン計算
     */
    calculateDeliveryTimeline(requestedTimeline, projectScale) {
        const baseTimelines = {
            small: 14,
            medium: 30,
            large: 60,
            enterprise: 90
        };

        const recommendedTimeline = baseTimelines[projectScale] || 30;
        const actualTimeline = Math.max(requestedTimeline, recommendedTimeline);

        return {
            requested: requestedTimeline,
            recommended: recommendedTimeline,
            actual: actualTimeline,
            phases: this.generatePhases(actualTimeline, projectScale)
        };
    }

    /**
     * コスト内訳生成
     */
    generateCostBreakdown(totalCost, requirements) {
        return {
            development: Math.round(totalCost * 0.6),
            design: Math.round(totalCost * 0.2),
            testing: Math.round(totalCost * 0.1),
            deployment: Math.round(totalCost * 0.05),
            support: Math.round(totalCost * 0.05)
        };
    }

    /**
     * 推奨事項生成
     */
    generateRecommendations(requirements, totalCost) {
        const recommendations = [];

        if (requirements.budget && totalCost > requirements.budget) {
            recommendations.push('予算に合わせた段階的開発をお勧めします');
            recommendations.push('MVP（最小実行可能製品）から開始することで初期コストを削減');
        }

        if (requirements.timeline < 14) {
            recommendations.push('短期間での開発には追加のリスクが伴います');
            recommendations.push('品質保証のため、可能であれば2週間以上の期間を確保');
        }

        recommendations.push('定期的な進捗共有で透明性を確保');
        recommendations.push('段階的リリースによるリスク軽減');

        if (requirements.projectScale === 'enterprise') {
            recommendations.push('エンタープライズ向けセキュリティ監査を推奨');
            recommendations.push('専用サポートチームの設置');
        }

        return recommendations;
    }

    /**
     * 見積もり条件取得
     */
    getEstimateTerms() {
        return {
            validity: '30日間',
            paymentTerms: '着手金30% + 中間金40% + 完了時30%',
            deliveryMethod: '段階的リリース',
            warranty: '3ヶ月間の無償サポート',
            modifications: '仕様変更は別途お見積もり'
        };
    }

    /**
     * 公開サービス情報フォーマット
     */
    formatPublicService(service) {
        return {
            id: service._id,
            name: service.name,
            description: service.description,
            category: service.category,
            features: service.features ? service.features.slice(0, 5) : [], // 最大5個
            pricing: service.pricing ? {
                startingFrom: service.pricing.startingFrom,
                currency: 'JPY',
                billingCycle: service.pricing.billingCycle
            } : null,
            icon: service.icon,
            tags: service.tags ? service.tags.slice(0, 10) : [], // 最大10個
            available: true
        };
    }

    /**
     * サービス詳細構築
     */
    async buildServiceDetails(service, user = null) {
        const baseDetails = {
            id: service._id,
            name: service.name,
            description: service.description,
            category: service.category,
            features: service.features,
            technicalSpecs: this.sanitizeTechnicalSpecs(service.technicalSpecs),
            requirements: service.requirements,
            deliverables: service.deliverables,
            timeline: service.timeline,
            supportLevel: service.supportLevel
        };

        // 認証ユーザーには追加情報
        if (user && user.isVerified) {
            baseDetails.pricing = service.pricing;
            baseDetails.customization = service.customization;
            baseDetails.integration = service.integration;
        }

        // プレミアムユーザーには詳細技術情報
        if (user && user.isPremium) {
            baseDetails.architectureOverview = service.architectureOverview;
            baseDetails.performanceMetrics = service.performanceMetrics;
        }

        return baseDetails;
    }

    // === ユーティリティメソッド ===

    /**
     * サービスアクセスログ
     */
    async logServiceAccess(req, serviceId, action) {
        await createAuditLog({
            action: `service_${action}`,
            userId: req.user?.id || 'anonymous',
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            details: { serviceId }
        });
    }

    /**
     * 技術仕様サニタイズ
     */
    sanitizeTechnicalSpecs(specs) {
        if (!specs) return null;

        const sanitized = { ...specs };
        delete sanitized.internalArchitecture;
        delete sanitized.securityImplementation;
        delete sanitized.deploymentSecrets;

        return sanitized;
    }

    /**
     * 見積もりID生成
     */
    generateEstimateId() {
        const timestamp = Date.now().toString(36);
        const random = Math.random().toString(36).substr(2, 8);
        return `EST_${timestamp}_${random}`.toUpperCase();
    }

    /**
     * キャッシュ操作
     */
    getFromCache(key) {
        const cached = this.cache.get(key);
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached;
        }
        this.cache.delete(key);
        return null;
    }

    setCache(key, data) {
        this.cache.set(key, {
            data,
            timestamp: Date.now()
        });

        // キャッシュサイズ制限
        if (this.cache.size > 100) {
            const oldestKey = this.cache.keys().next().value;
            this.cache.delete(oldestKey);
        }
    }

    /**
     * 要件保存用サニタイズ
     */
    sanitizeRequirementsForStorage(requirements) {
        const sanitized = { ...requirements };
        delete sanitized.contactInfo;
        delete sanitized.internalNotes;
        delete sanitized.budgetDetails;
        return sanitized;
    }
}

module.exports = new ServiceController();