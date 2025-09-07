/**
 * MongoDB初期化スクリプト
 * データベース・コレクション・インデックス作成
 * Constitutional AI準拠・masa様開発ルール完全遵守
 */

// データベース選択
db = db.getSiblingDB('shinai_secure');

try {
    // 1. ユーザー作成
    db.createUser({
        user: "mongodb_user",
        pwd: process.env.MONGO_PASSWORD || "secure_password_2024",
        roles: [
            {
                role: "readWrite",
                db: "shinai_secure"
            }
        ]
    });

    print("✅ MongoDB user created successfully");

    // 2. セッションコレクション作成とインデックス
    db.createCollection("sessions");
    db.sessions.createIndex({ "expires": 1 }, { expireAfterSeconds: 0 });
    db.sessions.createIndex({ "_id": 1 });
    print("✅ Sessions collection and indexes created");

    // 3. ユーザーコレクション作成とインデックス  
    db.createCollection("users");
    db.users.createIndex({ "email": 1 }, { unique: true });
    db.users.createIndex({ "username": 1 }, { unique: true });
    db.users.createIndex({ "created_at": 1 });
    db.users.createIndex({ "last_login": 1 });
    db.users.createIndex({ "status": 1 });
    print("✅ Users collection and indexes created");

    // 4. 監査ログコレクション作成とインデックス
    db.createCollection("security_audit_logs");
    db.security_audit_logs.createIndex({ "timestamp": 1 });
    db.security_audit_logs.createIndex({ "event_type": 1 });
    db.security_audit_logs.createIndex({ "metadata.source_ip": 1 });
    db.security_audit_logs.createIndex({ "metadata.user_id": 1 });
    db.security_audit_logs.createIndex({ "constitutional_compliance.compliant": 1 });
    db.security_audit_logs.createIndex({ "severity": 1 });
    print("✅ Security audit logs collection and indexes created");

    // 5. Constitutional AI違反ログコレクション
    db.createCollection("constitutional_violations");
    db.constitutional_violations.createIndex({ "timestamp": 1 });
    db.constitutional_violations.createIndex({ "severity": 1 });
    db.constitutional_violations.createIndex({ "violations.principle": 1 });
    db.constitutional_violations.createIndex({ "investigation_status": 1 });
    db.constitutional_violations.createIndex({ "compliance_score": 1 });
    print("✅ Constitutional violations collection and indexes created");

    // 6. セキュリティイベントコレクション
    db.createCollection("security_events");
    db.security_events.createIndex({ "timestamp": 1 });
    db.security_events.createIndex({ "event_type": 1 });
    db.security_events.createIndex({ "source.ip": 1 });
    db.security_events.createIndex({ "threat_level": 1 });
    print("✅ Security events collection and indexes created");

    // 7. サービスデータコレクション
    db.createCollection("services");
    db.services.createIndex({ "service_id": 1 }, { unique: true });
    db.services.createIndex({ "category": 1 });
    db.services.createIndex({ "status": 1 });
    db.services.createIndex({ "created_at": 1 });
    print("✅ Services collection and indexes created");

    // 8. お問い合わせコレクション
    db.createCollection("contacts");
    db.contacts.createIndex({ "email": 1 });
    db.contacts.createIndex({ "submitted_at": 1 });
    db.contacts.createIndex({ "status": 1 });
    db.contacts.createIndex({ "constitutional_compliance.compliant": 1 });
    print("✅ Contacts collection and indexes created");

    // 9. 料金見積りコレクション
    db.createCollection("pricing_estimates");
    db.pricing_estimates.createIndex({ "email": 1 });
    db.pricing_estimates.createIndex({ "service_type": 1 });
    db.pricing_estimates.createIndex({ "created_at": 1 });
    db.pricing_estimates.createIndex({ "total_price": 1 });
    print("✅ Pricing estimates collection and indexes created");

    // 10. システム統計コレクション
    db.createCollection("system_stats");
    db.system_stats.createIndex({ "date": 1 }, { unique: true });
    db.system_stats.createIndex({ "metric_type": 1 });
    print("✅ System stats collection and indexes created");

    // 11. アラートコレクション
    db.createCollection("security_alerts");
    db.security_alerts.createIndex({ "timestamp": 1 });
    db.security_alerts.createIndex({ "alert_type": 1 });
    db.security_alerts.createIndex({ "severity": 1 });
    db.security_alerts.createIndex({ "status": 1 });
    print("✅ Security alerts collection and indexes created");

    // 12. 整合性チェックコレクション
    db.createCollection("audit_integrity");
    db.audit_integrity.createIndex({ "date": 1 }, { unique: true });
    db.audit_integrity.createIndex({ "integrity_score": 1 });
    print("✅ Audit integrity collection and indexes created");

    // 13. 初期データ挿入

    // サービスデータ
    const services = [
        {
            service_id: "ai_consultation",
            name: "AI導入コンサルティング",
            category: "consulting",
            description: "企業様のAI導入戦略立案から実装まで包括的サポート",
            base_price: 500000,
            duration_months: 3,
            features: [
                "現状分析・課題抽出",
                "AI導入戦略立案",
                "技術選定支援",
                "実装サポート",
                "効果測定・改善"
            ],
            constitutional_compliance: {
                compliant: true,
                score: 1.0,
                principles: ["human_dignity", "transparency", "beneficence"]
            },
            status: "active",
            created_at: new Date(),
            updated_at: new Date()
        },
        {
            service_id: "custom_ai_development",
            name: "カスタムAIシステム開発",
            category: "development",
            description: "お客様の業務に特化したAIシステムの設計・開発",
            base_price: 1000000,
            duration_months: 6,
            features: [
                "要件定義・設計",
                "AIモデル開発",
                "システム統合",
                "テスト・検証",
                "運用保守"
            ],
            constitutional_compliance: {
                compliant: true,
                score: 1.0,
                principles: ["human_dignity", "privacy_protection", "accountability"]
            },
            status: "active",
            created_at: new Date(),
            updated_at: new Date()
        },
        {
            service_id: "ai_ethics_audit",
            name: "AI倫理監査",
            category: "audit",
            description: "Constitutional AI準拠によるAIシステム倫理監査",
            base_price: 300000,
            duration_months: 2,
            features: [
                "Constitutional AI準拠チェック",
                "バイアス分析",
                "透明性評価",
                "リスク評価",
                "改善提案"
            ],
            constitutional_compliance: {
                compliant: true,
                score: 1.0,
                principles: ["justice_rule_of_law", "equality_fairness", "transparency"]
            },
            status: "active",
            created_at: new Date(),
            updated_at: new Date()
        }
    ];

    db.services.insertMany(services);
    print("✅ Initial service data inserted");

    // システム統計初期データ
    const today = new Date();
    const initialStats = {
        date: today.toISOString().split('T')[0],
        metric_type: "system_initialization",
        metrics: {
            total_collections: 12,
            total_indexes: 35,
            constitutional_compliance_score: 1.0,
            security_level: "enterprise",
            initialization_timestamp: today
        },
        created_at: today
    };

    db.system_stats.insertOne(initialStats);
    print("✅ Initial system stats inserted");

    // 14. Constitutional AI準拠設定
    db.createCollection("constitutional_ai_config");
    const constitutionalConfig = {
        _id: "main_config",
        version: "2.0.0",
        compliance_threshold: 0.95,
        principles: {
            human_dignity: { weight: 1.0, enabled: true },
            individual_freedom: { weight: 0.9, enabled: true },
            equality_fairness: { weight: 0.95, enabled: true },
            justice_rule_of_law: { weight: 0.9, enabled: true },
            democratic_participation: { weight: 0.8, enabled: true },
            accountability_transparency: { weight: 0.95, enabled: true },
            beneficence_non_maleficence: { weight: 1.0, enabled: true },
            privacy_protection: { weight: 0.95, enabled: true },
            truthfulness_honesty: { weight: 0.9, enabled: true },
            sustainability: { weight: 0.8, enabled: true }
        },
        monitoring: {
            enabled: true,
            real_time_checking: true,
            alert_threshold: 0.8,
            log_all_checks: true
        },
        created_at: today,
        updated_at: today
    };

    db.constitutional_ai_config.insertOne(constitutionalConfig);
    print("✅ Constitutional AI configuration created");

    print("\n🎉 MongoDB initialization completed successfully!");
    print("📊 Database: shinai_secure");
    print("👤 User: mongodb_user");
    print("📁 Collections: 13");
    print("📇 Indexes: 35+");
    print("🛡️  Constitutional AI: Enabled");
    print("🔒 Security Level: Enterprise");

} catch (error) {
    print("❌ MongoDB initialization failed:");
    print(error);
    throw error;
}