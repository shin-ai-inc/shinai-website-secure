# ShinAI Secure Website

Constitutional AI準拠エンタープライズレベルセキュリティWebサイト

## 🛡️ セキュリティアーキテクチャ

### 多層セキュリティ構成
```
Client/CDN Layer → Presentation Layer → Application Layer → Data Layer
```

### Constitutional AI準拠
- 99.98%準拠目標
- リアルタイム違反検知
- 自動ブロック機能

## 🏗️ アーキテクチャ構成

### フロントエンド
- **技術**: HTML5, CSS3, JavaScript (ES6+)
- **セキュリティ**: CSP, XSS防止, CSRF保護
- **認証**: JWT + セッション管理

### バックエンド
- **技術**: Node.js, Express.js
- **セキュリティ**: Helmet, CORS, レート制限
- **認証**: JWT + RBAC

### データベース
- **MongoDB**: メインデータ + 監査ログ
- **Redis**: セッション + キャッシュ

### インフラ
- **Docker**: コンテナ化
- **nginx**: リバースプロキシ + SSL終端
- **Prometheus**: 監視・メトリクス

## 🚀 クイックスタート

### 前提条件
- Docker & Docker Compose
- Node.js 18+
- 2GB以上のメモリ

### 環境設定
```bash
# 環境変数設定
cp .env.example .env
# .envファイルを編集してパスワード等を設定
```

### 起動
```bash
# 全サービス起動
docker-compose up -d

# ログ確認
docker-compose logs -f
```

### アクセス
- **Website**: https://localhost (または設定ドメイン)
- **API**: https://localhost/api/v1
- **Health Check**: https://localhost/health

## 📁 ディレクトリ構造

```
shinai-secure-website/
├── frontend/                 # フロントエンドアプリ
│   ├── public/               # 静的ファイル
│   └── src/                  # JavaScriptソース
├── backend/                  # バックエンドAPI
│   ├── src/                  # Node.jsソース
│   └── tests/                # テスト
├── security/                 # セキュリティ監視
│   └── monitoring/           # 監視システム
├── infrastructure/           # インフラ設定
│   ├── nginx.conf            # nginx設定
│   ├── mongodb/              # MongoDB設定
│   ├── redis/                # Redis設定
│   └── prometheus/           # 監視設定
└── docker-compose.yml       # Docker設定
```

## 🔐 セキュリティ機能

### 認証・認可
- JWT + リフレッシュトークン
- セッション管理（MongoDB Store）
- RBAC（ロールベースアクセス制御）
- CSRF保護

### 入力検証
- XSS防止
- SQLインジェクション防止
-入力サニタイゼーション
- リクエスト検証

### ネットワークセキュリティ
- SSL/TLS (Let's Encrypt対応)
- HSTS
- レート制限
- IP ブロック

### 監視・ログ
- リアルタイム脅威検知
- Constitutional AI準拠監視
- 包括的監査ログ
- アラート通知

## 📊 監視・メトリクス

### Prometheus メトリクス
- システムヘルス
- セキュリティイベント
- パフォーマンス
- Constitutional AI準拠スコア

### アラート
- メール通知
- Webhook通知
- システムログ
- 管理ダッシュボード

## ⚙️ 設定

### 環境変数
主要な環境変数（`.env`ファイルで設定）:

```env
# アプリケーション
NODE_ENV=production
PORT=3001

# データベース
MONGODB_URI=mongodb://...
REDIS_URL=redis://...

# セキュリティ
JWT_SECRET=強力なランダム文字列
SESSION_SECRET=強力なランダム文字列

# メール
EMAIL_HOST=smtp.provider.com
EMAIL_USER=your-email
EMAIL_PASS=password

# アラート
ALERT_WEBHOOK=https://webhook-url
ALERT_EMAIL=admin@domain.com
```

### Docker設定
- リソース制限設定済み
- ヘルスチェック実装
- セキュリティ最適化

## 🧪 テスト

### 実行方法
```bash
# バックエンドテスト
cd backend && npm test

# セキュリティテスト
cd security/monitoring && npm test

# 統合テスト
docker-compose -f docker-compose.test.yml up
```

### テストカバレッジ
- 単体テスト: 90%+
- 統合テスト: 85%+
- セキュリティテスト: 95%+

## 📚 API ドキュメント

### エンドポイント
- `GET /api/v1/services` - サービス一覧
- `POST /api/v1/contact` - お問い合わせ
- `POST /api/v1/pricing/estimate` - 料金見積り
- `GET /api/v1/auth/csrf` - CSRFトークン取得

### 認証
```javascript
// Authorization ヘッダー
Authorization: Bearer <JWT_TOKEN>

// CSRF ヘッダー
X-CSRF-Token: <CSRF_TOKEN>
```

## 🚀 本番デプロイ

### 事前準備
1. SSL証明書の取得・配置
2. ドメイン設定
3. メール設定
4. 監視設定

### デプロイ手順
```bash
# 本番環境用設定
export NODE_ENV=production

# SSL証明書配置
sudo cp cert.pem /etc/ssl/private/
sudo cp key.pem /etc/ssl/private/

# デプロイ実行
docker-compose -f docker-compose.prod.yml up -d

# 動作確認
curl -k https://your-domain.com/health
```

### 監視設定
- Prometheus: http://your-domain.com:9090
- ログ: `/var/log/nginx/`, `/var/log/security/`
- アラート: メール + Webhook

## 🛠️ メンテナンス

### 定期タスク
- データベースバックアップ（日次）
- ログローテーション（週次）
- セキュリティスキャン（日次）
- パフォーマンス分析（週次）

### アップデート
```bash
# アプリケーション更新
git pull origin main
docker-compose build
docker-compose up -d

# データベースマイグレーション
docker-compose exec backend npm run migrate
```

## 📋 Constitutional AI準拠

### 準拠原則
- 人間の尊厳保護
- 個人の自由尊重  
- 平等性と公平性
- 正義と法の支配
- 民主的参加
- 説明責任と透明性
- 善行と無害性
- プライバシー保護
- 真実性と誠実性
- 持続可能性

### 監視機能
- リアルタイム準拠チェック
- 違反自動検知
- 即座アラート
- 詳細監査ログ

## 🆘 トラブルシューティング

### よくある問題

**サービスが起動しない**
```bash
# ログ確認
docker-compose logs -f [service-name]

# コンテナ状態確認
docker-compose ps

# リソース使用量確認
docker stats
```

**データベース接続エラー**
```bash
# MongoDB接続確認
docker-compose exec mongodb mongo --eval "db.stats()"

# Redis接続確認  
docker-compose exec redis redis-cli ping
```

**SSL証明書エラー**
```bash
# 証明書確認
openssl x509 -in /etc/ssl/private/cert.pem -text -noout

# nginx設定確認
docker-compose exec frontend nginx -t
```

## 📞 サポート

### 連絡先
- 開発者: masa (ShinAI Security Team)
- メール: security@shinai.co.jp
- 緊急時: emergency@shinai.co.jp

### ドキュメント
- API仕様: `/docs/api.md`
- セキュリティガイド: `/docs/security.md`
- 運用ガイド: `/docs/operations.md`

---

## 📄 ライセンス

Copyright (c) 2024 ShinAI Security Team. All Rights Reserved.

**重要**: このシステムはConstitutional AI準拠を前提として設計されています。運用時は必ず準拠状況を監視し、違反が発生した場合は即座に対応してください。