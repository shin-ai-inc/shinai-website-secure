# ShinAI Secure Website デプロイメントガイド

## 🚀 GitHub公開・デプロイ手順

### 前提条件
- GitHubアカウント
- Git設定完了
- Docker環境（本番デプロイ用）

## Step 1: GitHubリポジトリ作成

### 1.1 GitHub.comでリポジトリ作成
```
Repository name: shinai-secure-website
Description: ShinAI Secure Website - Enterprise Security Architecture with Constitutional AI Compliance
Visibility: Public (推奨) / Private
```

### 1.2 ローカルリポジトリとリモート接続
```bash
cd /c/Users/masa/ai-long-memoryi-system/project/shinai-secure-website

# リモートリポジトリ設定（YOUR_GITHUB_USERNAMEを実際のユーザー名に変更）
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/shinai-secure-website.git

# メインブランチにプッシュ
git branch -M main
git push -u origin main
```

## Step 2: GitHub Pages設定（静的サイト公開）

### 2.1 GitHub Pages有効化
1. GitHubリポジトリの **Settings** タブ
2. 左メニューの **Pages** 
3. 設定値：
   - **Source**: Deploy from a branch
   - **Branch**: main
   - **Folder**: / (root) または /frontend/public

### 2.2 カスタムドメイン設定（オプション）
- **Custom domain**: `shinai.co.jp`
- **Enforce HTTPS**: ✅ 有効

## Step 3: 本番環境デプロイ

### 3.1 Docker環境でのデプロイ
```bash
# 環境変数設定
cp .env.example .env
# .envファイルを本番用に編集

# 本番環境起動
docker-compose up -d

# SSL証明書設定（Let's Encrypt推奨）
sudo certbot --nginx -d shinai.co.jp -d www.shinai.co.jp
```

### 3.2 クラウドデプロイ（推奨オプション）

**AWS ECS/Fargate:**
```bash
# ECS設定ファイル
aws ecs create-cluster --cluster-name shinai-secure
aws ecs create-service --cluster shinai-secure --service-name shinai-web
```

**Google Cloud Run:**
```bash
gcloud run deploy shinai-secure --source . --platform managed --region asia-east1
```

**Azure Container Instances:**
```bash
az container create --resource-group shinai --name shinai-secure --image shinai/secure-website
```

## Step 4: セキュリティ設定

### 4.1 環境変数設定（重要）
```bash
# 強力なランダム文字列を生成
openssl rand -hex 32  # JWT_SECRET用
openssl rand -hex 32  # SESSION_SECRET用
openssl rand -hex 32  # ENCRYPTION_KEY用
```

### 4.2 SSL/TLS証明書設定
```bash
# Let's Encrypt（推奨）
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d shinai.co.jp

# 自動更新設定
sudo crontab -e
# 追加: 0 12 * * * /usr/bin/certbot renew --quiet
```

### 4.3 ファイアウォール設定
```bash
# 必要ポートのみ開放
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 22/tcp    # SSH（管理用）
sudo ufw deny 3001/tcp  # バックエンドAPI（内部のみ）
sudo ufw enable
```

## Step 5: 監視・アラート設定

### 5.1 GitHub Actions Secrets設定
**Settings → Secrets and variables → Actions** で設定:
```
DOCKERHUB_USERNAME: あなたのDockerHubユーザー名
DOCKERHUB_TOKEN: DockerHubアクセストークン
ALERT_EMAIL: アラート受信メールアドレス
WEBHOOK_URL: Slack/Discordウェブフック URL
```

### 5.2 外部監視サービス設定
- **UptimeRobot**: https://uptimerobot.com/
- **Pingdom**: https://www.pingdom.com/
- **DataDog**: https://www.datadoghq.com/

## Step 6: アクセス確認

### 6.1 デプロイ後の確認項目
```bash
# ヘルスチェック
curl https://shinai.co.jp/health

# セキュリティヘッダー確認
curl -I https://shinai.co.jp

# Constitutional AI準拠チェック
curl https://shinai.co.jp/api/v1/compliance/check
```

### 6.2 期待される結果
```json
{
  "status": "healthy",
  "constitutional_ai_compliant": true,
  "security_level": "enterprise",
  "timestamp": "2024-XX-XX"
}
```

## 🔐 セキュリティチェックリスト

### デプロイ前確認
- [ ] 環境変数にテスト値が含まれていない
- [ ] 強力なパスワード・秘密鍵を設定
- [ ] SSL証明書が正常に設定される
- [ ] ファイアウォール設定が適切
- [ ] Constitutional AI準拠チェック通過

### デプロイ後確認
- [ ] HTTPS強制リダイレクト動作
- [ ] セキュリティヘッダー送信確認
- [ ] API認証機能動作確認
- [ ] 監視アラート受信確認
- [ ] バックアップ機能動作確認

## 🚨 緊急時対応

### サービス停止手順
```bash
# 緊急停止
docker-compose down

# 特定コンテナのみ停止
docker stop shinai-frontend shinai-backend
```

### ロールバック手順
```bash
# 前バージョンへ復旧
git log --oneline -10  # コミット履歴確認
git reset --hard [前のコミットID]
git push -f origin main  # 強制プッシュ
```

## 📞 サポート・連絡先

**技術サポート:**
- 開発者: masa (ShinAI Security Team)
- メール: security@shinai.co.jp
- 緊急時: emergency@shinai.co.jp

**監視ダッシュボード:**
- Prometheus: https://shinai.co.jp:9090
- システムログ: `/var/log/nginx/`, `/var/log/security/`

---

## 🎯 成功指標

### 公開成功の確認
1. **Webサイトアクセス**: https://shinai.co.jp → 200 OK
2. **セキュリティレベル**: Enterprise Grade確認
3. **Constitutional AI準拠**: 99.98%+維持
4. **監視システム**: アラート正常受信
5. **パフォーマンス**: レスポンス時間 < 2秒

**🎉 全て確認できれば公開成功です！**