# ShinAI Security Monitoring System
# Constitutional AI準拠セキュリティ監視コンテナ
# masa様開発ルール完全遵守・本番環境対応

FROM node:18-alpine

# セキュリティアップデート
RUN apk update && apk upgrade && \
    apk add --no-cache \
    dumb-init \
    curl \
    ca-certificates \
    tzdata && \
    rm -rf /var/cache/apk/*

# 非root ユーザー作成
RUN addgroup -g 1001 -S nodejs && \
    adduser -S security -u 1001 -G nodejs

# タイムゾーン設定
ENV TZ=Asia/Tokyo
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 作業ディレクトリ設定
WORKDIR /app

# 依存関係ファイルコピー（キャッシュ最適化）
COPY --chown=security:nodejs package*.json ./

# 依存関係インストール（本番環境用）
RUN npm ci --only=production && \
    npm cache clean --force && \
    rm -rf /tmp/* /var/tmp/*

# アプリケーションファイルコピー
COPY --chown=security:nodejs src/ ./src/

# ログディレクトリ作成
RUN mkdir -p /var/log/security && \
    chown -R security:nodejs /var/log/security && \
    chmod 755 /var/log/security

# セキュリティ設定
RUN chmod 644 package*.json && \
    find /app -type f -name "*.js" -exec chmod 644 {} \; && \
    chmod 755 /app/src/app.js

# ヘルスチェック設定
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3002/health || exit 1

# 環境変数
ENV NODE_ENV=production
ENV PORT=3002
ENV HOST=0.0.0.0

# ポート公開
EXPOSE 3002

# 非rootユーザーに切り替え
USER security

# エントリーポイント設定
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/app.js"]

# ラベル（メタデータ）
LABEL maintainer="masa (ShinAI Security Team)" \
      version="2.0.0-secure" \
      description="ShinAI Security Monitoring System with Constitutional AI compliance" \
      org.label-schema.schema-version="1.0" \
      org.label-schema.name="shinai-security-monitoring" \
      org.label-schema.vendor="ShinAI" \
      org.label-schema.version="2.0.0-secure"