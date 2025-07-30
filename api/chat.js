/**
 * Vercel Serverless Function - ShinAI Chatbot API
 * OpenAI GPT-3.5-turbo統合チャットボット - セキュア版
 * Constitutional AI準拠・APIキー完全保護
 */

// CORS対応のレスポンスヘッダー
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

// セキュリティヘッダー
const securityHeaders = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'",
};

// レート制限用メモリストレージ（本番ではRedisを推奨）
const rateLimitStore = new Map();
const usageStore = new Map();

// Constitutional AI安全制約
const SAFETY_CONSTRAINTS = {
    maxMessageLength: 1000,
    dailyLimit: 100,
    monthlyLimit: 1000,
    rateLimitWindow: 60000, // 1分
    maxRequestsPerWindow: 10
};

// レート制限チェック
function checkRateLimit(clientId) {
    const now = Date.now();
    const windowMs = SAFETY_CONSTRAINTS.rateLimitWindow;
    const maxRequests = SAFETY_CONSTRAINTS.maxRequestsPerWindow;

    if (!rateLimitStore.has(clientId)) {
        rateLimitStore.set(clientId, []);
    }

    const requests = rateLimitStore.get(clientId);
    const validRequests = requests.filter(time => now - time < windowMs);
    
    if (validRequests.length >= maxRequests) {
        return false;
    }

    validRequests.push(now);
    rateLimitStore.set(clientId, validRequests);
    return true;
}

// 使用量制限チェック (Constitutional AI準拠)
function checkUsageLimit(clientId) {
    const today = new Date().toDateString();
    const thisMonth = new Date().toISOString().substring(0, 7);
    
    const dailyKey = `${clientId}:${today}`;
    const monthlyKey = `${clientId}:${thisMonth}`;
    
    const dailyUsed = usageStore.get(dailyKey) || 0;
    const monthlyUsed = usageStore.get(monthlyKey) || 0;
    
    const dailyLimit = SAFETY_CONSTRAINTS.dailyLimit;
    const monthlyLimit = SAFETY_CONSTRAINTS.monthlyLimit;
    
    if (dailyUsed >= dailyLimit || monthlyUsed >= monthlyLimit) {
        return false;
    }
    
    usageStore.set(dailyKey, dailyUsed + 1);
    usageStore.set(monthlyKey, monthlyUsed + 1);
    return true;
}

// 入力値検証 (Constitutional AI準拠)
function validateInput(message) {
    if (!message || typeof message !== 'string') {
        return { valid: false, error: 'メッセージが必要です' };
    }
    
    if (message.length > SAFETY_CONSTRAINTS.maxMessageLength) {
        return { 
            valid: false, 
            error: `メッセージが長すぎます。${SAFETY_CONSTRAINTS.maxMessageLength}文字以内で入力してください。` 
        };
    }
    
    // 不適切なコンテンツフィルタ
    const inappropriatePatterns = [
        /個人情報|住所|電話|クレジット|パスワード/i,
        /違法|犯罪|詐欺|ハッキング/i,
        /暴力|攻撃|脅迫|中傷/i
    ];
    
    for (const pattern of inappropriatePatterns) {
        if (pattern.test(message)) {
            return { 
                valid: false, 
                error: '不適切な内容が含まれています。適切な質問をお試しください。' 
            };
        }
    }
    
    return { valid: true };
}

// OpenAI API呼び出し
async function callOpenAI(message) {
    const systemPrompt = `あなたはShinAIというAI企業のチャットボット「ShinAIアシスタント」です。以下の情報をもとに、簡潔かつ丁寧に応答してください。

会社名：ShinAI
サービス：AI導入・業務効率化支援、AIチャットボット開発、企画書資料作成AIツール「アイプロ」、意思決定支援AI、AI内製化支援
住所：東京都千代田区丸の内3-8-3 Tokyo Innovation Base
メール：shinai.life@gmail.com
電話：03-1234-5678
営業時間：平日 9:00〜18:00（土日祝休）

特徴：
1. AIチャットボットは、24時間対応でお客様のお問い合わせに対応します。多言語対応、直感的な操作で顧客体験と業務効率を両立します。
2. 企画書資料作成AIツール「アイプロ」は、自然言語で指示するだけで企画書や提案資料の作成を自動化。複数の仮説や視点から高品質な企画書を短時間で作成します。
3. AI導入戦略・実装支援では、DX/AXの伴走支援と社内AIチーム育成・内製化支援で、成果定着と自走化を実現します。
4. 「真の価値を信じ、次世代のために新たな未来を創る」という理念のもと、AIで企業の課題解決を支援しています。

重要な制約：
- 300文字以内の簡潔な返答を心がけてください
- 詳細な相談は無料相談フォームへの誘導を行ってください
- 個人情報の収集や不適切な内容には対応しません
- ShinAIのサービス以外の専門的な技術相談は控えめに対応してください`;

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
        },
        body: JSON.stringify({
            model: 'gpt-3.5-turbo',
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: message }
            ],
            max_tokens: 500,
            temperature: 0.7,
            presence_penalty: 0.1,
            frequency_penalty: 0.1
        })
    });

    if (!response.ok) {
        throw new Error(`OpenAI API error: ${response.status} - ${response.statusText}`);
    }

    const data = await response.json();
    return data.choices[0].message.content.trim();
}

// フォールバック応答 (API失敗時)
function getFallbackResponse(message) {
    const fallbackResponses = [
        "申し訳ございませんが、一時的にサービスが利用できません。ShinAIはAI導入・業務効率化支援、AIチャットボット開発、企画書作成AIツール「アイプロ」などのサービスを提供しています。詳細は無料相談フォームからお問い合わせください。",
        "現在システムメンテナンス中です。ShinAIのサービスについてご質問がございましたら、お問い合わせフォームよりご連絡ください。AI導入から内製化支援まで、幅広くサポートいたします。",
        "一時的にAI応答が利用できません。ShinAIは「真の価値を信じ、次世代のために新たな未来を創る」という理念のもと、企業のAI課題解決を支援しています。お問い合わせフォームからご相談ください。"
    ];
    
    return fallbackResponses[Math.floor(Math.random() * fallbackResponses.length)];
}

// メイン関数
export default async function handler(req, res) {
    // CORS preflight対応
    if (req.method === 'OPTIONS') {
        return res.status(200).json({});
    }

    // セキュリティ・CORSヘッダー設定
    Object.entries({...corsHeaders, ...securityHeaders}).forEach(([key, value]) => {
        res.setHeader(key, value);
    });

    // POSTメソッドのみ許可
    if (req.method !== 'POST') {
        return res.status(405).json({ 
            error: 'Method not allowed',
            message: 'Only POST requests are accepted',
            allowedMethods: ['POST', 'OPTIONS']
        });
    }

    try {
        const { message } = req.body;
        
        // クライアントID生成（IPアドレス + User-Agent）
        const clientId = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
        
        // 入力検証 (Constitutional AI準拠)
        const validation = validateInput(message);
        if (!validation.valid) {
            return res.status(400).json({
                error: 'Invalid input',
                message: validation.error,
                timestamp: new Date().toISOString()
            });
        }

        // レート制限チェック
        if (!checkRateLimit(clientId)) {
            return res.status(429).json({
                error: 'Too many requests',
                message: '利用上限に達しました。しばらく待ってからお試しください。',
                retryAfter: 60,
                timestamp: new Date().toISOString()
            });
        }

        // 使用量制限チェック
        if (!checkUsageLimit(clientId)) {
            return res.status(429).json({
                error: 'Usage limit exceeded',
                message: '日次または月次の利用上限に達しました。',
                dailyLimit: SAFETY_CONSTRAINTS.dailyLimit,
                monthlyLimit: SAFETY_CONSTRAINTS.monthlyLimit,
                timestamp: new Date().toISOString()
            });
        }

        // OpenAI API呼び出し
        let response;
        let fallback = false;
        
        try {
            // APIキーが設定されているかチェック
            if (!process.env.OPENAI_API_KEY) {
                throw new Error('OpenAI API key not configured');
            }
            
            response = await callOpenAI(message);
        } catch (apiError) {
            console.error('OpenAI API Error:', apiError);
            response = getFallbackResponse(message);
            fallback = true;
        }

        // 成功レスポンス
        const today = new Date().toDateString();
        const thisMonth = new Date().toISOString().substring(0, 7);
        const dailyKey = `${clientId}:${today}`;
        const monthlyKey = `${clientId}:${thisMonth}`;

        return res.status(200).json({
            response: response,
            usage: {
                dailyUsed: usageStore.get(dailyKey) || 0,
                monthlyUsed: usageStore.get(monthlyKey) || 0,
                dailyLimit: SAFETY_CONSTRAINTS.dailyLimit,
                monthlyLimit: SAFETY_CONSTRAINTS.monthlyLimit
            },
            fallback: fallback,
            timestamp: new Date().toISOString(),
            status: 'success',
            version: '1.0.0'
        });

    } catch (error) {
        console.error('Server Error:', error);
        
        return res.status(500).json({
            error: 'Internal server error',
            message: 'システムエラーが発生しました。しばらく経ってからお試しください。',
            timestamp: new Date().toISOString(),
            fallback: true
        });
    }
}