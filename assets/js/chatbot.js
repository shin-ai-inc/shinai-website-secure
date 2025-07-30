/**
 * ==============================================
 * // === component-split: ChatbotModule ===
 * COMPONENT: インタラクティブAIチャットボット
 * Vercel Serverless Function統合版
 * ==============================================
 */
const ChatbotModule = {
    toggle: null,
    container: null,
    closeBtn: null,
    messages: null,
    input: null,
    submitBtn: null,
    isTyping: false,
    // セキュアAPI設定（Vercel Serverless Function）
    apiUrl: '/api/chat',
    // 不正利用防止設定
    maxMessageLength: 1000,
    lastMessageTime: 0,
    messageCount: 0,
    rateLimitWindow: 60000, // 1分
    // 使用量監視
    usageStats: {
        dailyUsed: 0,
        monthlyUsed: 0,
        dailyLimit: 100,
        monthlyLimit: 1000
    },
    defaultResponses: [
        "AIチャットボットについての詳細は、お問い合わせフォームよりお気軽にご連絡ください。",
        "AI導入についてのご相談は、専門のコンサルタントが対応いたします。無料相談フォームからお問い合わせください。",
        "AIソリューションについて詳しく知りたい場合は、資料をご用意しております。お気軽にお問い合わせください。",
        "ご質問ありがとうございます。より詳細なご提案をご希望の場合は、お問い合わせフォームよりご連絡ください。",
        "ShinAIのAIチャットボットは多言語対応、24時間稼働、カスタマイズ可能です。詳細はお問い合わせください。",
        "企画書資料作成AIツール「アイプロ」は、自動で高品質な企画書作成をサポートします。ぜひ実際のデモをご覧ください。"
    ],
    companyInfo: {
        name: "ShinAI",
        services: ["AI導入・業務効率化支援", "AIチャットボット開発", "企画書資料作成AIツール「アイプロ」", "意思決定支援AI", "AI内製化支援"],
        address: "東京都千代田区丸の内3-8-3 Tokyo Innovation Base",
        email: "shinai.life@gmail.com",
        phone: "03-1234-5678",
        hours: "平日 9:00〜18:00（土日祝休）"
    },
    systemPrompt: `あなたはShinAIというAI企業のチャットボット「ShinAIアシスタント」です。以下の情報をもとに、簡潔かつ丁寧に応答してください。

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

応答の際は、上記情報に基づいた正確な内容を提供し、詳細な相談は無料相談フォームへの誘導を行ってください。300文字以内の簡潔な返答を心がけてください。`,
    
    init: function() {
        this.toggle = document.getElementById('chatbot-button');
        this.container = document.getElementById('chatbot-window');
        this.closeBtn = document.getElementById('chatbot-close');
        this.messages = document.getElementById('chatbot-messages');
        this.input = document.getElementById('chat-input');
        this.submitBtn = document.getElementById('chat-send');
        
        if (!this.toggle || !this.container) return;
        
        this.toggle.addEventListener('click', this.toggleChat.bind(this));
        this.closeBtn.addEventListener('click', this.closeChat.bind(this));
        this.submitBtn.addEventListener('click', this.sendMessage.bind(this));
        this.input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendMessage();
        });
        
        // トグルボタンをアニメーション
        this.animateToggleButton();
        
        // 初期のウェルカムメッセージが既にHTMLにある前提
        
        // 30秒後にプロアクティブメッセージを表示（ユーザーがまだ開いていない場合）
        setTimeout(() => {
            if (!this.container.classList.contains('active')) {
                this.showProactivePrompt();
            }
        }, 30000);
        
        // 使用量統計の初期化
        this.initUsageStats();
    },
    
    initUsageStats: function() {
        // ローカルストレージから使用量統計を取得（クライアント側での概算）
        const today = new Date().toDateString();
        const thisMonth = new Date().toISOString().substring(0, 7);
        
        const storedStats = localStorage.getItem('shinai_chatbot_usage');
        if (storedStats) {
            try {
                const parsed = JSON.parse(storedStats);
                if (parsed.date === today) {
                    this.usageStats.dailyUsed = parsed.dailyUsed || 0;
                }
                if (parsed.month === thisMonth) {
                    this.usageStats.monthlyUsed = parsed.monthlyUsed || 0;
                }
            } catch (e) {
                console.warn('Failed to parse usage stats:', e);
            }
        }
    },
    
    toggleChat: function() {
        const isOpen = this.container.classList.toggle('active');
        this.toggle.setAttribute('aria-expanded', isOpen);
        
        if (isOpen) {
            this.input.focus();
            // スクリーンリーダー用のアナウンスを削除（視覚的表示を避けるため）
            // this.announceToScreenReaders('チャットボットが開きました');
            
            // 既存のプロアクティブプロンプトを削除
            const proactivePrompt = document.querySelector('.chatbot-proactive');
            if (proactivePrompt) {
                proactivePrompt.remove();
            }
        }
    },
    
    closeChat: function() {
        this.container.classList.remove('active');
        this.toggle.setAttribute('aria-expanded', false);
        // スクリーンリーダー用のアナウンスを削除（視覚的表示を避けるため）
        // this.announceToScreenReaders('チャットボットが閉じました');
    },
    
    sendMessage: async function() {
        const text = this.input.value.trim();
        if (!text || this.isTyping) return;
        
        // メッセージサイズ制限チェック
        if (text.length > this.maxMessageLength) {
            this.showErrorMessage(`メッセージが長すぎます。${this.maxMessageLength}文字以内で入力してください。（現在: ${text.length}文字）`);
            return;
        }
        
        // レート制限チェック
        const now = Date.now();
        if (now - this.lastMessageTime < 3000) { // 3秒間隔制限
            this.showErrorMessage('メッセージの送信間隔が短すぎます。少し待ってからお試しください。');
            return;
        }
        
        // 使用量制限チェック（クライアント側概算）
        if (this.usageStats.dailyUsed >= this.usageStats.dailyLimit) {
            this.showErrorMessage(`本日の利用上限（${this.usageStats.dailyLimit}回）に達しました。明日再度お試しください。詳しくはお問い合わせフォームからご連絡ください。`);
            return;
        }
        
        // ユーザーメッセージを追加
        this.addMessage(text, 'user');
        this.input.value = '';
        this.lastMessageTime = now;
        
        // 入力中表示
        this.showTypingIndicator();
        
        try {
            // セキュアAPIエンドポイント経由でOpenAI API呼び出し
            const response = await this.callSecureAPI(text);
            
            // 入力中表示を非表示
            this.hideTypingIndicator();
            
            // AIレスポンスを追加
            this.addMessage(response.message, 'bot');
            
            // 使用量統計更新
            if (response.usage) {
                this.updateUsageStats(response.usage);
            }
            
            // フォールバック表示の場合は警告を表示
            if (response.fallback) {
                this.showWarningMessage('APIサービスが一時的に利用できません。基本的な応答を表示しています。');
            }
            
            // スクロールを最下部へ
            this.scrollToBottom();
        } catch (error) {
            console.error('Error generating response:', error);
            this.hideTypingIndicator();
            
            // エラーの種類に応じた適切な応答
            if (error.status === 429) {
                this.addMessage("利用上限に達しました。しばらく待ってからお試しいただくか、お問い合わせフォームよりご連絡ください。", 'bot');
            } else if (error.status === 503) {
                this.addMessage("チャットボットサービスが一時的に利用できません。お問い合わせフォームよりご連絡ください。", 'bot');
            } else {
                // フォールバック応答
                const fallbackResponse = this.getLocalResponse(text);
                this.addMessage(fallbackResponse, 'bot');
                this.showWarningMessage('ネットワークエラーが発生しました。基本的な応答を表示しています。');
            }
            
            this.scrollToBottom();
        }
    },
    
    callSecureAPI: async function(userMessage) {
        try {
            const response = await fetch(this.apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message: userMessage
                })
            });
            
            if (!response.ok) {
                const error = new Error(`API request failed with status ${response.status}`);
                error.status = response.status;
                
                // サーバーからのエラーメッセージを取得
                try {
                    const errorData = await response.json();
                    error.message = errorData.error || error.message;
                } catch (e) {
                    // JSON解析に失敗した場合はデフォルトメッセージを使用
                }
                
                throw error;
            }
            
            const data = await response.json();
            return {
                message: data.response,
                usage: data.usage,
                fallback: data.fallback || false
            };
        } catch (error) {
            console.error('Secure API error:', error);
            throw error;
        }
    },
    
    getLocalResponse: function(text) {
        const lowerText = text.toLowerCase();
        
        // 基本的なキーワード検出
        if (lowerText.includes('チャットボット') || lowerText.includes('bot')) {
            return "当社のAIチャットボットは、24時間対応でお客様のお問い合わせに対応します。多言語対応、レスポンス最適化、柔軟なカスタマイズが可能で、導入にあたっては、お客様のサービスに合わせた設計をご提案させていただきます。";
        } else if (lowerText.includes('アイプロ') || lowerText.includes('企画') || lowerText.includes('資料作成')) {
            return "企画書資料作成AIツール「アイプロ」は、自然言語で指示するだけで企画書や提案資料の作成を自動化します。複数の仮説や視点から高品質な企画書を短時間で作成でき、ビジネスの意思決定を加速させます。詳細はお問い合わせフォームよりお気軽にご連絡ください。";
        } else if (lowerText.includes('コンサル') || lowerText.includes('戦略') || lowerText.includes('導入支援')) {
            return "AI戦略コンサルティングでは、お客様のビジネスに最適なAI導入計画を策定し、実装から運用までをサポートします。「やりっぱなしにしないAI導入」をモットーに、成果の定着と内製化の両立を目指します。まずは無料相談からお気軽にどうぞ。";
        } else if (lowerText.includes('料金') || lowerText.includes('価格') || lowerText.includes('費用')) {
            return "各サービスの料金は、導入規模や要件により異なります。業務自動化ソリューションは初期費用30万円〜、月額10万円〜、企画書資料作成AIツール「アイプロ」は初期費用45万円〜、月額15万円〜が目安となります。詳細はお問い合わせフォームよりご連絡いただくか、無料相談にてご案内させていただきます。";
        } else if (lowerText.includes('導入事例') || lowerText.includes('実績')) {
            return "これまで多くの企業様にAIソリューションを提供してきました。介護施設での記録業務効率化（作業時間35%減）、製造業での技能伝承支援（教育期間30%短縮）、自治体での市民対応チャットボット（問い合わせ応答率98%）など、業種別の導入事例について詳細な資料をご提供いたします。";
        } else if (lowerText.includes('会社') || lowerText.includes('企業')) {
            return "ShinAIは「真の価値を信じ、次世代のために新たな未来を創る」という理念のもと、最先端のAI技術で企業の課題解決を支援しています。技術だけでなく、人の感性や社会との調和を重視した「信じられるAI」の実現に取り組んでいます。";
        } else if (lowerText.includes('こんにちは') || lowerText.includes('はじめまして')) {
            return "こんにちは！ShinAIアシスタントです。AI導入や業務効率化についてのご質問があれば、お気軽にお聞きください。初回相談は無料で承っております。";
        } else if (lowerText.includes('いくら') || lowerText.includes('安く')) {
            return "ShinAIでは、お客様の規模や要件に合わせた柔軟な料金プランをご用意しています。小規模導入向けのスターターパッケージ（月額8万円〜）もございますので、ぜひお問い合わせフォームよりご相談ください。";
        } else if (lowerText.includes('デモ') || lowerText.includes('体験')) {
            return "サービスのデモをご希望ですね。各種AIソリューションのデモンストレーションをオンラインまたは貴社訪問にて行っております。まずはお問い合わせフォームより「デモ希望」とご記入の上、ご連絡ください。担当者が詳細をご案内いたします。";
        } else if (lowerText.includes('問い合わせ') || lowerText.includes('連絡')) {
            return "お問い合わせは、ページ上部のメニューにある「お問い合わせ」からフォームにアクセスいただくか、お電話（03-1234-5678、平日9:00〜18:00）、またはメール（shinai.life@gmail.com）にてお気軽にご連絡ください。";
        } else if (lowerText.includes('ありがとう')) {
            return "こちらこそありがとうございます。他にご質問やご不明点がございましたら、いつでもお気軽にお聞きください。ShinAIは御社のAI導入と業務効率化を全力でサポートいたします。";
        } else {
            // デフォルトレスポンス（ランダム）
            return this.defaultResponses[Math.floor(Math.random() * this.defaultResponses.length)];
        }
    },
    
    addMessage: function(text, type) {
        const message = document.createElement('div');
        message.classList.add('chat-message', type);
        message.textContent = text;
        
        if (type === 'bot') {
            message.setAttribute('role', 'status');
        }
        
        this.messages.appendChild(message);
        this.scrollToBottom();
    },
    
    scrollToBottom: function() {
        this.messages.scrollTop = this.messages.scrollHeight;
    },
    
    showTypingIndicator: function() {
        this.isTyping = true;
        
        const typingIndicator = document.createElement('div');
        typingIndicator.classList.add('bot-typing');
        typingIndicator.id = 'bot-typing';
        
        // 3つのドットを追加
        for (let i = 0; i < 3; i++) {
            const dot = document.createElement('span');
            dot.classList.add('typing-dot');
            typingIndicator.appendChild(dot);
        }
        
        this.messages.appendChild(typingIndicator);
        this.scrollToBottom();
    },
    
    hideTypingIndicator: function() {
        this.isTyping = false;
        
        const typingIndicator = document.getElementById('bot-typing');
        if (typingIndicator) {
            typingIndicator.remove();
        }
    },
    
    showProactivePrompt: function() {
        // 既に表示されている場合は何もしない
        if (document.querySelector('.chatbot-proactive')) return;
        
        const promptDiv = document.createElement('div');
        promptDiv.classList.add('chatbot-proactive');
        promptDiv.innerHTML = 'AIについてご質問がありますか？<br>お気軽にお問い合わせください！';
        
        // スタイル設定（CSSでスタイリング済み）
        
        // 吹き出しの尖った部分
        const arrow = document.createElement('div');
        promptDiv.appendChild(arrow);
        
        // クリックイベント
        promptDiv.addEventListener('click', () => {
            this.toggleChat();
            promptDiv.remove();
        });
        
        // チャットボットコンテナの親要素に追加
        this.toggle.parentNode.appendChild(promptDiv);
        
        // 30秒後に自動的に消える
        setTimeout(() => {
            if (promptDiv.parentNode) {
                promptDiv.style.animation = 'fadeInUp 0.5s ease reverse forwards';
                setTimeout(() => {
                    if (promptDiv.parentNode) {
                        promptDiv.remove();
                    }
                }, 500);
            }
        }, 30000);
    },
    
    animateToggleButton: function() {
        // 定期的に注目を集めるアニメーション
        setInterval(() => {
            if (!this.container.classList.contains('active')) {
                this.toggle.classList.add('attention');
                
                setTimeout(() => {
                    this.toggle.classList.remove('attention');
                }, 1000);
            }
        }, 20000); // 20秒ごと
    },
    
    announceToScreenReaders: function(message) {
        let ariaLive = document.querySelector('.sr-announcer');
        
        if (!ariaLive) {
            ariaLive = document.createElement('div');
            ariaLive.className = 'sr-announcer visually-hidden';
            ariaLive.setAttribute('aria-live', 'polite');
            document.body.appendChild(ariaLive);
        }
        
        ariaLive.textContent = message;
    },
    
    // 新機能: エラーメッセージ表示
    showErrorMessage: function(message) {
        const errorMessage = document.createElement('div');
        errorMessage.classList.add('chat-message', 'error-message');
        errorMessage.innerHTML = `<i class="fas fa-exclamation-triangle" aria-hidden="true"></i> ${message}`;
        errorMessage.setAttribute('role', 'alert');
        
        this.messages.appendChild(errorMessage);
        this.scrollToBottom();
        
        // 10秒後に自動削除
        setTimeout(() => {
            if (errorMessage.parentNode) {
                errorMessage.remove();
            }
        }, 10000);
    },
    
    // 新機能: 警告メッセージ表示
    showWarningMessage: function(message) {
        const warningMessage = document.createElement('div');
        warningMessage.classList.add('chat-message', 'warning-message');
        warningMessage.innerHTML = `<i class="fas fa-exclamation-circle" aria-hidden="true"></i> ${message}`;
        warningMessage.setAttribute('role', 'status');
        
        this.messages.appendChild(warningMessage);
        this.scrollToBottom();
        
        // 8秒後に自動削除
        setTimeout(() => {
            if (warningMessage.parentNode) {
                warningMessage.remove();
            }
        }, 8000);
    },
    
    // 新機能: 使用量統計更新
    updateUsageStats: function(usage) {
        if (usage) {
            this.usageStats.dailyUsed = usage.dailyUsed;
            this.usageStats.monthlyUsed = usage.monthlyUsed;
            this.usageStats.dailyLimit = usage.dailyLimit;
            this.usageStats.monthlyLimit = usage.monthlyLimit;
            
            // ローカルストレージに保存（概算用）
            const today = new Date().toDateString();
            const thisMonth = new Date().toISOString().substring(0, 7);
            
            const statsToStore = {
                date: today,
                month: thisMonth,
                dailyUsed: usage.dailyUsed,
                monthlyUsed: usage.monthlyUsed
            };
            
            try {
                localStorage.setItem('shinai_chatbot_usage', JSON.stringify(statsToStore));
            } catch (e) {
                console.warn('Failed to store usage stats:', e);
            }
            
            // 使用量が上限に近い場合は警告表示
            if (usage.dailyUsed >= usage.dailyLimit * 0.8) {
                this.showWarningMessage(`本日の利用回数が上限の80%（${usage.dailyUsed}/${usage.dailyLimit}）に達しました。`);
            } else if (usage.monthlyUsed >= usage.monthlyLimit * 0.8) {
                this.showWarningMessage(`今月の利用回数が上限の80%（${usage.monthlyUsed}/${usage.monthlyLimit}）に達しました。`);
            }
        }
    }
};

// DOMが読み込まれたら初期化
document.addEventListener('DOMContentLoaded', function() {
    ChatbotModule.init();
});