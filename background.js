//background.js handles the analysis, it runs the API calls and manages the whitelist
const OPENAI_API_KEY = 'Replace with your key'; // REPLACE WITH YOUR KEY
const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';

console.log('╔════════════════════════════════════════╗');
console.log('║  CHECK URL BACKGROUND SCRIPT LOADING  ║');
console.log('╚════════════════════════════════════════╝');
console.log('API Key Present:', OPENAI_API_KEY !== 'YOUR_API_KEY');
console.log('API Key Length:', OPENAI_API_KEY.length);
console.log('API Key Preview:', OPENAI_API_KEY.substring(0, 15) + '...');
console.log('========================================\n');


browser.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
        const defaultSettings = {
            realTimeScanning: true,
            showWarningPopups: true,
            blockMaliciousLinks: true,
            scanOnPageLoad: true,
            notifyOnThreats: true,
            keepScanHistory: true,
            autoUpdate: true,
            autoHighlightLinks: true,
            protectionLevel: 'standard'
        };
        
        browser.storage.local.set({
            extensionSettings: defaultSettings,
            scanHistory: [],
            statistics: {
                totalScans: 0,
                threatsBlocked: 0,
                safeSites: 0,
                suspiciousSites: 0,
                maliciousSites: 0,
                lastReset: new Date().toISOString()
            }
        });
        
        browser.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon-48.png',
            title: 'Check URL Extension Installed',
            message: 'AI-powered link protection is now active!'
        });
    }
});

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('📨 Message received:', message.action);
    
    switch (message.action) {
        case 'showNotification':
            browser.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon-48.png',
                title: message.title,
                message: message.message
            });
            sendResponse({ success: true });
            return false;
            
        case 'analyzeUrl':
            if (!message.url) {
                console.error('❌ No URL provided');
                sendResponse({ 
                    status: 'safe', 
                    threats: [], 
                    confidence: 0,
                    error: 'No URL provided'
                });
                return false;
            }
            
            analyzeUrlWithOpenAI(message.url).then(result => {
                console.log('✅ Analysis complete:', {
                    status: result.status,
                    aiPowered: result.aiPowered,
                    threats: result.threats
                });
                
                updateStatistics(result.status).then(() => {
                    sendResponse(result);
                }).catch(error => {
                    console.error('❌ Error updating statistics:', error);
                    sendResponse(result);
                });
            }).catch(error => {
                console.error('❌ Error in analyzeUrl:', error);
                sendResponse({ 
                    status: 'safe', 
                    threats: [], 
                    confidence: 0,
                    error: error.message 
                });
            });
            return true;
            
        case 'getScanHistory':
            browser.storage.local.get(['scanHistory']).then(result => {
                sendResponse(result.scanHistory || []);
            }).catch(error => {
                sendResponse([]);
            });
            return true;
            
        case 'getStatistics':
            browser.storage.local.get(['statistics']).then(result => {
                sendResponse(result.statistics || {});
            }).catch(error => {
                sendResponse({});
            });
            return true;
            
        default:
            sendResponse({ error: 'Unknown action' });
            return false;
    }
});

//Queries the link with OpenAI
async function analyzeUrlWithOpenAI(url) {
    console.log('\n🤖 === OPENAI ANALYSIS START ===');
    console.log('URL:', url);
    
    try {
        // Whitelist Google's UI elements and trusted sites
        const trustedUrls = [
            'accounts.google.com',
            'myaccount.google.com',
            'passwords.google.com',
            'www.google.com/accounts',
            'www.google.com/intl',
            'support.google.com',
            'mail.google.com',
            'drive.google.com',
            'docs.google.com',
            'calendar.google.com',
            'youtube.com',
            'play.google.com',
            'facebook.com',
            'instagram.com',
            'twitter.com',
            'x.com',
            'linkedin.com',
            'microsoft.com',
            'apple.com',
            'amazon.com',
            'ebay.com',
            'wikipedia.org',
            'github.com',
            'stackoverflow.com',
            'reddit.com',
            'netflix.com',
            'spotify.com',
            'nytimes.com',
            'bbc.com',
            'cnn.com',
            'bloomberg.com',
            'washingtonpost.com'
        ];
        
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        
        // Check trusted domains
        for (const trusted of trustedUrls) {
            if (hostname === trusted || hostname.endsWith('.' + trusted)) {
                console.log('✅ Whitelisted domain:', hostname);
                return {
                    status: 'safe',
                    threats: [],
                    confidence: 100,
                    reasoning: 'Trusted website',
                    timestamp: new Date().toISOString(),
                    domain: hostname,
                    aiPowered: false,
                    whitelisted: true
                };
            }
        }
        
        // Whitelist Google's internal navigation ONLY (not external search results)
        if (hostname.endsWith('.google.com')) {
            const isGoogleNavigation = (
                // Authentication and accounts
                url.includes('/accounts/') ||
                url.includes('ServiceLogin') ||
                url.includes('SignUp') ||
                url.includes('/intl/') ||
                url.includes('signin') ||
                url.includes('login') ||
                
                // Homepage
                url.includes('/webhp') ||
                
                // Search type tabs (Images, Videos, News, Shopping, etc.)
                url.includes('tbm=isch') ||  // Images
                url.includes('tbm=vid') ||   // Videos
                url.includes('tbm=nws') ||   // News
                url.includes('tbm=shop') ||  // Shopping
                url.includes('tbm=bks') ||   // Books
                url.includes('tbm=flm') ||   // Flights
                url.includes('&tbm=') ||     // Any search type tab
                
                // Pagination - must be Google's own pages, not external links
                (hostname === 'www.google.com' && url.includes('/search?') && url.includes('&start=')) ||
                
                // "People also searched for" and related - only if staying on google.com
                (hostname === 'www.google.com' && url.includes('/search?') && url.includes('&sa=')) ||
                
                // Settings and preferences
                url.includes('/preferences') ||
                url.includes('/advanced_search')
            );
            
            if (isGoogleNavigation) {
                console.log('✅ Whitelisted Google navigation/UI element');
                return {
                    status: 'safe',
                    threats: [],
                    confidence: 100,
                    reasoning: 'Google navigation element',
                    timestamp: new Date().toISOString(),
                    domain: hostname,
                    aiPowered: false,
                    whitelisted: true
                };
            }
        }
        
        if (OPENAI_API_KEY === 'YOUR_API_KEY') {
            console.error('❌ API key not configured');
            return fallbackAnalysis(url);
        }
        
        console.log('🌐 Making API request to OpenAI...');
        
        const requestBody = {
            model: 'gpt-4o-mini',
            messages: [
                {
                    role: 'system',
                    content: 'You are a cybersecurity expert. Analyze URLs and respond ONLY with valid JSON, no markdown formatting.'
                },
                {
                    role: 'user',
                    content: `Analyze this URL for security threats: ${url}\n\nRespond with ONLY this JSON structure (no markdown, no code blocks):\n{"status":"safe|suspicious|malicious","threats":["array"],"confidence":85,"reasoning":"brief explanation"}`
                }
            ],
            temperature: 0.3,
            max_tokens: 200
        };
        
        console.log('📤 Request body prepared');
        
        const response = await fetch(OPENAI_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            },
            body: JSON.stringify(requestBody)
        });

        console.log('📥 Response received:', {
            status: response.status,
            ok: response.ok
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('❌ OpenAI API Error:', errorText);
            return fallbackAnalysis(url);
        }

        const data = await response.json();
        console.log('✅ OpenAI response parsed successfully');
        
        const aiResponse = data.choices[0].message.content;
        console.log('🤖 AI Response:', aiResponse);
        
        let analysis;
        try {
            // Remove markdown code blocks if present
            let cleanResponse = aiResponse.trim();
            
            if (cleanResponse.startsWith('```')) {
                cleanResponse = cleanResponse.replace(/^```json?\s*\n?/i, '');
                cleanResponse = cleanResponse.replace(/\n?```\s*$/, '');
                cleanResponse = cleanResponse.trim();
            }
            
            console.log('🧹 Cleaned response:', cleanResponse);
            
            analysis = JSON.parse(cleanResponse);
            console.log('✅ Parsed analysis:', analysis);
        } catch (parseError) {
            console.error('❌ Error parsing AI JSON:', parseError);
            console.log('📋 Falling back to local analysis');
            return fallbackAnalysis(url);
        }

        const result = {
            status: analysis.status || 'safe',
            threats: Array.isArray(analysis.threats) ? analysis.threats : [],
            confidence: Math.min(100, Math.max(0, analysis.confidence || 70)),
            reasoning: analysis.reasoning || '',
            timestamp: new Date().toISOString(),
            domain: extractDomain(url),
            aiPowered: true
        };
        
        console.log('🎉 Analysis successful!');
        console.log('=== OPENAI ANALYSIS END ===\n');
        
        return result;

    } catch (error) {
        console.error('❌ Exception in OpenAI analysis:', error);
        console.log('📋 Falling back to local analysis');
        return fallbackAnalysis(url);
    }
}

function fallbackAnalysis(url) {
    console.log('🔧 Running fallback analysis for:', url);
    
    const threats = [];
    let status = 'safe';
    let riskScore = 0;
    
    const urlLower = url.toLowerCase();
    const domain = extractDomain(url);
    
    const maliciousPatterns = [
        'free-iphone', 'scam', 'malware', 'fake-bank',
        'suspicious-download', 'claim-now', 'win-money'
    ];
    
    for (const pattern of maliciousPatterns) {
        if (urlLower.includes(pattern.toLowerCase())) {
            riskScore += 10;
            if (pattern.includes('scam')) threats.push('Scam');
            else if (pattern.includes('malware')) threats.push('Malware');
            else threats.push('Suspicious Content');
        }
    }
    
    if (urlLower.match(/\.(tk|ml|ga|cf)$/)) {
        riskScore += 5;
        threats.push('Suspicious Domain');
    }
    
    if (url.match(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/)) {
        riskScore += 6;
    }
    
    if (riskScore >= 12) status = 'malicious';
    else if (riskScore >= 6) status = 'suspicious';
    
    const result = {
        status,
        threats: threats.length > 0 ? [...new Set(threats)] : [],
        confidence: Math.min(95, 50 + riskScore),
        reasoning: 'Fallback analysis (OpenAI unavailable)',
        timestamp: new Date().toISOString(),
        domain,
        aiPowered: false
    };
    
    console.log('📋 Fallback result:', result);
    return result;
}

function extractDomain(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return '';
    }
}

async function updateStatistics(status) {
    try {
        const result = await browser.storage.local.get(['statistics']);
        const stats = result.statistics || {
            totalScans: 0, threatsBlocked: 0, safeSites: 0, 
            suspiciousSites: 0, maliciousSites: 0, lastReset: new Date().toISOString()
        };
        
        stats.totalScans += 1;
        
        switch (status) {
            case 'safe': stats.safeSites += 1; break;
            case 'suspicious': stats.suspiciousSites += 1; break;
            case 'malicious': 
                stats.maliciousSites += 1; 
                stats.threatsBlocked += 1; 
                break;
        }
        
        await browser.storage.local.set({ statistics: stats });
    } catch (error) {
        console.error('❌ Error updating statistics:', error);
    }
}

console.log('✅ Background script loaded successfully\n');
