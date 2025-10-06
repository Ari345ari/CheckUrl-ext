// Fixed message listener for background.js
// Add this to replace the existing browser.runtime.onMessage.addListener in background.js

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('Background received message:', message);
    
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
                console.error('No URL provided to analyzeUrl');
                sendResponse({ 
                    status: 'safe', 
                    threats: [], 
                    confidence: 0,
                    error: 'No URL provided'
                });
                return false;
            }
            
            analyzeUrl(message.url).then(result => {
                console.log('Analysis result:', result);
                updateStatistics(result.status).then(() => {
                    sendResponse(result);
                }).catch(error => {
                    console.error('Error updating statistics:', error);
                    sendResponse(result);
                });
            }).catch(error => {
                console.error('Error in analyzeUrl:', error);
                sendResponse({ 
                    status: 'safe', 
                    threats: [], 
                    confidence: 0,
                    error: error.message 
                });
            });
            return true; // Keep channel open for async response
            
        case 'getScanHistory':
            browser.storage.local.get(['scanHistory']).then(result => {
                sendResponse(result.scanHistory || []);
            }).catch(error => {
                console.error('Error getting scan history:', error);
                sendResponse([]);
            });
            return true;
            
        case 'getStatistics':
            browser.storage.local.get(['statistics']).then(result => {
                sendResponse(result.statistics || {});
            }).catch(error => {
                console.error('Error getting statistics:', error);
                sendResponse({});
            });
            return true;
            
        default:
            console.log('Unknown action:', message.action);
            sendResponse({ error: 'Unknown action' });
            return false;
    }
});// Fixed message listener for background.js
// Add this to replace the existing browser.runtime.onMessage.addListener in background.js

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
        case 'showNotification':
            browser.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon-48.png',
                title: message.title,
                message: message.message
            });
            sendResponse({ success: true });
            break;
            
        case 'analyzeUrl':
            analyzeUrl(message.url).then(result => {
                updateStatistics(result.status);
                sendResponse(result);
            }).catch(error => {
                console.error('Error in analyzeUrl:', error);
                sendResponse({ 
                    status: 'safe', 
                    threats: [], 
                    confidence: 0,
                    error: error.message 
                });
            });
            return true; // Keep channel open for async response
            
        case 'getScanHistory':
            browser.storage.local.get(['scanHistory']).then(result => {
                sendResponse(result.scanHistory || []);
            }).catch(error => {
                console.error('Error getting scan history:', error);
                sendResponse([]);
            });
            return true;
            
        case 'getStatistics':
            browser.storage.local.get(['statistics']).then(result => {
                sendResponse(result.statistics || {});
            }).catch(error => {
                console.error('Error getting statistics:', error);
                sendResponse({});
            });
            return true;
    }
    
    return false;
});// Enhanced background script for real-time URL protection
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
            threatDatabase: {
                version: '1.1.0',
                lastUpdated: new Date().toISOString(),
                patterns: [
                    'free-iphone', 'scam', 'malware', 'fake-bank',
                    'suspicious-download', 'claim-now', 'win-money', 'urgent-action',
                    'verify-account', 'fake-antivirus', 'prize-winner', 'crypto-giveaway',
                    'fake-update', 'tech-support', 'click-here-free', 'download-virus',
                    'security-alert', 'computer-infected', 'microsoft-support',
                    'apple-support', 'google-support', 'amazon-support', 'paypal-support',
                    'bank-alert', 'account-suspended', 'immediate-action', 'confirm-identity',
                    'update-payment', 'verify-information', 'suspicious-activity',
                    'login-attempt', 'security-breach', 'data-breach', 'click-to-continue',
                    'activate-account', 'temporary-suspension', 'refund-pending',
                    'tax-refund', 'government-grant', 'stimulus-check', 'inheritance-fund',
                    'lottery-winner', 'sweepstakes', 'congratulations-winner',
                    'exclusive-offer', 'limited-time', 'act-now', 'expires-today',
                    'final-notice', 'last-warning', 'overdue-payment', 'payment-failed'
                ],
                domains: [
                    'bit.ly', 'tinyurl.com', '.tk', '.ml', '.ga', '.cf',
                    'temp-mail', '10minutemail', 'guerrillamail', 'mailinator',
                    'throwaway', 'tempmail', 'fake-', 'scam-',
                    'malware-', 'virus-', 'trojan-'
                ]
            },
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
            message: 'Real-time link protection is now active!'
        });
        
        console.log('Check URL extension installed successfully');
    }
});

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
        case 'showNotification':
            browser.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon-48.png',
                title: message.title,
                message: message.message
            });
            break;
            
        case 'analyzeUrl':
            analyzeUrl(message.url).then(result => {
                updateStatistics(result.status);
                sendResponse(result);
            });
            return true;
            
        case 'getScanHistory':
            browser.storage.local.get(['scanHistory']).then(result => {
                sendResponse(result.scanHistory || []);
            });
            return true;
            
        case 'getStatistics':
            browser.storage.local.get(['statistics']).then(result => {
                sendResponse(result.statistics || {});
            });
            return true;
    }
});

async function analyzeUrl(url) {
    try {
        const result = await browser.storage.local.get(['threatDatabase', 'extensionSettings']);
        const threatDb = result.threatDatabase;
        const settings = result.extensionSettings || {};
        
        if (!threatDb) {
            return { status: 'safe', threats: [], confidence: 0 };
        }
        
        const threats = [];
        let status = 'safe';
        let riskScore = 0;
        
        const urlLower = url.toLowerCase();
        const domain = extractDomain(url);
        
        // Check against malicious patterns
        for (const pattern of threatDb.patterns) {
            if (urlLower.includes(pattern.toLowerCase())) {
                riskScore += 10;
                
                if (pattern.includes('scam')) threats.push('Scam');
                else if (pattern.includes('malware')) threats.push('Malware');
                else if (pattern.includes('fake-bank')) threats.push('Identity Theft');
                else if (pattern.includes('crypto')) threats.push('Cryptocurrency Scam');
                else if (pattern.includes('tech-support')) threats.push('Tech Support Scam');
                else threats.push('Suspicious Content');
            }
        }
        
        // Check against suspicious domains
        for (const domainPattern of threatDb.domains) {
            if (urlLower.includes(domainPattern.toLowerCase())) {
                riskScore += 5;
                if (!threats.includes('Suspicious Domain')) {
                    threats.push('Suspicious Domain');
                }
            }
        }
        
        // Heuristic analysis
        riskScore += performHeuristicAnalysis(url, domain);
        
        // Determine status
        const protectionLevel = settings.protectionLevel || 'standard';
        const thresholds = getProtectionThresholds(protectionLevel);
        
        if (riskScore >= thresholds.malicious) {
            status = 'malicious';
        } else if (riskScore >= thresholds.suspicious) {
            status = 'suspicious';
        }
        
        return {
            status,
            threats: threats.length > 0 ? [...new Set(threats)] : undefined,
            confidence: Math.min(95, 70 + riskScore),
            riskScore,
            timestamp: new Date().toISOString(),
            domain
        };
        
    } catch (error) {
        console.error('Error analyzing URL:', error);
        return { status: 'safe', threats: [], confidence: 0, timestamp: new Date().toISOString() };
    }
}

function performHeuristicAnalysis(url, domain) {
    let riskScore = 0;
    
    // IP address instead of domain
    if (url.match(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/)) riskScore += 6;
    
    // Suspicious TLDs
    if (domain.match(/\.(tk|ml|ga|cf)$/)) riskScore += 5;
    
    // URL shorteners
    if (url.match(/(bit\.ly|tinyurl|t\.co)/i)) riskScore += 4;
    
    // Punycode (IDN attacks)
    if (url.includes('xn--')) riskScore += 4;
    
    // Brand impersonation
    if (url.match(/(paypal|amazon|microsoft|apple|google)/i)) {
        if (!domain.includes('paypal.com') && !domain.includes('amazon.com') && 
            !domain.includes('microsoft.com') && !domain.includes('apple.com') && 
            !domain.includes('google.com')) {
            riskScore += 7;
        }
    }
    
    // Non-HTTPS
    if (url.startsWith('http://')) riskScore += 2;
    
    return riskScore;
}

function getProtectionThresholds(level) {
    switch (level) {
        case 'strict': return { malicious: 8, suspicious: 4 };
        case 'standard': return { malicious: 12, suspicious: 6 };
        case 'permissive': return { malicious: 16, suspicious: 10 };
        default: return { malicious: 12, suspicious: 6 };
    }
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
        console.error('Error updating statistics:', error);
    }
}

console.log('Check URL background script loaded');
