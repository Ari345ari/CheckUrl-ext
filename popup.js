// Fixed popup implementation for the extension
document.addEventListener('DOMContentLoaded', async function() {
    console.log('Popup loading...');
    const root = document.getElementById('root');
    
    // Show loading state immediately
    root.innerHTML = `
        <div style="padding: 20px; text-align: center;">
            <div style="font-size: 32px; margin-bottom: 12px;">🔄</div>
            <p>Loading...</p>
        </div>
    `;
    
    try {
        // Get current tab URL
        const tabs = await browser.tabs.query({ active: true, currentWindow: true });
        console.log('Tabs:', tabs);
        
        const currentTab = tabs[0];
        
        if (!currentTab || !currentTab.url) {
            throw new Error('No active tab found');
        }
        
        const currentUrl = currentTab.url;
        console.log('Current URL:', currentUrl);
        
        // Get scan history and statistics
        const storageData = await browser.storage.local.get(['scanHistory', 'statistics']);
        console.log('Storage data:', storageData);
        
        const scanHistory = storageData.scanHistory || [];
        const stats = storageData.statistics || { 
            safeSites: 0, 
            maliciousSites: 0, 
            suspiciousSites: 0 
        };
        
        // Analyze current URL using background script
        let currentScan = { status: 'safe', threats: [] };
        try {
            console.log('Sending analyzeUrl message...');
            const response = await browser.runtime.sendMessage({
                action: 'analyzeUrl',  // CRITICAL: This was missing in some versions
                url: currentUrl
            });
            console.log('Analysis response:', response);
            currentScan = response || { status: 'safe', threats: [] };
        } catch (error) {
            console.error('Error analyzing current URL:', error);
            // Use basic analysis as fallback
            currentScan = basicAnalyze(currentUrl);
        }
        
        console.log('Rendering UI...');
        
        // Render popup UI
        root.innerHTML = `
            <div class="extension-popup">
                <div class="header">
                    <div class="title-section">
                        <div class="icon">🛡️</div>
                        <div class="title-text">
                            <h1>Check URL</h1>
                            <p>Real-time Link Protection</p>
                        </div>
                    </div>
                    <div class="stats">
                        <span class="stat safe">Safe: ${stats.safeSites || 0}</span>
                        <span class="stat blocked">Blocked: ${stats.maliciousSites || 0}</span>
                        <span class="stat warnings">Suspicious: ${stats.suspiciousSites || 0}</span>
                    </div>
                </div>
                
                <div class="current-page">
                    <div class="section-header">
                        <span>🌐 Current Page</span>
                        <button id="scanBtn" class="scan-btn">🔍 Scan</button>
                    </div>
                    <div class="url-status ${currentScan.status}">
                        <div class="status-icon">${getStatusIcon(currentScan.status)}</div>
                        <div class="url-info">
                            <div class="url" title="${escapeHtml(currentUrl)}">${escapeHtml(truncateUrl(currentUrl, 35))}</div>
                            <div class="scan-time">Scanned just now</div>
                        </div>
                        <div class="status-badge">${getStatusBadge(currentScan.status)}</div>
                    </div>
                    
                    ${currentScan.status === 'malicious' && currentScan.threats && currentScan.threats.length > 0 ? `
                    <div style="margin-top: 12px; padding: 12px; background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px;">
                        <div style="display: flex; align-items: start; gap: 8px;">
                            <span style="font-size: 14px;">⚠️</span>
                            <div>
                                <p style="margin: 0 0 8px 0; font-size: 14px; color: #991b1b; font-weight: 500;">
                                    This page contains malicious content.
                                </p>
                                <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                                    ${currentScan.threats.map(threat => `
                                        <span style="background: #dc2626; color: white; padding: 2px 6px; border-radius: 10px; font-size: 11px;">
                                            ${escapeHtml(threat)}
                                        </span>
                                    `).join('')}
                                </div>
                            </div>
                        </div>
                    </div>
                    ` : ''}
                </div>
                
                <div style="padding: 16px; padding-top: 0;">
                    <div class="section-header">Recent Scans</div>
                    <div style="max-height: 200px; overflow-y: auto;">
                        ${scanHistory.length > 0 ? scanHistory.slice(0, 8).map(scan => `
                            <div style="display: flex; align-items: center; gap: 12px; padding: 8px; border-radius: 6px; margin-bottom: 4px; background: ${scan.status === 'malicious' ? '#fef2f2' : '#f9fafb'};">
                                <div class="status-icon">${getStatusIcon(scan.status)}</div>
                                <div style="flex: 1; min-width: 0;">
                                    <div class="url" title="${escapeHtml(scan.url)}">${escapeHtml(truncateUrl(scan.url, 30))}</div>
                                    <div style="font-size: 12px; color: #6b7280;">${formatTime(scan.timestamp)}</div>
                                </div>
                                <div class="status-badge">${getStatusBadge(scan.status)}</div>
                            </div>
                        `).join('') : '<p style="text-align: center; color: #6b7280; font-size: 14px; margin: 20px 0;">No scans yet</p>'}
                    </div>
                </div>
                
                <div class="footer">
                    <div class="status-line">
                        <span>🟢 Protection: Active</span>
                        <span>✓ Auto-scan: Enabled</span>
                    </div>
                </div>
            </div>
        `;
        
        console.log('UI rendered successfully');
        
        // Add event listener for scan button
        const scanBtn = document.getElementById('scanBtn');
        if (scanBtn) {
            scanBtn.addEventListener('click', async () => {
                scanBtn.textContent = '🔄 Scanning...';
                scanBtn.disabled = true;
                
                try {
                    await browser.tabs.sendMessage(currentTab.id, { 
                        action: 'scanCurrentPage' 
                    });
                    
                    setTimeout(() => {
                        window.location.reload();
                    }, 1500);
                } catch (error) {
                    console.error('Error sending scan message:', error);
                    scanBtn.textContent = '🔍 Scan';
                    scanBtn.disabled = false;
                }
            });
        }
        
    } catch (error) {
        console.error('Error loading popup:', error);
        root.innerHTML = `
            <div style="padding: 20px; text-align: center;">
                <div style="font-size: 32px; margin-bottom: 12px;">🛡️</div>
                <h3 style="margin: 0 0 8px 0;">Check URL Scanner</h3>
                <p style="color: #dc2626; margin: 8px 0;">Error loading extension</p>
                <p style="font-size: 12px; color: #666; margin: 8px 0; word-break: break-word;">
                    ${escapeHtml(error.message || 'Unknown error')}
                </p>
                <button onclick="window.location.reload()" style="
                    margin-top: 12px;
                    padding: 8px 16px;
                    background: #3b82f6;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 14px;
                ">Reload</button>
            </div>
        `;
    }
});

// Escape HTML to prevent injection
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Basic URL analysis fallback
function basicAnalyze(url) {
    const urlLower = url.toLowerCase();
    const threats = [];
    
    if (urlLower.match(/scam|malware|fake|phishing|virus/i)) {
        threats.push('Suspicious Pattern');
        return { status: 'malicious', threats };
    }
    
    if (urlLower.match(/bit\.ly|tinyurl|\.tk|\.ml|\.ga|\.cf/i)) {
        threats.push('Suspicious Domain');
        return { status: 'suspicious', threats };
    }
    
    return { status: 'safe', threats: [] };
}

function getStatusIcon(status) {
    switch (status) {
        case 'safe': return '🛡️';
        case 'malicious': return '🚨';
        case 'suspicious': return '⚠️';
        case 'scanning': return '🔄';
        default: return '🛡️';
    }
}

function getStatusBadge(status) {
    switch (status) {
        case 'safe': return '<span class="badge safe">Safe</span>';
        case 'malicious': return '<span class="badge malicious">Malicious</span>';
        case 'suspicious': return '<span class="badge suspicious">Suspicious</span>';
        case 'scanning': return '<span class="badge">Scanning...</span>';
        default: return '<span class="badge safe">Safe</span>';
    }
}

function truncateUrl(url, maxLength) {
    if (!url) return '';
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength) + '...';
}

function formatTime(timestamp) {
    try {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = Math.floor((now - date) / 1000);
        
        if (diff < 60) return 'Just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return date.toLocaleDateString();
    } catch (error) {
        return 'Recently';
    }
}

console.log('Popup script loaded');
