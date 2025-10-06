// Enhanced content script - automatic link scanning and protection
(function() {
    'use strict';
    
    let warningPopup = null;
    let settings = {
        realTimeScanning: true,
        showWarningPopups: true,
        blockMaliciousLinks: true,
        scanOnPageLoad: true,
        autoHighlightLinks: true
    };
    
    // Enhanced threat patterns
    const maliciousPatterns = [
        /free[-_]?iphone/i, /scam/i, /malware/i, /fake[-_]?bank/i,
        /suspicious[-_]?download/i, /claim[-_]?now/i, /win[-_]?money/i,
        /urgent[-_]?action/i, /verify[-_]?account/i, /fake[-_]?antivirus/i,
        /prize[-_]?winner/i, /crypto[-_]?giveaway/i, /tech[-_]?support/i,
        /click[-_]?here[-_]?free/i, /security[-_]?alert/i, /computer[-_]?infected/i
    ];
    
    const suspiciousDomains = [
        /bit\.ly/i, /tinyurl\.com/i, /\.tk$/i, /\.ml$/i, /\.ga$/i, /\.cf$/i
    ];
    
    // Initialize
    loadSettingsAndInit();
    
    async function loadSettingsAndInit() {
        try {
            const result = await browser.storage.local.get(['extensionSettings']);
            if (result.extensionSettings) {
                settings = { ...settings, ...result.extensionSettings };
            }
        } catch (error) {
            console.error('CheckURL: Error loading settings:', error);
        }
        
        if (settings.scanOnPageLoad) {
            setTimeout(() => {
                scanAndMarkAllLinks();
                scanCurrentPageURL();
            }, 1000);
            setupLinkMonitoring();
        }
    }
    
    function scanCurrentPageURL() {
        const currentUrl = window.location.href;
        const scanResult = analyzeUrl(currentUrl);
        
        if (scanResult.status === 'malicious' || scanResult.status === 'suspicious') {
            showPageWarning(currentUrl, scanResult);
        }
        
        storeScanResult(currentUrl, scanResult);
    }
    
    function showPageWarning(url, scanResult) {
        const existingBanner = document.querySelector('.checkurl-page-warning');
        if (existingBanner) existingBanner.remove();
        
        const banner = document.createElement('div');
        banner.className = 'checkurl-page-warning';
        banner.innerHTML = `
            <div class="checkurl-warning-content">
                <div class="checkurl-warning-icon">⚠️</div>
                <div class="checkurl-warning-text">
                    <strong>Warning: This page may be dangerous</strong>
                    <br>Detected threats: ${scanResult.threats ? scanResult.threats.join(', ') : 'Suspicious content'}
                </div>
                <button class="checkurl-close-banner">×</button>
            </div>
        `;
        
        banner.style.cssText = `
            position: fixed !important; top: 0 !important; left: 0 !important; right: 0 !important;
            background: #fef2f2 !important; border-bottom: 2px solid #fca5a5 !important;
            z-index: 999999 !important; font-family: system-ui, -apple-system, sans-serif !important;
        `;
        
        banner.querySelector('.checkurl-warning-content').style.cssText = `
            display: flex !important; align-items: center !important; padding: 12px 20px !important; gap: 12px !important;
        `;
        
        banner.querySelector('.checkurl-close-banner').addEventListener('click', () => banner.remove());
        document.body.insertBefore(banner, document.body.firstChild);
    }
    
    function setupLinkMonitoring() {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        if (node.tagName === 'A' && node.href) {
                            processLink(node);
                        }
                        const links = node.querySelectorAll ? node.querySelectorAll('a[href]') : [];
                        links.forEach(link => processLink(link));
                    }
                });
            });
        });
        
        observer.observe(document.body, { childList: true, subtree: true });
    }
    
    function scanAndMarkAllLinks() {
        const links = document.querySelectorAll('a[href]');
        console.log(`CheckURL: Scanning ${links.length} links on page`);
        links.forEach(link => processLink(link));
    }
    
    function processLink(link) {
        if (!link.href || link.getAttribute('data-checkurl-processed')) return;
        
        const url = link.href;
        const scanResult = analyzeUrl(url);
        
        link.setAttribute('data-checkurl-processed', 'true');
        
        if (scanResult.status === 'malicious' || scanResult.status === 'suspicious') {
            markDangerousLink(link, scanResult);
        } 
        storeScanResult(url, scanResult);
    }
    
    function markDangerousLink(link, scanResult) {
        const isMalicious = scanResult.status === 'malicious';
        
        link.style.cssText += `
            outline: 2px solid ${isMalicious ? '#dc2626' : '#eab308'} !important;
            outline-offset: 1px !important;
            background-color: ${isMalicious ? 'rgba(220, 38, 38, 0.1)' : 'rgba(234, 179, 8, 0.1)'} !important;
            position: relative !important;
        `;
        
        const warningIcon = document.createElement('span');
        warningIcon.innerHTML = isMalicious ? '🚨' : '⚠️';
        warningIcon.style.cssText = `
            font-size: 12px !important; margin-left: 4px !important; opacity: 0.9 !important;
        `;
        
        if (!link.querySelector('.checkurl-warning-icon')) {
            warningIcon.className = 'checkurl-warning-icon';
            link.appendChild(warningIcon);
        }
        
        link.setAttribute('data-checkurl-status', scanResult.status);
        link.setAttribute('data-checkurl-threats', JSON.stringify(scanResult.threats || []));
        
        if (settings.showWarningPopups) {
            link.addEventListener('mouseenter', (e) => showHoverWarning(e, link, scanResult));
            link.addEventListener('mouseleave', hideHoverWarning);
        }
        
        link.addEventListener('click', (e) => handleDangerousClick(e, link, scanResult));
    }
 
    function showHoverWarning(event, link, scanResult) {
        hideHoverWarning();
        
        const rect = link.getBoundingClientRect();
        const x = rect.left + window.scrollX;
        const y = rect.bottom + window.scrollY;
        
        createWarningPopup(link.href, scanResult.threats || [], x + rect.width / 2, y - 50, scanResult.status);
    }
    
    function hideHoverWarning() {
        if (warningPopup) {
            warningPopup.remove();
            warningPopup = null;
        }
    }
    
    function handleDangerousClick(event, link, scanResult) {
        if (settings.blockMaliciousLinks && scanResult.status === 'malicious') {
            event.preventDefault();
            event.stopPropagation();
            showClickWarningDialog(link.href, scanResult);
        } else if (scanResult.status === 'suspicious') {
            event.preventDefault();
            event.stopPropagation();
            showClickWarningDialog(link.href, scanResult, true);
        }
    }
    
    function showClickWarningDialog(url, scanResult, allowProceed = false) {
        const modal = document.createElement('div');
        modal.className = 'checkurl-modal-overlay';
        modal.style.cssText = `
            position: fixed !important; top: 0 !important; left: 0 !important; right: 0 !important; bottom: 0 !important;
            background: rgba(0, 0, 0, 0.5) !important; display: flex !important; align-items: center !important;
            justify-content: center !important; z-index: 1000000 !important; font-family: system-ui, -apple-system, sans-serif !important;
        `;
        
        const dialog = document.createElement('div');
        dialog.style.cssText = `
            background: white !important; border-radius: 8px !important; padding: 24px !important;
            max-width: 500px !important; margin: 20px !important; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1) !important;
        `;
        
        dialog.innerHTML = `
            <div style="display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px;">
                <div style="font-size: 24px;">${scanResult.status === 'malicious' ? '🚨' : '⚠️'}</div>
                <div style="flex: 1;">
                    <h3 style="margin: 0; color: #dc2626; font-size: 18px; font-weight: 600;">
                        ${scanResult.status === 'malicious' ? 'Dangerous Link Detected' : 'Suspicious Link Warning'}
                    </h3>
                    <p style="margin: 8px 0; color: #374151;">
                        This link has been flagged as potentially ${scanResult.status === 'malicious' ? 'dangerous' : 'suspicious'}.
                    </p>
                </div>
            </div>
            
            <div style="background: #fef2f2; padding: 12px; border-radius: 6px; margin-bottom: 16px;">
                <p style="margin: 0; font-size: 12px; color: #991b1b; word-break: break-all;">
                    <strong>URL:</strong> ${url}
                </p>
            </div>
            
            ${scanResult.threats && scanResult.threats.length > 0 ? `
                <div style="margin-bottom: 16px;">
                    <p style="margin: 0 0 8px 0; font-size: 14px; color: #374151;">
                        <strong>Detected threats:</strong>
                    </p>
                    <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                        ${scanResult.threats.map(threat => `
                            <span style="background: #dc2626; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px;">
                                ${threat}
                            </span>
                        `).join('')}
                    </div>
                </div>
            ` : ''}
            
            <div style="display: flex; gap: 12px; justify-content: flex-end;">
                <button class="checkurl-stay-safe" style="
                    padding: 8px 16px; background: #dc2626; color: white; border: none; 
                    border-radius: 6px; cursor: pointer; font-weight: 500;
                ">Stay Safe</button>
                ${allowProceed || scanResult.status !== 'malicious' ? `
                    <button class="checkurl-proceed" style="
                        padding: 8px 16px; background: transparent; color: #dc2626; 
                        border: 1px solid #dc2626; border-radius: 6px; cursor: pointer; font-weight: 500;
                    ">Proceed Anyway</button>
                ` : ''}
            </div>
        `;
        
        modal.appendChild(dialog);
        document.body.appendChild(modal);
        
        dialog.querySelector('.checkurl-stay-safe').addEventListener('click', () => modal.remove());
        
        const proceedBtn = dialog.querySelector('.checkurl-proceed');
        if (proceedBtn) {
            proceedBtn.addEventListener('click', () => {
                modal.remove();
                window.open(url, '_blank');
            });
        }
        
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.remove();
        });
    }
    
    function createWarningPopup(url, threats, x, y, status = 'malicious') {
        hideHoverWarning();
        
        warningPopup = document.createElement('div');
        warningPopup.className = 'checkurl-hover-warning';
        warningPopup.innerHTML = `
            <div class="warning-content">
                <div class="warning-header">
                    <div class="warning-icon">${status === 'malicious' ? '🚨' : '⚠️'}</div>
                    <div class="warning-title">${status === 'malicious' ? 'Malicious Link' : 'Suspicious Link'}</div>
                </div>
                <div class="warning-body">
                    <p class="warning-text">This link has been flagged as ${status}.</p>
                    <div class="warning-url">${url}</div>
                    ${threats.length > 0 ? `
                        <div class="warning-threats">
                            ${threats.map(threat => `<span class="threat-badge">${threat}</span>`).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
        
        warningPopup.style.cssText = `
            position: absolute !important; width: 300px !important; background: #fef2f2 !important;
            border: 2px solid #fca5a5 !important; border-radius: 8px !important;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3) !important; font-family: system-ui, -apple-system, sans-serif !important;
            font-size: 14px !important; z-index: 999999 !important;
            left: ${Math.min(x, window.innerWidth - 320)}px !important;
            top: ${Math.max(y - 120, 10)}px !important;
        `;
        
        document.body.appendChild(warningPopup);
        
        setTimeout(() => {
            if (warningPopup) {
                warningPopup.remove();
                warningPopup = null;
            }
        }, 5000);
    }
    
    function analyzeUrl(url) {
        try {
            const threats = [];
            let status = 'safe';
            
            for (const pattern of maliciousPatterns) {
                if (pattern.test(url)) {
                    status = 'malicious';
                    if (url.match(/scam/i)) threats.push('Scam');
                    if (url.match(/malware/i)) threats.push('Malware');
                    if (url.match(/fake[-_]?bank/i)) threats.push('Identity Theft');
                    if (url.match(/crypto[-_]?giveaway/i)) threats.push('Cryptocurrency Scam');
                    if (url.match(/tech[-_]?support/i)) threats.push('Tech Support Scam');
                    break;
                }
            }
            
            if (status === 'safe') {
                for (const pattern of suspiciousDomains) {
                    if (pattern.test(url)) {
                        status = 'suspicious';
                        threats.push('Suspicious Domain');
                        break;
                    }
                }
            }
            
            return {
                status,
                threats: threats.length > 0 ? [...new Set(threats)] : undefined,
                timestamp: new Date().toISOString()
            };
            
        } catch (error) {
            console.error('CheckURL: Error analyzing URL:', error);
            return { status: 'safe', threats: [], timestamp: new Date().toISOString() };
        }
    }
    
    function storeScanResult(url, scanResult) {
        try {
            browser.storage.local.get(['scanHistory']).then(result => {
                const history = result.scanHistory || [];
                const scanItem = {
                    id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
                    url: url,
                    status: scanResult.status,
                    timestamp: scanResult.timestamp,
                    threats: scanResult.threats
                };
                
                history.unshift(scanItem);
                if (history.length > 200) history.splice(200);
                
                browser.storage.local.set({ scanHistory: history });
            });
        } catch (error) {
            console.error('CheckURL: Error storing scan result:', error);
        }
    }
    
    // Listen for messages
    browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === 'scanCurrentPage') {
            scanAndMarkAllLinks();
            scanCurrentPageURL();
            sendResponse({ success: true });
        } else if (message.action === 'getCurrentPageUrl') {
            sendResponse({ url: window.location.href });
        }
    });
    
    console.log('CheckURL: Enhanced content script loaded');
    
})();