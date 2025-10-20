// Content script - compatible with OpenAI-powered analysis
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
    
    const processedLinks = new Set();
    const analysisCache = new Map();
    
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
    
    async function scanCurrentPageURL() {
        const currentUrl = window.location.href;
        
        try {
            const scanResult = await analyzeUrlWithBackend(currentUrl);
            
            if (scanResult.status === 'malicious' || scanResult.status === 'suspicious') {
                showPageWarning(currentUrl, scanResult);
            }
            
            storeScanResult(currentUrl, scanResult);
        } catch (error) {
            console.error('CheckURL: Error scanning current page:', error);
        }
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
                    <strong>⚠️ Warning: This page may be dangerous</strong>
                    <br>${scanResult.reasoning || `Detected threats: ${scanResult.threats ? scanResult.threats.join(', ') : 'Suspicious content'}`}
                    ${scanResult.aiPowered ? '<br><small>🤖 AI-powered analysis</small>' : ''}
                </div>
                <button class="checkurl-close-banner">×</button>
            </div>
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
        
        // Process links in batches to avoid overwhelming the API
        let index = 0;
        const batchSize = 5;
        
        function processBatch() {
            const batch = Array.from(links).slice(index, index + batchSize);
            batch.forEach(link => processLink(link));
            
            index += batchSize;
            if (index < links.length) {
                setTimeout(processBatch, 1000); // 1 second delay between batches
            }
        }
        
        processBatch();
    }
    
    async function processLink(link) {
        if (!link.href || processedLinks.has(link.href)) return;
        
        const url = link.href;
        processedLinks.add(url);
        
        // Check cache first
        if (analysisCache.has(url)) {
            const cachedResult = analysisCache.get(url);
            applyLinkMarking(link, cachedResult);
            return;
        }
        
        try {
            const scanResult = await analyzeUrlWithBackend(url);
            analysisCache.set(url, scanResult);
            
            if (scanResult.status === 'malicious' || scanResult.status === 'suspicious') {
                applyLinkMarking(link, scanResult);
            }
            
            storeScanResult(url, scanResult);
        } catch (error) {
            console.error('CheckURL: Error processing link:', error);
        }
    }
    
    function applyLinkMarking(link, scanResult) {
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
        link.setAttribute('data-checkurl-ai', scanResult.aiPowered ? 'true' : 'false');
        
        if (settings.showWarningPopups) {
            link.addEventListener('mouseenter', (e) => showHoverWarning(e, link, scanResult));
            link.addEventListener('mouseleave', hideHoverWarning);
        }
        
        link.addEventListener('click', (e) => handleDangerousClick(e, link, scanResult));
    }
    
    async function analyzeUrlWithBackend(url) {
        try {
            const response = await browser.runtime.sendMessage({
                action: 'analyzeUrl',
                url: url
            });
            
            return response;
        } catch (error) {
            console.error('CheckURL: Error communicating with background:', error);
            return { status: 'safe', threats: [], confidence: 0 };
        }
    }
    
    function showHoverWarning(event, link, scanResult) {
        hideHoverWarning();
        
        const rect = link.getBoundingClientRect();
        const x = rect.left + window.scrollX;
        const y = rect.bottom + window.scrollY;
        
        createWarningPopup(link.href, scanResult, x + rect.width / 2, y - 50);
    }
    
    function hideHoverWarning() {
        if (warningPopup) {
            warningPopup.remove();
            warningPopup = null;
        }
    }
    
    function createWarningPopup(url, scanResult, x, y) {
        hideHoverWarning();
        
        const status = scanResult.status;
        const threats = scanResult.threats || [];
        
        warningPopup = document.createElement('div');
        warningPopup.className = 'checkurl-hover-warning';
        warningPopup.innerHTML = `
            <div class="warning-content">
                <div class="warning-header">
                    <div class="warning-icon">${status === 'malicious' ? '🚨' : '⚠️'}</div>
                    <div class="warning-title">${status === 'malicious' ? 'Malicious Link' : 'Suspicious Link'}</div>
                </div>
                <div class="warning-body">
                    <p class="warning-text">${scanResult.reasoning || 'This link has been flagged as ' + status + '.'}</p>
                    <div class="warning-url">${url}</div>
                    ${threats.length > 0 ? `
                        <div class="warning-threats">
                            ${threats.map(threat => `<span class="threat-badge">${threat}</span>`).join('')}
                        </div>
                    ` : ''}
                    ${scanResult.aiPowered ? '<p style="font-size: 11px; color: #666; margin-top: 8px;">🤖 AI-powered analysis</p>' : ''}
                </div>
            </div>
        `;
        
        warningPopup.style.cssText = `
            position: absolute !important; width: 320px !important; background: #fef2f2 !important;
            border: 2px solid #fca5a5 !important; border-radius: 8px !important;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3) !important; font-family: system-ui, -apple-system, sans-serif !important;
            font-size: 14px !important; z-index: 999999 !important;
            left: ${Math.min(x, window.innerWidth - 340)}px !important;
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
                        ${scanResult.reasoning || 'This link has been flagged as potentially ' + scanResult.status + '.'}
                    </p>
                    ${scanResult.aiPowered ? '<p style="margin: 4px 0; font-size: 12px; color: #666;">🤖 AI-powered analysis</p>' : ''}
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
    
    function storeScanResult(url, scanResult) {
        try {
            browser.storage.local.get(['scanHistory']).then(result => {
                const history = result.scanHistory || [];
                const scanItem = {
                    id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
                    url: url,
                    status: scanResult.status,
                    timestamp: scanResult.timestamp || new Date().toISOString(),
                    threats: scanResult.threats,
                    aiPowered: scanResult.aiPowered || false
                };
                
                history.unshift(scanItem);
                if (history.length > 200) history.splice(200);
                
                browser.storage.local.set({ scanHistory: history });
            });
        } catch (error) {
            console.error('CheckURL: Error storing scan result:', error);
        }
    }
    
    browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === 'scanCurrentPage') {
            scanAndMarkAllLinks();
            scanCurrentPageURL();
            sendResponse({ success: true });
        } else if (message.action === 'getCurrentPageUrl') {
            sendResponse({ url: window.location.href });
        }
    });
    
    console.log('CheckURL: Content script loaded with OpenAI integration');
    
})();
