/**
 * 🔒 HealthyU Website Security Monitor
 * Client-side security monitoring and threat detection
 * Version: 1.0.0
 * Author: HealthyU Security Team
 */

(function() {
    'use strict';

    // 🛡️ SECURITY CONFIGURATION
    const SECURITY_CONFIG = {
        // Threat detection thresholds
        MAX_REQUESTS_PER_MINUTE: 100,
        MAX_SUSPICIOUS_PATTERNS: 5,
        BLOCKED_IPS: new Set(),
        
        // Monitoring intervals
        CHECK_INTERVAL: 5000, // 5 seconds
        LOG_INTERVAL: 60000,  // 1 minute
        
        // Security patterns to detect
        SUSPICIOUS_PATTERNS: [
            /<script/i,
            /javascript:/i,
            /on\w+\s*=/i,
            /eval\s*\(/i,
            /document\.cookie/i,
            /localStorage/i,
            /sessionStorage/i,
            /window\.open/i,
            /location\.href/i,
            /innerHTML/i,
            /outerHTML/i,
            /insertAdjacentHTML/i
        ],
        
        // Blocked user agents
        BLOCKED_USER_AGENTS: [
            /bot/i,
            /crawler/i,
            /spider/i,
            /scraper/i,
            /curl/i,
            /wget/i,
            /python/i,
            /nikto/i,
            /sqlmap/i,
            /nmap/i
        ]
    };

    // 🛡️ SECURITY STATE
    let securityState = {
        requestCount: 0,
        suspiciousActivities: 0,
        blockedAttempts: 0,
        lastRequestTime: Date.now(),
        threatLevel: 'LOW',
        logs: []
    };

    // 🛡️ UTILITY FUNCTIONS
    function sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        return input.replace(/[<>]/g, '').trim();
    }

    function logSecurityEvent(level, message, data = {}) {
        const event = {
            timestamp: new Date().toISOString(),
            level: level,
            message: sanitizeInput(message),
            data: data,
            userAgent: navigator.userAgent,
            url: window.location.href,
            referrer: document.referrer
        };

        securityState.logs.push(event);
        
        // Keep only last 100 logs
        if (securityState.logs.length > 100) {
            securityState.logs.shift();
        }

        // Update threat level
        updateThreatLevel();
        
        // Send to server if critical
        if (level === 'CRITICAL') {
            sendSecurityAlert(event);
        }
    }

    function updateThreatLevel() {
        const suspiciousCount = securityState.suspiciousActivities;
        const requestCount = securityState.requestCount;
        
        if (suspiciousCount > 10 || requestCount > 200) {
            securityState.threatLevel = 'CRITICAL';
        } else if (suspiciousCount > 5 || requestCount > 100) {
            securityState.threatLevel = 'HIGH';
        } else if (suspiciousCount > 2 || requestCount > 50) {
            securityState.threatLevel = 'MEDIUM';
        } else {
            securityState.threatLevel = 'LOW';
        }
    }

    function detectSuspiciousActivity() {
        // Check for suspicious patterns in URL
        const url = window.location.href;
        const queryString = window.location.search;
        
        for (const pattern of SECURITY_CONFIG.SUSPICIOUS_PATTERNS) {
            if (pattern.test(url) || pattern.test(queryString)) {
                logSecurityEvent('WARNING', 'Suspicious pattern detected in URL', {
                    pattern: pattern.toString(),
                    url: url
                });
                securityState.suspiciousActivities++;
                return true;
            }
        }

        // Check for suspicious user agent
        const userAgent = navigator.userAgent;
        for (const blockedAgent of SECURITY_CONFIG.BLOCKED_USER_AGENTS) {
            if (blockedAgent.test(userAgent)) {
                logSecurityEvent('CRITICAL', 'Blocked user agent detected', {
                    userAgent: userAgent
                });
                return true;
            }
        }

        return false;
    }

    function monitorNetworkRequests() {
        // Override fetch to monitor requests
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            securityState.requestCount++;
            securityState.lastRequestTime = Date.now();
            
            // Check for suspicious requests
            const url = args[0];
            if (typeof url === 'string' && url.includes('javascript:')) {
                logSecurityEvent('CRITICAL', 'Suspicious fetch request detected', {
                    url: url
                });
                securityState.blockedAttempts++;
                return Promise.reject(new Error('Blocked suspicious request'));
            }
            
            return originalFetch.apply(this, args);
        };

        // Override XMLHttpRequest
        const originalXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, ...args) {
            securityState.requestCount++;
            
            if (typeof url === 'string' && url.includes('javascript:')) {
                logSecurityEvent('CRITICAL', 'Suspicious XHR request detected', {
                    url: url,
                    method: method
                });
                securityState.blockedAttempts++;
                return;
            }
            
            return originalXHROpen.apply(this, [method, url, ...args]);
        };
    }

    function monitorDOMChanges() {
        // Monitor for suspicious DOM modifications
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            const element = node;
                            
                            // Check for suspicious attributes
                            const suspiciousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover'];
                            for (const attr of suspiciousAttrs) {
                                if (element.hasAttribute(attr)) {
                                    logSecurityEvent('WARNING', 'Suspicious DOM attribute detected', {
                                        attribute: attr,
                                        element: element.tagName
                                    });
                                    securityState.suspiciousActivities++;
                                }
                            }
                            
                            // Check for script tags
                            if (element.tagName === 'SCRIPT') {
                                logSecurityEvent('CRITICAL', 'Dynamic script tag detected', {
                                    src: element.src,
                                    content: element.textContent.substring(0, 100)
                                });
                                securityState.suspiciousActivities++;
                            }
                        }
                    });
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    function monitorKeyboardEvents() {
        // Monitor for suspicious keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            const suspiciousCombos = [
                { ctrl: true, shift: true, key: 'I' }, // Developer tools
                { ctrl: true, shift: true, key: 'J' }, // Developer tools
                { ctrl: true, shift: true, key: 'C' }, // Developer tools
                { f12: true }, // F12
                { ctrl: true, key: 'U' }, // View source
                { ctrl: true, key: 'S' }  // Save page
            ];

            for (const combo of suspiciousCombos) {
                if (combo.ctrl && e.ctrlKey && combo.shift && e.shiftKey && e.key === combo.key ||
                    combo.f12 && e.key === 'F12' ||
                    combo.ctrl && e.ctrlKey && !combo.shift && e.key === combo.key) {
                    
                    logSecurityEvent('INFO', 'Suspicious keyboard shortcut detected', {
                        key: e.key,
                        ctrl: e.ctrlKey,
                        shift: e.shiftKey
                    });
                }
            }
        });
    }

    function monitorConsoleAccess() {
        // Detect console access attempts
        const originalConsole = {
            log: console.log,
            warn: console.warn,
            error: console.error,
            info: console.info
        };

        Object.keys(originalConsole).forEach(method => {
            console[method] = function(...args) {
                logSecurityEvent('INFO', `Console ${method} accessed`, {
                    arguments: args.map(arg => String(arg).substring(0, 50))
                });
                return originalConsole[method].apply(console, args);
            };
        });
    }

    function sendSecurityAlert(event) {
        // Send security alert to server
        try {
            fetch('/api/security-alert', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Security-Token': generateSecurityToken()
                },
                body: JSON.stringify(event)
            }).catch(() => {
                // Silently fail if server is not available
            });
        } catch (error) {
            // Silently fail
        }
    }

    function generateSecurityToken() {
        // Generate a simple security token
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(2);
        return btoa(`${timestamp}:${random}:${navigator.userAgent}`);
    }

    function startPeriodicChecks() {
        setInterval(() => {
            // Check for suspicious activity
            detectSuspiciousActivity();
            
            // Reset counters if needed
            const now = Date.now();
            if (now - securityState.lastRequestTime > 60000) {
                securityState.requestCount = Math.max(0, securityState.requestCount - 10);
            }
            
            // Log security state periodically
            if (securityState.logs.length > 0) {
                const recentLogs = securityState.logs.slice(-10);
                logSecurityEvent('INFO', 'Security state update', {
                    threatLevel: securityState.threatLevel,
                    requestCount: securityState.requestCount,
                    suspiciousActivities: securityState.suspiciousActivities,
                    blockedAttempts: securityState.blockedAttempts
                });
            }
        }, SECURITY_CONFIG.CHECK_INTERVAL);
    }

    function initializeSecurityMonitor() {
        // Start all monitoring functions
        monitorNetworkRequests();
        monitorDOMChanges();
        monitorKeyboardEvents();
        monitorConsoleAccess();
        startPeriodicChecks();
        
        // Initial security check
        detectSuspiciousActivity();
        
        logSecurityEvent('INFO', 'Security monitor initialized', {
            config: SECURITY_CONFIG,
            timestamp: new Date().toISOString()
        });
    }

    // 🛡️ INITIALIZE SECURITY MONITOR
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeSecurityMonitor);
    } else {
        initializeSecurityMonitor();
    }

    // 🛡️ EXPOSE SECURITY API (for debugging)
    window.HealthyUSecurity = {
        getState: () => ({ ...securityState }),
        getConfig: () => ({ ...SECURITY_CONFIG }),
        getLogs: () => [...securityState.logs],
        resetCounters: () => {
            securityState.requestCount = 0;
            securityState.suspiciousActivities = 0;
            securityState.blockedAttempts = 0;
        }
    };

})(); 
