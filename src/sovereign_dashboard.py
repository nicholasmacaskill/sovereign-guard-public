import os
import re
import sys
from datetime import datetime
from flask import Flask, jsonify, render_template_string
import path_utils

# TODO: REFACTOR Technical Debt
# Move HTML/CSS templates to a dedicated templates/ directory.
# Decompose this file into API routes and UI rendering modules.

app = Flask(__name__)

# Constants (Now using path_utils)
LOG_FILE = path_utils.get_log_file('guard_monitor.log')
WHITELIST_FILE = path_utils.get_config_file('whitelist.json')
LEARNING_LOG = path_utils.get_config_file('.learning_log.json')

# HTML Template (Cyberpunk/Terminal Style)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sovereign Guard Mission Control</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

        :root {
            --bg-gradient: radial-gradient(circle at 50% -20%, #1a2a40, #050505 80%);
            --glass-bg: rgba(20, 30, 50, 0.4);
            --glass-border: rgba(255, 255, 255, 0.1);
            --glass-highlight: rgba(255, 255, 255, 0.15);
            --text-primary: #e0f2ff;
            --text-secondary: #7a8ba0;
            --accent-green: #00ff9d;
            --accent-red: #ff3333;
            --accent-yellow: #ffcc00;
            --font-tech: 'Share Tech Mono', monospace;
        }
        body {
            background: var(--bg-gradient);
            color: var(--text-primary);
            font-family: var(--font-tech);
            margin: 0;
            padding: 20px; /* Reduced padding */
            height: 100vh;
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
            overflow: hidden; /* Prevent body scroll */
            letter-spacing: 0.5px;
        }
        /* Noise texture covers everything */
        /* Add subtle noise texture */
        body::before {
            content: "";
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)' opacity='0.05'/%3E%3C/svg%3E");
            pointer-events: none;
            z-index: -1;
        }

        .stat-card, .log-container {
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-top: 1px solid var(--glass-highlight);
            border-left: 1px solid var(--glass-highlight);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.5);
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--glass-border);
            padding-bottom: 20px;
            margin-bottom: 40px;
            backdrop-filter: blur(10px);
        }
        .title {
            font-size: 24px;
            font-weight: 200;
            display: flex;
            align-items: center;
            gap: 15px;
            letter-spacing: 1px;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            background-color: var(--accent-green);
            border-radius: 50%;
            box-shadow: 0 0 15px var(--accent-green);
            animation: pulse 3s infinite;
        }
        @keyframes pulse {
            0% { opacity: 0.8; box-shadow: 0 0 5px var(--accent-green); }
            50% { opacity: 0.4; box-shadow: 0 0 20px var(--accent-green); }
            100% { opacity: 0.8; box-shadow: 0 0 5px var(--accent-green); }
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            padding: 25px;
            border-radius: 16px;
            border: 1px solid var(--glass-border);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
            transition: transform 0.2s;
        }
        .stat-card:hover {
            transform: translateY(-2px);
            background: rgba(255, 255, 255, 0.05);
        }
        .stat-value {
            font-size: 42px;
            font-weight: 300;
            color: var(--text-primary);
            margin-bottom: 5px;
        }
        .stat-label {
            color: var(--text-secondary);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 2px;
            font-weight: 600;
        }
        .log-container {
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-top: 1px solid var(--glass-highlight);
            border-left: 1px solid var(--glass-highlight);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.5);
            /* Layout Fixes */
            flex-grow: 1; /* Fill remaining vertical space */
            display: flex;
            flex-direction: column;
            overflow: hidden;
            min-height: 0; /* Crucial for nested flex scroll */
        }
        .log-header {
            background: rgba(0, 0, 0, 0.2);
            padding: 15px 25px;
            font-weight: 500;
            border-bottom: 1px solid var(--glass-border);
            display: flex;
            justify-content: space-between;
            color: var(--text-secondary);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
            flex-shrink: 0; /* Header stays fixed */
        }
        .log-list {
            list-style: none;
            padding: 0;
            margin: 0;
            overflow-y: auto; /* Scroll ONLY the list */
            flex-grow: 1;
        }
        .log-item {
            padding: 18px 30px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            display: grid;
            grid-template-columns: 160px 1fr 140px;
            gap: 20px;
            align-items: center;
            font-family: var(--font-mono);
            font-size: 13px;
            transition: background 0.2s;
        }
        .log-item:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }
        .timestamp {
            color: #666;
            font-variant-numeric: tabular-nums;
        }
        .message {
            color: var(--text-primary);
            line-height: 1.4;
        }
        .risk-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: 600;
            text-align: center;
            font-size: 10px;
            letter-spacing: 0.5px;
            backdrop-filter: blur(4px);
        }
        .risk-critical {
            background: rgba(255, 77, 77, 0.1);
            color: var(--accent-red);
            border: 1px solid rgba(255, 77, 77, 0.2);
            box-shadow: 0 0 10px rgba(255, 77, 77, 0.05);
        }
        .risk-warning {
            background: rgba(255, 204, 0, 0.1);
            color: var(--accent-yellow);
            border: 1px solid rgba(255, 204, 0, 0.2);
        }
        .risk-info {
            background: rgba(0, 255, 157, 0.05);
            color: var(--accent-green);
            border: 1px solid rgba(0, 255, 157, 0.1);
        }
        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 6px;
        }
        ::-webkit-scrollbar-track {
            background: transparent;
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        .whitelist-btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--glass-border);
            color: var(--text-secondary);
            padding: 5px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 10px;
            font-family: -apple-system, sans-serif;
            font-weight: 600;
            letter-spacing: 0.5px;
            margin-right: 15px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .whitelist-btn:hover {
            border-color: var(--accent-green);
            color: #000;
            background: var(--accent-green);
            box-shadow: 0 0 15px rgba(0, 255, 157, 0.3);
            transform: translateY(-1px);
        }
        .sync-btn {
            background: rgba(0, 255, 157, 0.1);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 11px;
            font-family: var(--font-tech);
            font-weight: 600;
            letter-spacing: 1px;
            transition: all 0.3s;
        }
        .sync-btn:hover {
            background: var(--accent-green);
            color: #000;
            box-shadow: 0 0 20px rgba(0, 255, 157, 0.4);
        }
        .sync-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        .spinning {
            display: inline-block;
            animation: spin 1s linear infinite;
        }
        .mode-badge {
            background: rgba(0, 255, 157, 0.15);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1px;
            margin-left: 15px;
        }
        .mode-badge.warn {
            background: rgba(255, 204, 0, 0.15);
            border-color: var(--accent-yellow);
            color: var(--accent-yellow);
        }
        .mode-badge.protect {
            background: rgba(255, 77, 77, 0.15);
            border-color: var(--accent-red);
            color: var(--accent-red);
        }
        .learning-banner {
            background: rgba(0, 255, 157, 0.05);
            border: 1px solid rgba(0, 255, 157, 0.2);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .action-btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--glass-border);
            color: var(--text-primary);
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-family: var(--font-tech);
            letter-spacing: 1px;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .action-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: var(--text-primary);
        }
        .action-btn.primary {
            border-color: var(--accent-green);
            color: var(--accent-green);
        }
        .action-btn.primary:hover {
            background: var(--accent-green);
            color: #000;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(10px);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .modal-content {
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            padding: 40px;
            border-radius: 20px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            position: relative;
        }
        .close-modal {
            position: absolute;
            top: 20px;
            right: 20px;
            cursor: pointer;
            opacity: 0.5;
        }
        .close-modal:hover { opacity: 1; }
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 14px;
            color: var(--accent-green);
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="title">
            <div class="status-dot"></div>
            Sovereign Guard // MISSION CONTROL
            <span id="mode-badge" class="mode-badge">LEARN</span>
        </div>
        <div style="display: flex; gap: 20px; align-items: center;">
            <div style="color: var(--text-secondary);">Last Active: <span id="last-active" style="color: var(--accent-green);">--:--:--</span></div>
            <div style="color: var(--text-secondary);">System Status: <span style="color: var(--accent-green);">SECURE</span></div>
            <button onclick="syncNow()" class="sync-btn" id="sync-btn">
                <span id="sync-icon">⟳</span> SYNC NOW
            </button>
        </div>
    </div>

    <div id="learning-banner" class="learning-banner" style="display: none;">
        <div style="flex-grow: 1;">
            <div style="font-weight: 600; margin-bottom: 5px;">🎓 Learning Phase: Active</div>
            <div style="font-size: 12px; opacity: 0.8;" id="learning-progress">Observing your behavior to build a whitelist...</div>
        </div>
        <button onclick="bootstrap()" class="action-btn primary">
            🚀 BOOTSTRAP INTELLIGENCE
        </button>
    </div>

    <div class="stats-grid">
        <div class="stat-card" id="trust-score-card" style="cursor: default; grid-column: span 1;">
            <div class="stat-value" id="trust-score" style="font-size: 56px;">--</div>
            <div class="stat-label">TRUST SCORE <span id="trust-grade" style="font-size: 10px; opacity: 0.7;"></span></div>
        </div>
        <div class="stat-card" onclick="showReport()" style="cursor: pointer;">
            <div class="stat-value" id="count-threats">0</div>
            <div class="stat-label">Neutralized (View Report)</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="learning-obs-count">0</div>
            <div class="stat-label">Observations (<span id="count-scans">Active</span>)</div>
        </div>
        <div class="stat-card">
            <div style="display: flex; flex-direction: column; gap: 10px;">
                <button onclick="restartMonitor()" class="action-btn" style="width: 100%; border: none; background: rgba(0,255,157,0.1); color: var(--accent-green);">⟳ RESTART GUARD</button>
                <button onclick="showReport()" class="action-btn" style="width: 100%; border: none; background: rgba(255,255,255,0.05);">☰ VIEW BRIEFING</button>
            </div>
        </div>
    </div>

    <div id="modal" class="modal">
        <div class="modal-content">
            <span class="close-modal" onclick="closeModal()">✕ CLOSE</span>
            <div id="report-content">
                <pre id="briefing-text">Loading technical briefing...</pre>
            </div>
        </div>
    </div>

    <div class="log-container">
        <div class="log-header">
            <span>Event Log</span>
            <span style="font-size: 12px; color: var(--text-secondary);">Auto-refreshing...</span>
        </div>
        <ul class="log-list" id="log-list">
            <!-- Items injected by JS -->
        </ul>
    </div>

    <script>
        async function fetchLogs() {
            try {
                const response = await fetch('/api/logs');
                const data = await response.json();
                
                const list = document.getElementById('log-list');
                list.innerHTML = ''; // Clear current

                let threats = 0;
                let scans = 0;

                data.logs.forEach(log => {
                    const li = document.createElement('li');
                    li.className = 'log-item';
                    
                    // Parse Severity
                    let badgeClass = 'risk-info';
                    let badgeText = 'INFO';
                    let actionHtml = '';
                    
                    if (log.message.includes('SECURITY ALERT') || log.message.includes('THREAT')) {
                        badgeClass = 'risk-critical';
                        badgeText = 'THREAT';
                        threats++;
                        
                        // Extract Process Name for Whitelisting
                        const match = log.message.match(/Process '([^']+)'/);
                        const procName = match ? match[1] : null;
                        
                        actionHtml = `<div style="display:flex; gap:10px;">`;
                        if (procName) {
                            actionHtml += `<button onclick="whitelist('${procName}')" class="whitelist-btn">WHITELIST</button>`;
                        }
                        actionHtml += `<button onclick="viewForensics('${btoa(log.message)}')" class="whitelist-btn" style="background:rgba(0,255,157,0.1); border-color:var(--accent-green);">AI ANALYSIS</button>`;
                        actionHtml += `</div>`;
                    } else if (log.message.includes('WARNING')) {
                        badgeClass = 'risk-warning';
                        badgeText = 'WARNING';
                    } else if (log.message.includes('scans') || log.message.includes('Scanned')) {
                        scans++;
                    }

                    // Clean Message
                    let cleanMsg = log.message.replace('WARNING - ', '').replace('INFO - ', '');
                    
                    li.innerHTML = `
                        <span class="timestamp">${log.timestamp}</span>
                        <div style="display:flex; justify-content:space-between; align-items:center; width:100%">
                            <span class="message">${cleanMsg}</span>
                            ${actionHtml}
                        </div>
                        <span class="risk-badge ${badgeClass}">${badgeText}</span>
                    `;
                    list.appendChild(li);
                });

                // Update Stats
                document.getElementById('count-threats').innerText = threats;
                document.getElementById('count-scans').innerText = "Active"; 
                if (data.logs.length > 0) {
                     document.getElementById('last-active').innerText = data.logs[0].timestamp.split(' ')[1];
                }

            } catch (e) {
                console.error("Failed to fetch logs", e);
            }
        }

        async function whitelist(procName) {
            if (!confirm(`Are you sure you want to whitelist '${procName}'? This will allow it to run securely.`)) return;
            
            try {
                const res = await fetch('/api/whitelist', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({process: procName})
                });
                const result = await res.json();
                if (result.success) {
                    alert("✅ " + result.message);
                } else {
                    alert("❌ Error: " + result.error);
                }
            } catch (e) {
                alert("❌ Network Error");
            }
        }

        async function syncNow() {
            const btn = document.getElementById('sync-btn');
            const icon = document.getElementById('sync-icon');
            
            btn.disabled = true;
            icon.classList.add('spinning');
            
            try {
                const res = await fetch('/api/sync', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({force: true})
                });
                const result = await res.json();
                
                if (result.success) {
                    if (result.new_count > 0) {
                        alert(`✅ ${result.message}\n\nNew processes:\n${result.new_processes.join(', ')}`);
                    } else {
                        alert("✅ " + result.message);
                    }
                } else {
                    alert("⚠️ " + result.message);
                }
            } catch (e) {
                alert("❌ Sync failed: Network error");
            } finally {
                btn.disabled = false;
                icon.classList.remove('spinning');
            }
        }

        async function bootstrap() {
            if (!confirm("This will scan your system for applications and migrate history to skip the 7-day wait. Proceed?")) return;
            
            try {
                const res = await fetch('/api/bootstrap', {method: 'POST'});
                const result = await res.json();
                if (result.success) {
                    alert("✅ Bootstrap successful! Restarting monitor to apply new phase...");
                    await fetch('/api/restart', {method: 'POST'});
                    location.reload();
                } else {
                    alert("❌ Bootstrap failed: " + result.error);
                }
            } catch (e) {
                alert("❌ Network error");
            }
        }

        async function viewForensics(encodedMsg) {
            const message = atob(encodedMsg);
            document.getElementById('modal').style.display = 'flex';
            document.getElementById('briefing-text').textContent = "🤖 Guard AI is analyzing the event chain...";
            
            try {
                const res = await fetch(`/api/forensics?message=${encodeURIComponent(message)}`);
                const data = await res.json();
                
                // For better formatting in the modal
                const reportContent = data.report;
                document.getElementById('briefing-text').innerHTML = `<div style="color:var(--text-primary); text-align:left; font-family:sans-serif; line-height:1.6; padding:20px;">${reportContent.replace(/\n/g, '<br>').replace(/## (.*)/g, '<h2 style="color:var(--accent-green);">$1</h2>').replace(/### (.*)/g, '<h3 style="color:var(--accent-yellow);">$1</h3>').replace(/- \*\*(.*)\*\*: (.*)/g, '<li><strong>$1</strong>: $2</li>').replace(/- (.*)/g, '<li>$1</li>').replace(/> \[!NOTE\]<br>> (.*)/g, '<div style="background:rgba(0,255,157,0.05); padding:10px; border-left:4px solid var(--accent-green); margin-top:20px;"><strong>NOTE:</strong> $1</div>')}</div>`;
            } catch (e) {
                document.getElementById('briefing-text').textContent = "Failed to generate AI forensic report.";
            }
        }

        async function showReport() {
            document.getElementById('modal').style.display = 'flex';
            try {
                const res = await fetch('/api/report');
                const data = await res.json();
                document.getElementById('briefing-text').textContent = data.report;
            } catch (e) {
                document.getElementById('briefing-text').textContent = "Failed to load report.";
            }
        }

        function closeModal() {
            document.getElementById('modal').style.display = 'none';
        }

        async function restartMonitor() {
            if (confirm("Restart Sovereign Guard? This will briefly pause monitoring.")) {
                try {
                    await fetch('/api/restart', { method: 'POST' });
                    alert("Monitor restarting...");
                    setTimeout(() => location.reload(), 2000);
                } catch (e) {
                    alert("Error: " + e);
                }
            }
        }


        // Initial Load + Interval
        fetchLogs();
        fetchLearningStats();
        fetchTrustScore();
        setInterval(fetchLogs, 3000);
        setInterval(fetchLearningStats, 5000);
        setInterval(fetchTrustScore, 10000);
        
        async function fetchTrustScore() {
            try {
                const response = await fetch('/api/trust_score');
                const data = await response.json();
                
                const scoreEl = document.getElementById('trust-score');
                const gradeEl = document.getElementById('trust-grade');
                const cardEl = document.getElementById('trust-score-card');
                
                if (scoreEl && gradeEl && cardEl) {
                    scoreEl.textContent = data.score;
                    gradeEl.textContent = "// " + data.grade.toUpperCase();
                    
                    // Set color based on grade
                    let color = 'var(--accent-green)';
                    if (data.grade === 'Good') color = 'var(--accent-yellow)';
                    if (data.grade === 'Fair') color = '#ff8800';
                    if (data.grade === 'At Risk') color = 'var(--accent-red)';
                    
                    scoreEl.style.color = color;
                    cardEl.style.boxShadow = `0 0 20px ${color}22`;
                    cardEl.style.borderColor = `${color}44`;
                }
            } catch (e) {
                console.error("Failed to fetch trust score", e);
            }
        }
        
        async function fetchLearningStats() {
            try {
                const response = await fetch('/api/learning');
                const data = await response.json();
                
                // Update mode badge
                const modeBadge = document.getElementById('mode-badge');
                modeBadge.textContent = data.mode.toUpperCase();
                modeBadge.className = 'mode-badge ' + data.mode;
                
                // Show/hide learning banner
                const banner = document.getElementById('learning-banner');
                if (data.mode === 'learn') {
                    banner.style.display = 'flex';
                    document.getElementById('learning-obs-count').textContent = data.stats.total_observations || 0;
                } else {
                    banner.style.display = 'none';
                    document.getElementById('learning-obs-count').textContent = data.stats.total_observations || 0;
                }
            } catch (e) {
                console.error("Failed to fetch learning stats", e);
            }
        }
    </script>
</body>
</html>
"""

def parse_logs():
    logs = []
    if not os.path.exists(LOG_FILE):
        return []
    
    try:
        with open(LOG_FILE, 'r') as f:
            # Read last 100 lines
            lines = f.readlines()[-100:]
            
            for line in reversed(lines):
                # Basic Parse: 2026-01-02 11:46:48,895 - WARNING - Message...
                parts = line.split(' - ', 2)
                if len(parts) >= 3:
                    timestamp = parts[0].split(',')[0] # Remove milliseconds
                    level = parts[1]
                    message = parts[2].strip()
                    
                    logs.append({
                        "timestamp": timestamp,
                        "level": level,
                        "message": message
                    })
    except Exception as e:
        print(f"Error parsing logs: {e}")
        
    return logs




@app.route('/api/learning')
def get_learning_stats():
    """Get learning mode statistics"""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    try:
        import learning_engine
        stats = learning_engine.analyze_learnings()
        mode = learning_engine.get_protection_mode()
        
        return jsonify({
            "mode": mode,
            "stats": stats
        })
    except Exception as e:
        return jsonify({
            "mode": os.getenv('PROTECTION_MODE', 'protect'),
            "stats": {"status": "error", "error": str(e)}
        })

@app.route('/api/trust_score')
def get_trust_score():
    """Get system trust score"""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    try:
        import learning_engine
        score_data = learning_engine.calculate_trust_score()
        return jsonify(score_data)
    except Exception as e:
        return jsonify({"error": str(e), "score": 0, "grade": "Unknown"}), 500

@app.route('/api/forensics')
def get_forensics():
    """Get AI forensic report for a message"""
    from flask import request
    message = request.args.get('message', '')
    
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    try:
        import ai_forensics
        
        # Determine threat type from message
        threat_type = "UNKNOWN"
        if "SECURITY ALERT" in message or "THREAT" in message:
            if "debugging port" in message.lower() or "hijack" in message.lower():
                threat_type = "HIJACK_ATTEMPT"
            elif "reverse shell" in message.lower() or "netcat" in message.lower():
                threat_type = "REVERSE_SHELL"
            elif "clipboard" in message.lower():
                threat_type = "CLIPBOARD_SENTRY"
            elif "multimedia" in message.lower() or "camera" in message.lower():
                threat_type = "MULTIMEDIA_ACCESS"
        elif "typo-squat" in message.lower():
            threat_type = "SUPPLY_CHAIN_TYPO"
            
        report = ai_forensics.generate_report(threat_type, {"raw_event": message})
        return jsonify({"report": report})
    except Exception as e:
        return jsonify({"error": str(e), "report": "Failed to generate forensic report."}), 500

@app.route('/api/sync', methods=['POST'])
def sync_intelligence():
    """Trigger whitelist sync from cloud"""
    from flask import request
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    try:
        import sovereign_core as core
        
        # Get license key from env or request
        license_key = os.getenv('LICENSE_KEY', 'free-tier')
        force = request.json.get('force', False) if request.json else False
        
        result = core.sync_whitelist(license_key=license_key, force=force)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Sync error: {str(e)}",
            "new_count": 0
        }), 500

@app.route('/api/whitelist', methods=['POST'])
def whitelist_process():
    from flask import request
    data = request.json
    process_name = data.get('process')
    
    if not process_name:
        return jsonify({"success": False, "error": "No process name provided"}), 400
        
    try:
        whitelist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'whitelist.json')
        
        current_whitelist = []
        if os.path.exists(whitelist_path):
            with open(whitelist_path, 'r') as f:
                try:
                    current_whitelist = json.load(f)
                    if not isinstance(current_whitelist, list):
                        current_whitelist = []
                except: 
                    current_whitelist = []
        
        if process_name not in current_whitelist:
            current_whitelist.append(process_name)
            with open(whitelist_path, 'w') as f:
                json.dump(current_whitelist, f, indent=2)
                
            return jsonify({"success": True, "message": f"'{process_name}' added to whitelist. Monitor will auto-reload."})
        else:
            return jsonify({"success": True, "message": f"'{process_name}' is already whitelisted."})
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/bootstrap', methods=['POST'])
def api_bootstrap():
    """Trigger the bootstrap discovery process"""
    import sys
    import subprocess
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        # Use simple os.system or direct call since ctl objects might be complex in memory
        bootstrap_script = os.path.join(os.path.dirname(__file__), 'bootstrap_discovery.py')
        venv_python = os.path.join(os.path.dirname(__file__), 'venv', 'bin', 'python3')
        
        # Ensure executable exists
        if not os.path.exists(venv_python):
             venv_python = sys.executable # Fallback
             
        subprocess.check_call([venv_python, bootstrap_script])
        
        # Create marker file
        marker_path = os.path.join(os.path.dirname(__file__), '.bootstrap_done')
        with open(marker_path, 'w') as f:
            from datetime import datetime
            f.write(datetime.now().isoformat())
            
        return jsonify({"success": True})
    except Exception as e:
        print(f"Bootstrap API Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/report')
def api_report():
    """Get the technical briefing report"""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        # Use io.StringIO to capture output of ctl.report()
        import io
        from contextlib import redirect_stdout
        import sovereign_ctl as ctl
        
        f = io.StringIO()
        with redirect_stdout(f):
            ctl.report()
        
        return jsonify({"report": f.getvalue()})
    except Exception as e:
        return jsonify({"report": f"Error generating report: {str(e)}"})

@app.route('/api/restart', methods=['POST'])
def api_restart():
    """Restart the monitor process"""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import sovereign_ctl as ctl
        ctl.stop()
        time.sleep(1)
        ctl.start()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/logs')
def get_logs():
    return jsonify({"logs": parse_logs()})

if __name__ == '__main__':
    import time # Needed for sleep
    print(f"🚀 Dashboard running at http://127.0.0.1:5000")
    app.run(port=5000)
