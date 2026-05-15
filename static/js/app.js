// Navigation Logic
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const sectionId = e.target.getAttribute('data-section');
        switchSection(sectionId);
    });
});

function switchSection(sectionId) {
    // Update active nav link
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-section') === sectionId) {
            link.classList.add('active');
        }
    });

    // Update active section
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    document.getElementById(sectionId).classList.add('active');
}

// Global File State
let currentEmailFile = null;
let currentFullFile = null;

// File Upload Handlers (Email Scan)
setupFileUpload('email-upload-zone', 'email-file-input', 'email-file-info', 'email-file-name', 'btn-email-analyze', (file) => {
    currentEmailFile = file;
});

// File Upload Handlers (Full Scan)
setupFileUpload('full-upload-zone', 'full-file-input', 'full-file-info', 'full-file-name', 'btn-full-analyze', (file) => {
    currentFullFile = file;
});

function setupFileUpload(zoneId, inputId, infoId, nameId, btnId, setFileCallback) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    const info = document.getElementById(infoId);
    const name = document.getElementById(nameId);
    const btn = document.getElementById(btnId);

    // Click to open dialog
    zone.addEventListener('click', (e) => {
        if (e.target.className !== 'btn-clear') {
            input.click();
        }
    });

    // Drag and drop events
    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
    });

    zone.addEventListener('dragleave', () => {
        zone.classList.remove('dragover');
    });

    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            handleFileSelection(e.dataTransfer.files[0]);
        }
    });

    // Input change
    input.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFileSelection(e.target.files[0]);
        }
    });

    function handleFileSelection(file) {
        if (!file.name.toLowerCase().endsWith('.eml')) {
            alert('Please select a valid .eml file.');
            return;
        }
        setFileCallback(file);
        zone.querySelector('.upload-content').style.opacity = '0.3';
        info.style.display = 'flex';
        name.textContent = file.name;
        btn.disabled = false;
    }
}

function clearFile(type) {
    if (type === 'email') {
        currentEmailFile = null;
        document.getElementById('email-file-input').value = '';
        document.getElementById('email-file-info').style.display = 'none';
        document.querySelector('#email-upload-zone .upload-content').style.opacity = '1';
        document.getElementById('btn-email-analyze').disabled = true;
        document.getElementById('email-results').style.display = 'none';
    } else {
        currentFullFile = null;
        document.getElementById('full-file-input').value = '';
        document.getElementById('full-file-info').style.display = 'none';
        document.querySelector('#full-upload-zone .upload-content').style.opacity = '1';
        document.getElementById('btn-full-analyze').disabled = true;
        document.getElementById('full-results').style.display = 'none';
    }
}

// ── UI Helpers ──────────────────────────────────────────────────────────────

function setLoading(btnId, isLoading) {
    const btn = document.getElementById(btnId);
    const text = btn.querySelector('.btn-text');
    const loader = btn.querySelector('.btn-loader');
    
    if (isLoading) {
        btn.disabled = true;
        text.style.display = 'none';
        loader.style.display = 'block';
    } else {
        btn.disabled = false;
        text.style.display = 'block';
        loader.style.display = 'none';
    }
}

function createVerdictBanner(title, riskScore, verdict) {
    return `
        <div class="verdict-banner verdict-${verdict}">
            <div class="verdict-info">
                <h3>${title}</h3>
                <h2>${verdict} RISK</h2>
            </div>
            <div class="verdict-score">
                <div class="score-value">${riskScore}</div>
                <div class="score-label">Risk Score (0-100)</div>
            </div>
        </div>
    `;
}

function createBadge(status) {
    const s = String(status).toLowerCase();
    if (s === 'pass' || s === 'true' || s === 'aligned') return `<span class="badge badge-pass">${status}</span>`;
    if (s === 'fail' || s === 'false' || s === 'misaligned' || s === 'no') return `<span class="badge badge-fail">${status}</span>`;
    return `<span class="badge badge-neutral">${status}</span>`;
}

// ── API Calls & Rendering ───────────────────────────────────────────────────

// 1. Email Header Analysis
async function analyzeEmail() {
    if (!currentEmailFile) return;
    setLoading('btn-email-analyze', true);
    
    const formData = new FormData();
    formData.append('eml_file', currentEmailFile);

    try {
        const res = await fetch('/api/analyze-header', { method: 'POST', body: formData });
        const data = await res.json();
        
        if (data.error) throw new Error(data.error);
        
        renderHeaderReport('email-results', data.report);
    } catch (err) {
        alert('Error: ' + err.message);
    } finally {
        setLoading('btn-email-analyze', false);
    }
}

function renderHeaderReport(containerId, report) {
    const container = document.getElementById(containerId);
    container.style.display = 'flex';
    
    let html = createVerdictBanner('Header Analysis Result', report.risk_score, report.verdict);
    
    // Overview Card
    html += `
        <div class="results-grid">
            <div class="result-card">
                <div class="result-card-header">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
                    Metadata
                </div>
                <div class="result-card-body">
                    <div class="data-row"><span class="data-label">From Domain</span><span class="data-value">${report.from_domain || 'N/A'}</span></div>
                    <div class="data-row"><span class="data-label">Envelope Sender</span><span class="data-value">${report.envelope_sender_domain || 'N/A'}</span></div>
                    <div class="data-row"><span class="data-label">Reply-To</span><span class="data-value">${report.reply_to_domain || 'N/A'}</span></div>
                    <div class="data-row"><span class="data-label">Received Hops</span><span class="data-value">${report.received_hops}</span></div>
                </div>
            </div>
            
            <div class="result-card" style="grid-column: 1 / -1;">
                <div class="result-card-header">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                    Authentication Checks
                </div>
                <div class="result-card-body" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
    `;
    
    // Auth Cards
    report.auth_results.forEach(auth => {
        html += `
            <div style="background: rgba(0,0,0,0.2); padding: 1rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.05);">
                <h4 style="margin-bottom: 1rem; color: var(--accent-cyan);">${auth.mechanism}</h4>
                <div class="data-row"><span class="data-label">Status</span><span class="data-value">${createBadge(auth.status.toUpperCase())}</span></div>
                <div class="data-row"><span class="data-label">Domain</span><span class="data-value">${auth.domain}</span></div>
                <div class="data-row"><span class="data-label">DNS Record</span><span class="data-value">${createBadge(auth.dns_record_found ? 'YES' : 'NO')}</span></div>
                <div class="data-row"><span class="data-label">Alignment</span><span class="data-value">${createBadge(auth.aligned ? 'ALIGNED' : 'MISALIGNED')}</span></div>
                <div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 1rem;">${auth.details}</div>
            </div>
        `;
    });
    
    html += `</div></div></div>`; // Close Auth checks & grid
    
    // Suspicious Flags
    if (report.suspicious_flags.length > 0) {
        html += `
            <div class="result-card">
                <div class="result-card-header" style="color: var(--accent-red);">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    Suspicious Indicators
                </div>
                <div class="result-card-body">
                    <ul class="alerts-list">
                        ${report.suspicious_flags.map(flag => `
                            <li class="alert-item">
                                <svg class="alert-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                                <span>${flag}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            </div>
        `;
    }
    
    container.innerHTML = html;
}

// 2. URL Analysis
async function analyzeURL() {
    const urlInput = document.getElementById('url-input').value;
    if (!urlInput) return;
    
    setLoading('btn-url-analyze', true);
    
    try {
        const res = await fetch('/api/analyze-website', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });
        const data = await res.json();
        
        if (data.error) throw new Error(data.error);
        
        renderWebsiteReport('url-results', data.report);
    } catch (err) {
        alert('Error: ' + err.message);
    } finally {
        setLoading('btn-url-analyze', false);
    }
}

function renderWebsiteReport(containerId, report) {
    const container = document.getElementById(containerId);
    container.style.display = 'flex';
    
    let html = createVerdictBanner('Website Analysis Result', report.risk_score, report.verdict);
    
    html += `
        <div class="results-grid">
            <!-- Domain Info -->
            <div class="result-card" style="grid-column: span 2;">
                <div class="result-card-header">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                    Domain Information
                </div>
                <div class="result-card-body" style="display:grid; grid-template-columns: 1fr 1fr; gap: 0 2rem;">
                    <div>
                        <div class="data-row"><span class="data-label">Target URL</span><span class="data-value">${report.target_url}</span></div>
                        <div class="data-row"><span class="data-label">Final URL</span><span class="data-value">${report.final_url}</span></div>
                        <div class="data-row"><span class="data-label">Domain</span><span class="data-value">${report.domain}</span></div>
                        <div class="data-row"><span class="data-label">Registered Domain</span><span class="data-value">${report.registered_domain}</span></div>
                    </div>
                    <div>
                        <div class="data-row"><span class="data-label">WHOIS Available</span><span class="data-value">${createBadge(report.domain_age.whois_available ? 'YES' : 'NO')}</span></div>
                        <div class="data-row"><span class="data-label">Registrar</span><span class="data-value">${report.domain_age.registrar}</span></div>
                        <div class="data-row"><span class="data-label">Created Date</span><span class="data-value">${report.domain_age.creation_date || 'N/A'}</span></div>
                        <div class="data-row"><span class="data-label">Domain Age</span><span class="data-value">${report.domain_age.age_days} days</span></div>
                    </div>
                    <div style="grid-column: span 2; margin-top: 1rem; padding-top: 1rem; border-top: 1px dashed rgba(255,255,255,0.05);">
                        <span class="data-label" style="display:block; margin-bottom:0.5rem;">WHOIS Details:</span>
                        <div style="font-size:0.85rem; color:var(--text-muted);">${report.domain_age.details || 'N/A'}</div>
                    </div>
                </div>
            </div>
            
            <!-- SSL Info -->
            <div class="result-card">
                <div class="result-card-header">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    SSL/TLS Certificate
                </div>
                <div class="result-card-body">
                    <div class="data-row"><span class="data-label">Has SSL</span><span class="data-value">${createBadge(report.ssl.has_ssl ? 'YES' : 'NO')}</span></div>
                    <div class="data-row"><span class="data-label">Issuer</span><span class="data-value">${report.ssl.issuer}</span></div>
                    <div class="data-row"><span class="data-label">Free CA</span><span class="data-value">${createBadge(report.ssl.is_free ? 'YES' : 'NO')}</span></div>
                    <div class="data-row"><span class="data-label">Certificate Valid</span><span class="data-value">${createBadge(report.ssl.is_valid ? 'YES' : 'NO')}</span></div>
                    <div class="data-row"><span class="data-label">Valid From</span><span class="data-value">${report.ssl.valid_from || 'N/A'}</span></div>
                    <div class="data-row"><span class="data-label">Valid To</span><span class="data-value">${report.ssl.valid_to || 'N/A'}</span></div>
                    <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px dashed rgba(255,255,255,0.05);">
                        <span class="data-label" style="display:block; margin-bottom:0.5rem;">SSL Details:</span>
                        <div style="font-size:0.85rem; color:var(--text-muted);">${report.ssl.details || 'N/A'}</div>
                    </div>
                </div>
            </div>
            
            <!-- Details -->
            <div class="result-card">
                <div class="result-card-header">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                    Page Characteristics
                </div>
                <div class="result-card-body">
                    <div class="data-row"><span class="data-label">Login Form Found</span><span class="data-value">${createBadge(report.login_form.found ? 'FOUND' : 'NONE')}</span></div>
                    <div class="data-row"><span class="data-label">On HTTP (non-TLS)</span><span class="data-value">${createBadge(report.login_form.on_http ? 'YES' : 'NO')}</span></div>
                    <div class="data-row"><span class="data-label">Password Fields</span><span class="data-value">${report.login_form.password_fields}</span></div>
                    <div class="data-row"><span class="data-label">URL Shortener</span><span class="data-value">${createBadge(report.is_url_shortener ? 'YES' : 'NO')}</span></div>
                    <div class="data-row"><span class="data-label">External Iframes</span><span class="data-value">${report.external_iframes}</span></div>
                    <div class="data-row"><span class="data-label">Typosquatting</span><span class="data-value">${report.typosquatting && report.typosquatting.length > 0 ? report.typosquatting.join(', ') : 'None detected'}</span></div>
                    <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px dashed rgba(255,255,255,0.05);">
                        <span class="data-label" style="display:block; margin-bottom:0.5rem;">Form Details:</span>
                        <div style="font-size:0.85rem; color:var(--text-muted);">${report.login_form.details || 'N/A'}</div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Suspicious Flags
    if (report.suspicious_indicators.length > 0) {
        html += `
            <div class="result-card">
                <div class="result-card-header" style="color: var(--accent-red);">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    Suspicious Indicators
                </div>
                <div class="result-card-body">
                    <ul class="alerts-list">
                        ${report.suspicious_indicators.map(ind => `
                            <li class="alert-item">
                                <svg class="alert-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                                <span>${ind}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            </div>
        `;
    }
    
    container.innerHTML = html;
}

// 3. Full Pipeline Analysis
async function analyzeFull() {
    if (!currentFullFile) return;
    
    // UI Updates
    setLoading('btn-full-analyze', true);
    const steps = document.querySelectorAll('.pipeline-step');
    const connectors = document.querySelectorAll('.pipeline-connector');
    
    // Fake progress animation for UX
    steps[0].classList.add('active');
    setTimeout(() => { connectors[0].classList.add('active'); steps[1].classList.add('active'); }, 1000);
    setTimeout(() => { connectors[1].classList.add('active'); steps[2].classList.add('active'); }, 2000);
    
    const formData = new FormData();
    formData.append('eml_file', currentFullFile);

    try {
        const res = await fetch('/api/analyze-full', { method: 'POST', body: formData });
        const data = await res.json();
        
        if (data.error) throw new Error(data.error);
        
        renderFullReport('full-results', data);
    } catch (err) {
        alert('Error: ' + err.message);
        steps.forEach(s => s.classList.remove('active'));
        connectors.forEach(c => c.classList.remove('active'));
    } finally {
        setLoading('btn-full-analyze', false);
    }
}

function renderFullReport(containerId, data) {
    const container = document.getElementById(containerId);
    container.style.display = 'flex';
    
    // Determine overall verdict
    let highestScore = data.header_report.risk_score;
    let worstVerdict = data.header_report.verdict;
    
    data.website_reports.forEach(wr => {
        if (wr.risk_score > highestScore) {
            highestScore = wr.risk_score;
            worstVerdict = wr.verdict;
        }
    });
    
    let html = createVerdictBanner('Full Pipeline Analysis Result', highestScore, worstVerdict);
    
    // Step 1: Headers
    html += `<h2 class="sub-report-title">1. Email Header Analysis</h2>`;
    // Create a temporary container, use existing function, extract HTML
    const tempHeader = document.createElement('div');
    tempHeader.id = 'temp-header';
    document.body.appendChild(tempHeader);
    renderHeaderReport('temp-header', data.header_report);
    // Remove the verdict banner from the sub-report
    tempHeader.querySelector('.verdict-banner').remove();
    html += tempHeader.innerHTML;
    document.body.removeChild(tempHeader);
    
    // Step 2: IOC Extraction
    html += `<h2 class="sub-report-title">2. IOC Extraction</h2>`;
    html += `
        <div class="results-grid">
            <div class="result-card">
                <div class="result-card-header">🔗 Extracted URLs (${data.ioc_report.urls.length})</div>
                <div class="result-card-body">
                    ${data.ioc_report.urls.length > 0 ? 
                        `<div class="alerts-list">${data.ioc_report.urls.map(u => `<div class="list-item">${u}</div>`).join('')}</div>` : 
                        '<span class="text-muted">No URLs found.</span>'}
                </div>
            </div>
            
            <div class="result-card">
                <div class="result-card-header" style="color: var(--accent-yellow);">⚠ Obfuscated Links (${data.ioc_report.obfuscated_links.length})</div>
                <div class="result-card-body">
                    ${data.ioc_report.obfuscated_links.length > 0 ? 
                        `<ul class="alerts-list">
                            ${data.ioc_report.obfuscated_links.map(l => `
                                <li class="alert-item" style="flex-direction: column; background: rgba(245, 158, 11, 0.05); border-left-color: var(--accent-yellow);">
                                    <div style="font-weight: 600;">Display: ${l.display_text}</div>
                                    <div style="font-family: var(--font-mono); font-size: 0.85rem;">Actual: ${l.href}</div>
                                    <div style="color: var(--accent-yellow); font-size: 0.85rem; margin-top: 0.5rem;">${l.reason}</div>
                                </li>
                            `).join('')}
                        </ul>` : 
                        '<span class="text-muted">No obfuscated links found.</span>'}
                </div>
            </div>
        </div>
    `;
    
    // Step 3: Website Scans
    if (data.website_reports.length > 0) {
        html += `<h2 class="sub-report-title">3. Website Scans (${data.website_reports.length} analyzed)</h2>`;
        
        data.website_reports.forEach((wr, i) => {
            const tempWeb = document.createElement('div');
            tempWeb.id = 'temp-web-' + i;
            document.body.appendChild(tempWeb);
            
            if (wr.error) {
                html += `
                    <div class="result-card" style="margin-bottom: 2rem;">
                        <div class="result-card-header">URL: ${wr.target_url}</div>
                        <div class="result-card-body" style="color: var(--accent-red);">Error: ${wr.error}</div>
                    </div>
                `;
            } else {
                renderWebsiteReport('temp-web-' + i, wr);
                html += `<div style="margin-bottom: 3rem;">` + tempWeb.innerHTML + `</div>`;
            }
            
            document.body.removeChild(tempWeb);
        });
    }
    
    container.innerHTML = html;
}
