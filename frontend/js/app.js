/**
 * SilentSeal Enhanced - Frontend Application
 * Privacy Intelligence Platform
 */

// API Base URL
const API_BASE = 'http://127.0.0.1:8000';

// Global Application Namespace
window.app = window.app || {};
const app = window.app;

// Application State
const state = {
    currentPage: 'dashboard',
    documents: [],
    stats: {
        documents: 0,
        entities: 0,
        redacted: 0
    },
    currentDocId: null,
    processingResult: null,
    currentVaultName: 'default'
};

// DOM Elements
const elements = {
    navItems: document.querySelectorAll('.nav-item'),
    pages: document.querySelectorAll('.page'),
    uploadZone: document.getElementById('upload-zone'),
    fileInput: document.getElementById('file-input'),
    loadingOverlay: document.getElementById('loading-overlay'),
    loadingText: document.getElementById('loading-text'),
    processingResults: document.getElementById('processing-results'),
    modal: document.getElementById('explanation-modal'),
    modalClose: document.getElementById('modal-close'),
    modalBody: document.getElementById('modal-body'),
    previewContainer: document.getElementById('preview-container'),
    previewObject: document.getElementById('preview-object'),
    previewInfo: document.getElementById('preview-info'),
    previewFallback: document.getElementById('preview-fallback-link')
};

// Global Error Handling for Debugging
window.onerror = function (msg, url, line, col, error) {
    const errorMsg = `Error: ${msg}\nLine: ${line}\nUrl: ${url}`;
    console.error(errorMsg, error);
    // Only alert for major issues that keep the app from working
    if (msg.toLowerCase().includes('ref') || msg.toLowerCase().includes('syntax')) {
        alert("⚠️ SYSTEM ERROR DETECTED:\n" + errorMsg);
    }
    return false;
};

window.onunhandledrejection = function (event) {
    console.error('Unhandled Promise Rejection:', event.reason);
    // Optional: alert(`⚠️ ASYNC ERROR: ${event.reason}`);
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    console.log("🚀 SilentSeal Application Starting...");

    try {
        initNavigation();
        initUpload();
        initAnalytics();
        initLinkage();
        loadStats();

        // Initialize Extended Features
        initStandbyMode();
        initSystemScanner();
        initVault();
        initAuditLog();
        initProcessedDocuments();

        // Feature Expansion 2.0
        initRemediation();
        initIncidents();
        initRBAC();
        initRules();
        initCompliance();
        initObservability();
        initPrivacyGraph();

        // Start Periodic System Checks
        setInterval(() => checkVaultStatus(), 5000);
        setInterval(() => checkBackendHealth(), 10000);
        checkBackendHealth(); // Initial check

        console.log("✅ All Modules Initialized.");
    } catch (err) {
        console.error("❌ CRITICAL INIT ERROR:", err);
        alert("❌ APP FAILED TO START: " + err.message);
    }
});

// Navigation
function initNavigation() {
    elements.navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            navigateTo(page);
        });
    });
}

function navigateTo(page) {
    // Update nav
    elements.navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });

    // Update pages
    elements.pages.forEach(p => {
        p.classList.toggle('active', p.id === `page-${page}`);
    });

    state.currentPage = page;

    // Trigger page-specific loads
    if (page === 'audit') loadAuditLogs();
    if (page === 'documents') loadProcessedDocuments();
    if (page === 'vault') checkVaultStatus();
    if (page === 'remediation') loadRemediationHistory();
    if (page === 'incidents') loadIncidents();
    if (page === 'rbac') loadRBAC();
    if (page === 'rules') loadRules();
    if (page === 'compliance') loadComplianceTemplates();
    if (page === 'observability') loadObservabilityDashboard();
    if (page === 'privacy-graph') loadPrivacyGraph();
}

// Upload Functionality
function initUpload() {
    const uploadZone = elements.uploadZone;
    const fileInput = elements.fileInput;

    // Click to upload
    uploadZone.addEventListener('click', () => fileInput.click());

    // Drag and drop
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('drag-over');
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('drag-over');
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length) {
            handleFileUpload(files[0]);
        }
    });

    // File input change
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFileUpload(e.target.files[0]);
        }
    });

    // Download button
    document.getElementById('btn-download')?.addEventListener('click', downloadRedacted);

    // Report button
    document.getElementById('btn-report')?.addEventListener('click', showReport);
}

async function handleFileUpload(file) {
    showLoading('Uploading document...');

    try {
        // Upload file
        const formData = new FormData();
        formData.append('file', file);

        const uploadResponse = await fetch(`${API_BASE}/api/upload`, {
            method: 'POST',
            body: formData
        });

        if (!uploadResponse.ok) throw new Error('Upload failed');

        const uploadResult = await uploadResponse.json();
        state.currentDocId = uploadResult.doc_id;

        // Process document
        showLoading('Analyzing document...');

        const options = {
            use_synthetic_replacement: document.getElementById('opt-synthetic')?.checked ?? true,
            generate_explanations: document.getElementById('opt-explanations')?.checked ?? true,
            run_adversarial_test: document.getElementById('opt-adversarial')?.checked ?? false,
            enable_handwriting_ocr: document.getElementById('opt-handwriting')?.checked ?? true,
            semantic_query: document.getElementById('opt-semantic-query')?.value.trim() || null,
            strict_validation: document.getElementById('opt-strict')?.checked ?? false
        };

        const processResponse = await fetch(`${API_BASE}/api/process/${state.currentDocId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(options)
        });

        if (!processResponse.ok) throw new Error('Processing failed');

        const result = await processResponse.json();
        // Merge results so file_path (from upload) and entities (from process) are together
        state.processingResult = { ...uploadResult, ...result };

        // Update stats
        state.stats.documents++;
        state.stats.entities += result.entities_found;
        state.stats.redacted += result.entities_found;
        updateStatsDisplay();

        // Show results
        hideLoading();
        displayResults(state.processingResult);

        // Auto-show the report to give immediate feedback
        showReport();

    } catch (error) {
        hideLoading();
        alert(`Error: ${error.message}`);
        console.error(error);
    }
}

function displayResults(result) {
    elements.processingResults.classList.remove('hidden');

    // Update risk score display
    const riskScore = result.risk_score?.score || 0;
    const riskLevel = result.risk_score?.level || 'LOW';
    const kAnonymity = result.risk_score?.k_anonymity || '∞';

    document.getElementById('risk-score').textContent = Math.round(riskScore);
    document.getElementById('risk-level').textContent = riskLevel;
    document.getElementById('risk-level').className = `risk-stat-value risk-level ${riskLevel}`;
    document.getElementById('k-value').textContent = kAnonymity > 1000000 ? '∞' : kAnonymity;

    // Animate risk gauge
    const riskArc = document.getElementById('risk-arc');
    if (riskArc) {
        const dashOffset = 251 - (251 * (riskScore / 100));
        riskArc.style.strokeDashoffset = dashOffset;
    }

    // Display entities
    const entitiesList = document.getElementById('entities-list');
    entitiesList.innerHTML = '';

    (result.entities || []).forEach((entity, index) => {
        const isSynthetic = !!entity.replacement;
        const tag = document.createElement('div');
        tag.className = 'entity-tag';
        if (isSynthetic) tag.style.border = '1px solid var(--accent-primary)';

        tag.innerHTML = `
            <span class="entity-type">${entity.type}</span>
            <span class="entity-preview">${isSynthetic ? entity.replacement : maskValue(entity.text)}</span>
            ${isSynthetic ? '<span style="font-size: 8px; background: var(--accent-primary); color: white; padding: 1px 4px; border-radius: 3px; margin-left: 5px;">SYNTHETIC</span>' : ''}
            <span class="entity-confidence">${Math.round((entity.confidence || 0.95) * 100)}%</span>
        `;
        tag.addEventListener('click', () => showExplanation(entity, result.explanations?.[index]));
        entitiesList.appendChild(tag);
    });

    // Display Adversarial Report
    const advPanel = document.getElementById('adversarial-panel');
    if (advPanel) {
        if (result.adversarial_report) {
            advPanel.classList.remove('hidden');
            const report = result.adversarial_report;
            const gradeEl = document.getElementById('robustness-grade');
            const barEl = document.getElementById('robustness-bar');

            document.getElementById('robustness-score').textContent = `${report.robustness_score}%`;
            barEl.style.width = `${report.robustness_score}%`;
            gradeEl.textContent = report.grade;

            // Dynamic Styling based on Grade/Score
            if (report.robustness_score >= 80) {
                gradeEl.style.background = '#22c55e'; // Green
                barEl.style.background = '#22c55e';
                advPanel.style.background = 'rgba(34, 197, 94, 0.05)';
                advPanel.style.borderColor = 'rgba(34, 197, 94, 0.1)';
            } else if (report.robustness_score >= 60) {
                gradeEl.style.background = '#f59e0b'; // Amber
                barEl.style.background = '#f59e0b';
                advPanel.style.background = 'rgba(245, 158, 11, 0.05)';
                advPanel.style.borderColor = 'rgba(245, 158, 11, 0.1)';
            } else {
                gradeEl.style.background = '#ef4444'; // Red
                barEl.style.background = '#ef4444';
                advPanel.style.background = 'rgba(239, 68, 68, 0.05)';
                advPanel.style.borderColor = 'rgba(239, 68, 68, 0.1)';
            }

            const vulnList = document.getElementById('adversarial-vulnerabilities');
            if (report.vulnerabilities && report.vulnerabilities.length > 0) {
                vulnList.innerHTML = `
                    <p style="font-weight: bold; margin-bottom: 8px; color: #ef4444;">🚨 Vulnerabilities Identified:</p>
                    <ul style="padding-left: 20px; list-style-type: disc;">
                        ${report.vulnerabilities.slice(0, 3).map(v => `
                            <li style="margin-bottom: 5px;">
                                <strong>${v.type}</strong>: ${v.detail || v.recommendation}
                            </li>
                        `).join('')}
                    </ul>
                `;
            } else {
                vulnList.innerHTML = '<p style="color: #22c55e;">✅ No major vulnerabilities detected in the redacted output.</p>';
            }
        } else {
            advPanel.classList.add('hidden');
        }
    }

    // Display explanations
    const explanationsList = document.getElementById('explanations-list');
    explanationsList.innerHTML = '';

    (result.explanations || []).slice(0, 5).forEach(exp => {
        const item = document.createElement('div');
        item.className = 'explanation-item';
        item.innerHTML = `
            <h4>
                <span class="entity-type">${exp.entity?.type || 'Entity'}</span>
                - ${exp.decision || 'REDACT'}
            </h4>
            <p>${exp.human_readable || exp.decision_reason || 'Sensitive data detected and redacted for privacy protection.'}</p>
        `;
        explanationsList.appendChild(item);
    });
}

function maskValue(value) {
    if (!value) return '***';
    if (value.length <= 4) return '***';
    return value.substring(0, 3) + '***';
}

function showExplanation(entity, explanation) {
    const modal = elements.modal;
    const body = elements.modalBody;

    body.innerHTML = `
        <div class="explanation-detail">
            <h4>Entity Details</h4>
            <p><strong>Type:</strong> ${entity.type}</p>
            <p><strong>Detection Method:</strong> ${entity.method || 'Hybrid'}</p>
            <p><strong>Confidence:</strong> ${Math.round((entity.confidence || 0.95) * 100)}%</p>
            
            ${explanation ? `
                <h4 style="margin-top: 20px;">Why Redacted</h4>
                <p>${explanation.decision_reason || 'Sensitive personal information detected.'}</p>
                
                <h4 style="margin-top: 20px;">Legal Basis</h4>
                <p><strong>Regulation:</strong> ${explanation.legal_basis?.regulation || 'DPDP Act 2023'}</p>
                <p><strong>Category:</strong> ${explanation.legal_basis?.category || 'Personal Information'}</p>
                <p><strong>Sensitivity:</strong> ${explanation.legal_basis?.context_sensitivity || 'MEDIUM'}</p>
                
                <h4 style="margin-top: 20px;">Recommendation</h4>
                <p>${explanation.recommendation || 'Redact this entity before sharing externally.'}</p>
            ` : ''}
        </div>
    `;

    modal.classList.add('active');
}

// Modal close
elements.modalClose?.addEventListener('click', () => {
    elements.modal.classList.remove('active');
});

elements.modal?.addEventListener('click', (e) => {
    if (e.target === elements.modal) {
        elements.modal.classList.remove('active');
    }
});

async function downloadRedacted() {
    if (!state.currentDocId) return;

    try {
        const response = await fetch(`${API_BASE}/api/download/${state.currentDocId}`);
        if (!response.ok) throw new Error('Download failed');

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `redacted_${state.currentDocId}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (error) {
        alert(`Download error: ${error.message}`);
    }
}

function showReport() {
    if (!state.processingResult) return;

    const result = state.processingResult;
    const body = elements.modalBody;

    body.innerHTML = `
        <div class="report-content">
            <h4>Processing Report</h4>
            <p><strong>Document ID:</strong> ${state.currentDocId}</p>
            <p><strong>Entities Found:</strong> ${result.entities_found || 0}</p>
            <p><strong>Risk Score:</strong> ${result.risk_score?.score || 0}%</p>
            <p><strong>Risk Level:</strong> ${result.risk_score?.level || 'N/A'}</p>
            
            <h4 style="margin-top: 20px;">Recommendations</h4>
            <ul style="margin-left: 20px; margin-bottom: 20px;">
                ${(result.risk_score?.recommendations || ['Review detected entities']).map(r => `<li>${r}</li>`).join('')}
            </ul>

            <div style="display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap;">
                <button class="btn btn-primary" onclick="app.showRemediationOptions()">⚡ Remediation Actions</button>
                <button class="btn btn-outline" onclick="app.previewRedaction()" style="border: 1px solid var(--accent-primary); color: var(--accent-primary);">👁️ Preview Redaction</button>
                <button class="btn btn-secondary" onclick="app.closeModal()">Close</button>
            </div>
        </div>
    `;

    elements.modal.classList.add('active');
}

async function showRemediationOptions() {
    const result = state.processingResult;
    if (!result) return;

    const body = elements.modalBody;
    body.innerHTML = '<div class="loading-spinner"></div> Loading suggested actions...';

    const modal = elements.modal;
    modal.classList.add('active');

    try {
        const response = await fetch(`${API_BASE}/api/remediation/suggest`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                file_path: result.file_path || '',
                risk_level: result.risk_score?.level,
                risk_score: result.risk_score?.score,
                entities: result.entities
            })
        });

        const data = await response.json();
        const suggestions = data.suggestions || [];

        body.innerHTML = `
            <h3>⚡ Recommended Actions</h3>
            <p style="color: var(--text-secondary); margin-bottom: 20px;">
                Based on the risk level <strong>${result.risk_score?.level}</strong> and ${result.entities_found} detected entities.
            </p>
            <div class="remediation-cards" style="display: grid; gap: 15px;">
                ${suggestions.map(s => `
                    <div class="card" style="border-left: 4px solid ${s.priority <= 2 ? '#ef4444' : '#6366f1'};">
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <h4>${s.label}</h4>
                            ${s.auto_recommended ? '<span class="badge badge-primary">Recommended</span>' : ''}
                        </div>
                        <p style="font-size: 13px; color: var(--text-muted); margin: 8px 0;">${s.description}</p>
                        <p style="font-size: 12px; color: var(--text-secondary);">Reason: ${s.reason}</p>
                        
                        <div style="margin-top: 15px; display: flex; gap: 10px;">
                            <button class="btn btn-sm btn-primary" onclick="executeRemediation('${s.action}')">Execute</button>
                            ${s.action === 'redact_replace' ?
                `<button class="btn btn-sm btn-outline" onclick="previewRedaction()">👁️ Preview</button>` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
            <button class="btn btn-secondary" style="margin-top:20px;" onclick="showReport()">Back to Report</button>
        `;

    } catch (e) {
        body.innerHTML = `<p class="error-state">Error loading suggestions: ${e.message}</p>`;
    }
}

async function previewRedaction(btnElement = null) {
    const docId = state.currentDocId;
    const result = state.processingResult;
    if (!docId || !result) return;

    const btn = btnElement || (event?.target && event.target.tagName === 'BUTTON' ? event.target : null);
    const originalText = btn ? btn.innerHTML : '';
    if (btn) {
        btn.innerHTML = 'Generating...';
        btn.disabled = true;
    }

    try {
        // Construct redaction map (simple all-entity redaction for preview)
        const redactionMap = result.entities.map(e => ({
            entity: e,
            replacement: '[REDACTED]' // Simple replacement for preview
        }));

        const response = await fetch(`${API_BASE}/api/redact/preview`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                doc_id: docId,
                redaction_map: redactionMap
            })
        });

        if (!response.ok) throw new Error("Preview generation failed");

        const blob = await response.blob();
        console.log(`📦 PDF Preview Blob: ${blob.size} bytes, type: ${blob.type}`);

        if (blob.size < 100) {
            throw new Error("Generated PDF is too small (possibly empty)");
        }

        const url = window.URL.createObjectURL(blob);

        // Embed preview in modal
        if (elements.previewObject) {
            elements.previewObject.data = url;
            if (elements.previewInfo) {
                elements.previewInfo.innerHTML = `Size: ${(blob.size / 1024).toFixed(1)} KB`;
            }
            if (elements.previewFallback) {
                elements.previewFallback.href = url;
            }
            elements.previewContainer.classList.remove('hidden');
        }

        const modal = elements.modal;
        modal.classList.add('active');

    } catch (e) {
        alert("Preview failed: " + e.message);
    } finally {
        if (btn) {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    }
}

async function executeRemediation(actionType) {
    if (!confirm("Execute this action?")) return;

    const result = state.processingResult;
    const docId = state.currentDocId;

    try {
        const response = await fetch(`${API_BASE}/api/remediation/execute`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action_type: actionType,
                file_path: result.file_path,
                risk_level: result.risk_score?.level,
                risk_score: result.risk_score?.score,
                entities: result.entities,
                details: {}
            })
        });

        const data = await response.json();
        alert(`Action Executed: ${data.status}`);
        // Refresh
        loadRemediationHistory();

    } catch (e) {
        alert("Execution failed: " + e.message);
    }
}

// Analytics
function initAnalytics() {
    const queryBtn = document.getElementById('btn-query');
    const queryInput = document.getElementById('query-input');
    const epsilonSlider = document.getElementById('epsilon-slider');
    const epsilonValue = document.getElementById('epsilon-value');

    epsilonSlider?.addEventListener('input', () => {
        epsilonValue.textContent = epsilonSlider.value;
    });

    queryBtn?.addEventListener('click', async () => {
        const query = queryInput.value.trim();
        if (!query) return;

        const epsilon = parseFloat(epsilonSlider.value);

        try {
            const response = await fetch(`${API_BASE}/api/analytics/query`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query, epsilon })
            });

            const result = await response.json();
            displayQueryResult(result);

        } catch (error) {
            document.getElementById('query-result').innerHTML = `
        < p style = "color: var(--danger)" > Error: ${error.message}</p >
            `;
        }
    });
}

function displayQueryResult(result) {
    const resultDiv = document.getElementById('query-result');

    if (result.error) {
        resultDiv.innerHTML = `< p style = "color: var(--danger)" > ${result.error}</p > `;
        return;
    }

    resultDiv.innerHTML = `
        < div class="query-result-content" >
            <h4>Result: ${JSON.stringify(result.result)}</h4>
            <p style="color: var(--text-secondary); margin-top: 12px;">
                <strong>Noise Applied:</strong> Laplace mechanism with ε=${result.noise_info?.epsilon || 1.0}
            </p>
            <p style="color: var(--text-secondary);">
                <strong>95% Confidence Interval:</strong> 
                [${result.confidence_interval?.lower || 'N/A'}, ${result.confidence_interval?.upper || 'N/A'}]
            </p>
            <p style="color: var(--text-muted); margin-top: 8px;">
                Privacy budget remaining: ${result.remaining_budget || 'N/A'}
            </p>
            ${result.warning ? `<p style="color: var(--warning); margin-top: 12px;">${result.warning}</p>` : ''}
        </div >
        `;

    // Update budget bar
    const remaining = result.remaining_budget || 10;
    const fill = document.getElementById('budget-fill');
    if (fill) {
        fill.style.width = `${(remaining / 10) * 100}% `;
    }
    document.getElementById('budget-remaining').textContent = remaining.toFixed(1);
}

// Linkage Check
function initLinkage() {
    const multiUpload = document.getElementById('multi-upload-zone');
    const multiInput = document.getElementById('multi-file-input');

    multiUpload?.addEventListener('click', () => multiInput?.click());

    multiUpload?.addEventListener('dragover', (e) => {
        e.preventDefault();
        multiUpload.style.borderColor = 'var(--accent-primary)';
    });

    multiUpload?.addEventListener('dragleave', () => {
        multiUpload.style.borderColor = 'rgba(99, 102, 241, 0.4)';
    });

    multiUpload?.addEventListener('drop', (e) => {
        e.preventDefault();
        multiUpload.style.borderColor = 'rgba(99, 102, 241, 0.4)';
        if (e.dataTransfer.files.length >= 2) {
            handleMultiUpload(Array.from(e.dataTransfer.files));
        } else {
            alert('Please drop at least 2 documents for linkage check');
        }
    });

    multiInput?.addEventListener('change', (e) => {
        if (e.target.files.length >= 2) {
            handleMultiUpload(Array.from(e.target.files));
        } else {
            alert('Please select at least 2 documents for linkage check');
        }
    });
}

async function handleMultiUpload(files) {
    showLoading('Uploading documents...');

    try {
        const docIds = [];

        // Upload all files
        for (const file of files) {
            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch(`${API_BASE}/api/upload`, {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                const result = await response.json();
                docIds.push(result.doc_id);
            }
        }

        // Check linkage
        showLoading('Analyzing cross-document linkage...');

        const linkageResponse = await fetch(`${API_BASE}/api/linkage/check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(docIds)
        });

        if (!linkageResponse.ok) throw new Error('Linkage check failed');

        const linkageResult = await linkageResponse.json();
        hideLoading();
        displayLinkageResults(linkageResult);

    } catch (error) {
        hideLoading();
        alert(`Error: ${error.message} `);
    }
}

function displayLinkageResults(result) {
    const resultsDiv = document.getElementById('linkage-results');
    resultsDiv.classList.remove('hidden');

    document.getElementById('linkage-risk').textContent =
        `${result.combined_risk?.score || 0}% `;

    const detailsDiv = document.getElementById('linkage-details');
    detailsDiv.innerHTML = `
        < div class="linkage-info" >
            <p><strong>Documents Analyzed:</strong> ${result.documents_analyzed || 0}</p>
            <p><strong>Risk Level:</strong> ${result.combined_risk?.level || 'NONE'}</p>
            <p><strong>Total Linkages:</strong> ${result.linkages?.length || 0}</p>
            
            <h4 style="margin-top: 20px;">Explanation</h4>
            <p>${result.combined_risk?.explanation || 'No linkages detected.'}</p>
            
            <h4 style="margin-top: 20px;">Recommendations</h4>
            <ul style="margin-left: 20px;">
                ${(result.recommendations || ['No action required']).map(r => `<li>${r}</li>`).join('')}
            </ul>
        </div >
        `;
}

// Stats
function loadStats() {
    updateStatsDisplay();
}

function updateStatsDisplay() {
    document.getElementById('stat-documents').textContent = state.stats.documents;
    document.getElementById('stat-entities').textContent = state.stats.entities;
    document.getElementById('stat-redacted').textContent = state.stats.redacted;
}

// Loading
function showLoading(text = 'Processing...') {
    elements.loadingText.textContent = text;
    elements.loadingOverlay.classList.add('active');
}

function hideLoading() {
    elements.loadingOverlay.classList.remove('active');
}

async function checkBackendHealth() {
    const indicator = document.querySelector('.status-indicator');
    if (!indicator) return;

    try {
        const response = await fetch(`${API_BASE}/api`);
        if (response.ok) {
            indicator.classList.remove('offline');
            indicator.querySelector('span:last-child').textContent = 'System Ready';
        } else {
            indicator.classList.add('offline');
            indicator.querySelector('span:last-child').textContent = 'Service Issue';
        }
    } catch (err) {
        indicator.classList.add('offline');
        indicator.querySelector('span:last-child').textContent = 'Offline';
    }
}

// Utility function to format dates
function formatDate(dateString) {
    return new Date(dateString).toLocaleString();
}

// ============== STANDBY MODE (FILE WATCHER) ==============

function initStandbyMode() {
    const startBtn = document.getElementById('btn-start-watcher');
    const stopBtn = document.getElementById('btn-stop-watcher');
    const addFolderBtn = document.getElementById('btn-add-watch-path');

    if (startBtn) {
        startBtn.addEventListener('click', startWatcher);
    }
    if (stopBtn) {
        stopBtn.addEventListener('click', stopWatcher);
    }
    if (addFolderBtn) {
        addFolderBtn.addEventListener('click', addWatchPath);
    }

    // Poll for detections and status
    setInterval(loadRecentDetections, 3000);
    setInterval(updateWatcherStatus, 5000);

    // Initial loads
    updateWatcherStatus();
    loadRecentDetections();
}

async function loadRecentDetections() {
    try {
        const response = await fetch(`${API_BASE}/api/watcher/detections`);
        const data = await response.json();
        renderDetections(data.detections || []);
    } catch (error) {
        console.error('Error loading detections:', error);
    }
}

function renderDetections(detections) {
    const container = document.getElementById('recent-detections-list');
    if (!container) return;

    if (detections.length === 0) {
        container.innerHTML = '<p class="empty-state">No detections yet. Files will appear here when PII is detected.</p>';
        return;
    }

    container.innerHTML = detections.map(d => {
        const riskColor = d.risk_level === 'HIGH' ? '#ef4444' : d.risk_level === 'MEDIUM' ? '#f59e0b' : '#22c55e';
        const time = new Date(d.timestamp * 1000).toLocaleTimeString();

        return `
            <div class="detection-item" style="padding: 16px; background: rgba(99, 102, 241, 0.05); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 12px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div style="flex: 1;">
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                            <span style="font-size: 18px;">📄</span>
                            <strong>${d.file_name}</strong>
                            <span style="background: ${riskColor}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">${d.risk_level}</span>
                            <span style="color: #9ca3af; font-size: 12px;">${time}</span>
                        </div>
                        <div style="margin-left: 30px; color: #9ca3af; font-size: 13px;">
                            <div>Risk Score: <span style="color: ${riskColor}; font-weight: bold;">${d.risk_score}%</span></div>
                            <div>Entities Found: ${d.entities_count}</div>
                            <div style="margin-top: 6px;">
                                ${d.entities.slice(0, 5).map(e => `<span style="background: rgba(99, 102, 241, 0.1); padding: 2px 6px; border-radius: 4px; margin-right: 6px; font-size: 11px;"><strong>${e.type}:</strong> ${e.value}</span>`).join('')}
                                ${d.entities.length > 5 ? `<span style="color: #9ca3af;">+${d.entities.length - 5} more</span>` : ''}
                            </div>
                        </div>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button onclick="openFile('${d.file_path}')" style="padding: 6px 12px; background: rgba(99, 102, 241, 0.1); color: #6366f1; border: 1px solid rgba(99, 102, 241, 0.3); border-radius: 6px; cursor: pointer; font-size: 12px;">Open</button>
                        <button onclick="encryptFile('${d.file_path.replace(/\\/g, '\\\\')}')" style="padding: 6px 12px; background: rgba(34, 197, 94, 0.1); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 6px; cursor: pointer; font-size: 12px;">🔒 Encrypt</button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function openFile(filePath) {
    alert(`Opening file: ${filePath}\n\nThis would open the file in the default application.`);
    // TODO: Implement file opening
}

async function encryptFile(filePath) {
    try {
        // 1. Check vault status
        const statusResp = await fetch(`${API_BASE}/api/vault/status`);
        const status = await statusResp.json();

        let password = "dummy"; // Not used if unlocked

        if (!status.unlocked) {
            password = prompt("🔐 Vault is locked. Enter Master Password to unlock:");
            if (!password) return;

            // Unlock first
            const unlockResp = await fetch(`${API_BASE}/api/vault/unlock?password=${encodeURIComponent(password)}`, {
                method: 'POST'
            });

            if (!unlockResp.ok) {
                alert("❌ Incorrect password!");
                return;
            }
        }

        if (!confirm(`Encrypt this file?\n${filePath}\n\nIt will be moved to Secure Vault.`)) return;

        // 2. Encrypt
        const resp = await fetch(`${API_BASE}/api/vault/encrypt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                file_path: filePath,
                password: password,
                delete_original: false
            })
        });

        if (resp.ok) {
            const result = await resp.json();
            alert(`✅ File Encrypted Successfully!\n\nSaved to vault as:\n${result.vault_name}`);
        } else {
            const err = await resp.json();
            alert(`❌ Encryption failed: ${err.detail}`);
        }

    } catch (error) {
        console.error("Encryption error:", error);
        alert("Encryption failed. See console for details.");
    }
}

function initStandbyMode() {
    const startBtn = document.getElementById('btn-start-watcher');
    const stopBtn = document.getElementById('btn-stop-watcher');
    const addPathBtn = document.getElementById('btn-add-path');

    if (startBtn) startBtn.addEventListener('click', startWatcher);
    if (stopBtn) stopBtn.addEventListener('click', stopWatcher);
    if (addPathBtn) addPathBtn.addEventListener('click', addWatchPath);

    updateWatcherStatus();
}

async function startWatcher() {
    try {
        showLoading('Starting file monitoring...');
        const response = await fetch(`${API_BASE}/api/watcher/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const result = await response.json();
        hideLoading();

        if (result.status === 'started' || result.status === 'already_running') {
            updateWatcherUI(true, result.paths || []);
        } else {
            console.error('Watcher failed to start:', result);
            alert('❌ Failed to start monitoring: ' + (result.message || 'Unknown error'));
        }
    } catch (error) {
        hideLoading();
        console.error('Error starting watcher:', error);
    }
}

async function stopWatcher() {
    try {
        const response = await fetch(`${API_BASE}/api/watcher/stop`, { method: 'POST' });
        const result = await response.json();

        if (result.status === 'stopped') {
            updateWatcherUI(false, []);
        }
    } catch (error) {
        console.error('Error stopping watcher:', error);
    }
}

async function updateWatcherStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/watcher/status`);
        const result = await response.json();

        const isRunning = result.status === 'running';
        updateWatcherUI(isRunning, result.watched_paths || []);
    } catch (error) {
        console.error('Error getting watcher status:', error);
    }
}

function updateWatcherUI(isRunning, paths) {
    const statusDot = document.getElementById('watcher-status-dot');
    const statusText = document.getElementById('watcher-status-text');
    const startBtn = document.getElementById('btn-start-watcher');
    const stopBtn = document.getElementById('btn-stop-watcher');
    const pathsList = document.getElementById('watch-paths-list');

    if (statusDot) {
        statusDot.className = `status-dot ${isRunning ? 'running' : 'stopped'}`;
        statusDot.style.color = isRunning ? 'var(--success)' : 'var(--text-muted)';
    }
    if (statusText) {
        statusText.textContent = isRunning ? 'Running' : 'Stopped';
    }
    if (startBtn) {
        startBtn.disabled = isRunning;
    }
    if (stopBtn) {
        stopBtn.disabled = !isRunning;
    }
    if (pathsList && paths.length > 0) {
        pathsList.innerHTML = paths.map(p => `
            <div class="path-item" style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: rgba(255,255,255,0.03); border-radius: 8px; margin-bottom: 8px;">
                <span>📂 ${p}</span>
                <button class="btn-remove-path" data-path="${p}" style="background: rgba(255,0,0,0.1); color: #ff6b6b; border: 1px solid rgba(255,0,0,0.3); padding: 4px 12px; border-radius: 6px; cursor: pointer; font-size: 12px;">✕ Remove</button>
            </div>
        `).join('');

        // Add remove button event listeners
        document.querySelectorAll('.btn-remove-path').forEach(btn => {
            btn.addEventListener('click', () => removeWatchPath(btn.dataset.path));
        });
    } else if (pathsList) {
        pathsList.innerHTML = '<p class="empty-state">No folders being monitored</p>';
    }
}

async function addWatchPath() {
    const input = document.getElementById('new-folder-path');
    const path = input.value.trim();

    if (!path) {
        alert('Please enter a folder path');
        return;
    }

    try {
        showLoading('Adding folder...');
        const response = await fetch(`${API_BASE}/api/watcher/add-path`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path })
        });
        const result = await response.json();
        hideLoading();

        if (result.status === 'added' || result.status === 'already_watching') {
            input.value = ''; // Clear input
            updateWatcherStatus(); // Refresh the list
        } else {
            alert(result.message || 'Failed to add folder');
        }
    } catch (error) {
        hideLoading();
        console.error('Error adding path:', error);
        alert('Failed to add folder. Make sure the path exists.');
    }
}

async function removeWatchPath(path) {
    if (!confirm(`Remove "${path}" from monitoring?`)) {
        return;
    }

    try {
        showLoading('Removing folder...');
        const response = await fetch(`${API_BASE}/api/watcher/remove-path`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path })
        });
        const result = await response.json();
        hideLoading();

        if (result.status === 'removed') {
            updateWatcherStatus(); // Refresh the list
        } else {
            alert(result.message || 'Failed to remove folder');
        }
    } catch (error) {
        hideLoading();
        console.error('Error removing path:', error);
        alert('Failed to remove folder');
    }
}

// ============== SYSTEM SCANNER ==============

let scanPollInterval = null;

// System Scanner - Folder management
let scanFolders = [];

function initSystemScanner() {
    const startBtn = document.getElementById('btn-start-scan');
    const pauseBtn = document.getElementById('btn-pause-scan');
    const cancelBtn = document.getElementById('btn-cancel-scan');
    const addFolderBtn = document.getElementById('btn-add-scan-folder');
    const clearBtn = document.getElementById('btn-clear-results');

    if (startBtn) startBtn.addEventListener('click', startSystemScan);
    if (pauseBtn) pauseBtn.addEventListener('click', pauseSystemScan);
    if (cancelBtn) cancelBtn.addEventListener('click', cancelSystemScan);
    if (addFolderBtn) addFolderBtn.addEventListener('click', addScanFolder);
    if (clearBtn) clearBtn.addEventListener('click', clearScanResults);

    // Initialize default folders
    initializeScanFolders();

    // Load initial dashboard data
    loadRiskDashboard();
}

async function initializeScanFolders() {
    try {
        const res = await fetch(`${API_BASE}/api/scan/defaults`);
        const data = await res.json();
        if (data.paths && data.paths.length > 0) {
            scanFolders = data.paths;
        } else {
            // Fallback if backend fails to detect
            scanFolders = ['C:\\Users\\Public\\Documents', 'C:\\Users\\Public\\Downloads'];
        }
    } catch (e) {
        console.error("Failed to fetch scan defaults:", e);
        scanFolders = [];
    }
    updateScanFoldersList();
}

function updateScanFoldersList() {
    const list = document.getElementById('scan-folders-list');
    if (!list) return;

    if (scanFolders.length === 0) {
        list.innerHTML = '<p class="empty-state">No folders selected. Add folders to scan.</p>';
        return;
    }

    list.innerHTML = scanFolders.map((folder, index) => `
        <div class="path-item" style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: rgba(99, 102, 241, 0.05); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 8px; margin-bottom: 8px;">
            <span>📁 ${folder}</span>
            <button class="btn-remove-scan-folder" data-index="${index}" style="background: rgba(255,0,0,0.1); color: #ff6b6b; border: 1px solid rgba(255,0,0,0.3); padding: 4px 12px; border-radius: 6px; cursor: pointer; font-size: 12px;">✕ Remove</button>
        </div>
    `).join('');

    // Add remove event listeners
    document.querySelectorAll('.btn-remove-scan-folder').forEach(btn => {
        btn.addEventListener('click', () => removeScanFolder(parseInt(btn.dataset.index)));
    });
}

function addScanFolder() {
    const input = document.getElementById('scan-folder-path');
    const path = input.value.trim();

    if (!path) {
        alert('Please enter a folder path');
        return;
    }

    if (scanFolders.includes(path)) {
        alert('This folder is already in the scan list');
        return;
    }

    scanFolders.push(path);
    input.value = '';
    updateScanFoldersList();
}

function removeScanFolder(index) {
    if (confirm(`Remove "${scanFolders[index]}" from scan list?`)) {
        scanFolders.splice(index, 1);
        updateScanFoldersList();
    }
}

async function clearScanResults() {
    if (!confirm('Clear all previous scan results? This will reset the dashboard and file list.')) {
        return;
    }

    try {
        showLoading('Clearing results...');

        // Call backend to clear
        await fetch(`${API_BASE}/api/scan/clear`, { method: 'POST' });

        hideLoading();
        alert('✓ Results cleared!');

        // Reload page to reset UI
        loadRiskDashboard();
    } catch (error) {
        hideLoading();
        console.error('Error clearing results:', error);
        alert('Error clearing results');
    }
}

async function startSystemScan() {
    if (scanFolders.length === 0) {
        alert("⚠️ Please add at least one folder to scan.");
        return;
    }

    try {
        showLoading('Starting system scan...');

        const response = await fetch(`${API_BASE}/api/scan/system`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ paths: scanFolders })
        });
        const result = await response.json();
        hideLoading();

        if (result.status === 'started') {
            document.getElementById('btn-start-scan').disabled = true;
            document.getElementById('btn-pause-scan').disabled = false;
            document.getElementById('btn-cancel-scan').disabled = false;

            // Start polling for progress
            scanPollInterval = setInterval(updateScanProgress, 2000);
        } else {
            alert(`⚠️ Scan failed to start: ${result.message || 'Check if folder paths are valid.'}`);
        }
    } catch (error) {
        hideLoading();
        console.error('Error starting scan:', error);
        alert(`❌ Error starting scan: ${error.message}`);
    }
}

async function pauseSystemScan() {
    try {
        const pauseBtn = document.getElementById('btn-pause-scan');
        const isPaused = pauseBtn.textContent.includes('Resume');

        const endpoint = isPaused ? '/api/scan/resume' : '/api/scan/pause';
        await fetch(`${API_BASE}${endpoint}`, { method: 'POST' });

        pauseBtn.textContent = isPaused ? '⏸️ Pause' : '▶️ Resume';
    } catch (error) {
        console.error('Error pausing scan:', error);
    }
}

async function cancelSystemScan() {
    try {
        await fetch(`${API_BASE}/api/scan/cancel`, { method: 'POST' });

        if (scanPollInterval) {
            clearInterval(scanPollInterval);
            scanPollInterval = null;
        }

        document.getElementById('btn-start-scan').disabled = false;
        document.getElementById('btn-pause-scan').disabled = true;
        document.getElementById('btn-cancel-scan').disabled = true;
        document.getElementById('scan-current-file').textContent = 'Scan cancelled';
    } catch (error) {
        console.error('Error cancelling scan:', error);
    }
}

async function updateScanProgress() {
    try {
        const response = await fetch(`${API_BASE}/api/scan/progress`);
        const progress = await response.json();

        const progressFill = document.getElementById('scan-progress-fill');
        const filesCount = document.getElementById('scan-files-count');
        const piiCount = document.getElementById('scan-pii-count');
        const currentFile = document.getElementById('scan-current-file');

        if (progressFill) progressFill.style.width = `${progress.progress_percent || 0}%`;
        if (filesCount) filesCount.textContent = progress.files_scanned || 0;
        if (piiCount) piiCount.textContent = progress.files_with_pii || 0;
        if (currentFile) currentFile.textContent = progress.current_file || 'Scanning...';

        // Update risk buckets
        document.getElementById('high-risk-count').textContent = progress.high_risk_files || 0;
        document.getElementById('medium-risk-count').textContent = progress.medium_risk_files || 0;
        document.getElementById('low-risk-count').textContent = progress.low_risk_files || 0;

        // Check if scan is complete
        if (progress.status === 'completed' || progress.status === 'cancelled') {
            if (scanPollInterval) {
                clearInterval(scanPollInterval);
                scanPollInterval = null;
            }

            document.getElementById('btn-start-scan').disabled = false;
            document.getElementById('btn-pause-scan').disabled = true;
            document.getElementById('btn-cancel-scan').disabled = true;

            if (progress.status === 'completed') {
                loadRiskDashboard();
            }
        }
    } catch (error) {
        console.error('Error getting scan progress:', error);
    }
}

async function loadRiskDashboard() {
    try {
        const response = await fetch(`${API_BASE}/api/inventory/buckets`);
        const data = await response.json();

        const buckets = data.buckets || {};
        document.getElementById('high-risk-count').textContent = buckets.HIGH?.count || 0;
        document.getElementById('medium-risk-count').textContent = buckets.MEDIUM?.count || 0;
        document.getElementById('low-risk-count').textContent = buckets.LOW?.count || 0;

        // Load high-risk files
        const highRiskFiles = buckets.HIGH?.files || [];
        const filesList = document.getElementById('high-risk-files-list');

        if (filesList) {
            if (highRiskFiles.length === 0) {
                filesList.innerHTML = '<p class="empty-state">No high-risk files found</p>';
            } else {
                filesList.innerHTML = highRiskFiles.slice(0, 10).map(f => `
                    <div class="file-item">
                        <span class="file-name">${f.file_name}</span>
                        <span class="file-risk high">Score: ${Math.round(f.risk_score)}%</span>
                    </div>
                `).join('');
            }
        }
    } catch (error) {
        console.error('Error loading risk dashboard:', error);
    }
}

// ============== ENCRYPTED VAULT ==============

// Explainability Functions
function generateExplanations(entities) {
    if (!entities || entities.length === 0) return [];

    // Simulating AI generation for demo purposes
    // In production, this would call /api/explain
    return entities.map(e => {
        const type = e.entity_type;
        let explanation = "";
        let impact = "";

        if (type === 'PHONE_NUMBER') {
            explanation = "Detected a 10-digit sequence matching standard mobile numbering patterns.";
            impact = "High risk of solicitations or identity tracking if exposed.";
        } else if (type === 'EMAIL_ADDRESS') {
            explanation = "Identified email syntax (user@domain.com).";
            impact = "Direct communication channel; high potential for phishing/spam.";
        } else if (type === 'AADHAAR_NUMBER') {
            explanation = "Found 12-digit UIDAI pattern with Verhoeff algorithm check.";
            impact = "Critical identity document; severe risk of identity theft.";
        } else if (type === 'PAN_CARD') {
            explanation = "Matched 10-char alphanumeric Permanent Account Number format.";
            impact = "Financial identifier; used for tax fraud or unauthorized credit checks.";
        } else {
            explanation = `Identified sensitive ${type.toLowerCase().replace('_', ' ')} pattern.`;
            impact = "Potential privacy violation under DPDP/GDPR.";
        }

        return {
            type: type,
            text: e.text,
            explanation: explanation,
            impact: impact
        };
    });
}

function renderExplanations(explanations) {
    const list = document.getElementById('explanations-list');
    if (!list) return;

    if (explanations.length === 0) {
        list.innerHTML = '<p class="empty-state">No explanations generated.</p>';
        return;
    }

    list.innerHTML = explanations.map(exp => `
            <div class="explanation-item">
                <h4>
                    <span class="entity-type">${exp.type}</span>
                    <span class="entity-preview">"${exp.text}"</span>
                </h4>
                <p><strong>Analysis:</strong> ${exp.explanation}</p>
                <p style="margin-top:4px; color:var(--text-muted);"><strong>Impact:</strong> ${exp.impact}</p>
            </div>
        `).join('');
}

function toggleAdversarialPanel(show) {
    const panel = document.getElementById('adversarial-panel');
    if (panel) {
        if (show) {
            panel.classList.remove('hidden');
            // Simulate running test
            setTimeout(() => {
                document.getElementById('robustness-score').textContent = "92%";
                document.getElementById('robustness-bar').style.width = "92%";
                document.getElementById('adversarial-vulnerabilities').innerHTML = `
                        <p>✅ <strong>Context Injection:</strong> Resisted prompt injection attacks.</p>
                        <p>✅ <strong>Obfuscation:</strong> Detected spacing manipulation (e.g., "P A N").</p>
                        <p>⚠️ <strong>Homoglyphs:</strong> Minor vulnerability to Cyrillic character substitution.</p>
                    `;
            }, 1500);
        } else {
            panel.classList.add('hidden');
        }
    }
}

function initVault() {
    const unlockBtn = document.getElementById('btn-unlock-vault');
    const lockBtn = document.getElementById('btn-lock-vault');
    const initVaultLink = document.getElementById('btn-init-vault');
    const vaultUploadZone = document.getElementById('vault-upload-zone');
    const vaultFileInput = document.getElementById('vault-file-input');
    const vaultSelector = document.getElementById('vault-selector');
    const btnNewVault = document.getElementById('btn-new-vault');
    const btnExportKey = document.getElementById('btn-export-public-key');
    const btnImportKey = document.getElementById('btn-import-key');

    if (unlockBtn) unlockBtn.addEventListener('click', unlockVault);
    if (lockBtn) lockBtn.addEventListener('click', lockVault);
    if (initVaultLink) initVaultLink.addEventListener('click', (e) => {
        e.preventDefault();
        initializeVault();
    });

    if (vaultUploadZone) {
        vaultUploadZone.addEventListener('click', () => vaultFileInput?.click());
        vaultUploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            vaultUploadZone.style.borderColor = 'var(--accent-primary)';
        });
        vaultUploadZone.addEventListener('dragleave', () => {
            vaultUploadZone.style.borderColor = '';
        });
        vaultUploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            vaultUploadZone.style.borderColor = '';
            if (e.dataTransfer.files.length) {
                addFileToVault(e.dataTransfer.files[0]);
            }
        });
    }

    if (vaultFileInput) {
        vaultFileInput.addEventListener('change', (e) => {
            if (e.target.files.length) {
                addFileToVault(e.target.files[0]);
            }
        });
    }

    if (vaultSelector) {
        vaultSelector.addEventListener('change', (e) => switchVault(e.target.value));
    }
    if (btnNewVault) {
        btnNewVault.addEventListener('click', () => {
            const name = prompt("Enter a name for the new vault unit:");
            if (name) {
                initializeVault(name);
            }
        });
    }

    if (btnExportKey) {
        btnExportKey.addEventListener('click', exportPublicKey);
    }
    if (btnImportKey) {
        btnImportKey.addEventListener('click', importRecipientKey);
    }

    // Check vault status and load list
    checkVaultStatus();
    loadVaultList();
}

async function loadVaultList() {
    try {
        const response = await fetch(`${API_BASE}/api/vaults`);
        const data = await response.json();
        const selector = document.getElementById('vault-selector');
        if (selector && data.vaults) {
            // Preservation of 'default' if empty
            const vaults = data.vaults.length > 0 ? data.vaults : ['default'];
            selector.innerHTML = vaults.map(v => `<option value="${v}">${v}</option>`).join('');

            // Check if we need to select the current one
            const currentName = document.getElementById('current-vault-name')?.textContent;
            if (currentName) selector.value = currentName;
        }
    } catch (err) {
        console.error("Error loading vault list:", err);
    }
}

async function switchVault(name) {
    try {
        showLoading(`Switching to vault: ${name}...`);
        const response = await fetch(`${API_BASE}/api/vaults/select?name=${encodeURIComponent(name)}`, {
            method: 'POST'
        });
        const result = await response.json();
        hideLoading();

        if (result.status === 'success') {
            document.getElementById('current-vault-name').textContent = name;
            state.currentVaultName = name; // Update state
            // Re-check status and files for the new vault
            checkVaultStatus();
        }
    } catch (err) {
        hideLoading();
        alert("Failed to switch vault: " + err.message);
    }
}

async function checkVaultStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/vault/status?name=${encodeURIComponent(state.currentVaultName)}`);
        const status = await response.json();

        const isUnlocked = status.status === 'unlocked';
        showVaultView(isUnlocked);

        if (isUnlocked) {
            loadVaultFiles();
        }
    } catch (error) {
        console.error('Error checking vault status:', error);
    }
}

async function initializeVault(name = "default") {
    const password = document.getElementById('vault-password')?.value || prompt(`Enter master password for vault "${name}":`);
    if (!password) {
        alert('Password is required to initialize a vault');
        return;
    }

    try {
        showLoading(`Initializing vault "${name}"...`);
        const response = await fetch(`${API_BASE}/api/vault/initialize?password=${encodeURIComponent(password)}&name=${encodeURIComponent(name)}`, {
            method: 'POST'
        });
        const result = await response.json();
        hideLoading();

        if (result.status === 'success') {
            showVaultView(true);
            loadVaultFiles();
        } else {
            alert(result.message || 'Failed to initialize vault');
        }
    } catch (error) {
        hideLoading();
        console.error('Error initializing vault:', error);
    }
}

async function unlockVault() {
    const password = document.getElementById('vault-password')?.value;
    if (!password) {
        alert('Please enter the master password');
        return;
    }

    try {
        showLoading('Unlocking vault...');
        const response = await fetch(`${API_BASE}/api/vault/unlock?password=${encodeURIComponent(password)}&name=${encodeURIComponent(state.currentVaultName)}`, {
            method: 'POST'
        });
        const result = await response.json();
        hideLoading();

        if (result.status === 'success') {
            showVaultView(true);
            loadVaultFiles();
        } else {
            alert(result.message || 'Invalid password');
        }
    } catch (error) {
        hideLoading();
        console.error('Error unlocking vault:', error);
    }
}

async function lockVault() {
    try {
        await fetch(`${API_BASE}/api/vault/lock?name=${encodeURIComponent(state.currentVaultName)}`, { method: 'POST' });
        showVaultView(false);
        document.getElementById('vault-password').value = '';
    } catch (error) {
        console.error('Error locking vault:', error);
    }
}

function showVaultView(isUnlocked) {
    const lockedView = document.getElementById('vault-locked-view');
    const unlockedView = document.getElementById('vault-unlocked-view');

    if (lockedView) lockedView.style.display = isUnlocked ? 'none' : 'block';
    if (unlockedView) unlockedView.classList.toggle('hidden', !isUnlocked);
}

async function loadVaultFiles() {
    try {
        const response = await fetch(`${API_BASE}/api/vault/files?name=${encodeURIComponent(state.currentVaultName)}`);
        const data = await response.json();

        const filesList = document.getElementById('vault-files-list');
        if (!filesList) return;

        const files = data.files || [];
        if (files.length === 0) {
            filesList.innerHTML = '<p class="empty-state">No files in vault</p>';
        } else {
            filesList.innerHTML = files.map(f => `
                <div class="file-item" style="display: flex; justify-content: space-between; align-items: center; padding: 10px; border-bottom: 1px solid rgba(255,255,255,0.1);">
                    <div style="flex-grow: 1;">
                        <span class="file-name" style="display: block; font-weight: 500;">🔐 ${f.original_name}</span>
                        <span style="color: var(--text-muted); font-size: 12px;">
                            ${formatFileSize(f.original_size)}
                        </span>
                    </div>
                    <button class="btn-delete-file" 
                            onclick="deleteVaultFile('${f.vault_name}')"
                            style="background: transparent; border: none; color: #ef4444; cursor: pointer; padding: 5px; opacity: 0.7; transition: opacity 0.2s;"
                            onmouseover="this.style.opacity='1'" 
                            onmouseout="this.style.opacity='0.7'">
                        🗑️
                    </button>
                </div>
            `).join('');
        }
    } catch (error) {
        console.error('Error loading vault files:', error);
    }

} // End loadVaultFiles

async function deleteVaultFile(filename) {
    if (!confirm(`Are you sure you want to delete this file from the vault?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/vault/remove?name=${encodeURIComponent(state.currentVaultName)}&filename=${encodeURIComponent(filename)}`, {
            method: 'DELETE'
        });

        const result = await response.json();
        if (result.status === 'success') {
            loadVaultFiles(); // Refresh list
        } else {
            alert(result.message || 'Failed to delete file');
        }
    } catch (error) {
        console.error('Error deleting vault file:', error);
        alert('Failed to delete file from vault');
    }
}

async function addFileToVault(file) {
    try {
        console.log("Starting upload for:", file.name);

        showLoading('Encrypting and adding file to vault...');

        const formData = new FormData();
        formData.append('file', file);

        const uploadResp = await fetch(`${API_BASE}/api/upload`, {
            method: 'POST',
            body: formData
        });

        if (!uploadResp.ok) {
            const err = await uploadResp.json().catch(() => ({}));
            alert("Upload Failed! Status: " + uploadResp.status);
            throw new Error(err.detail || 'File upload failed');
        }

        const uploadResult = await uploadResp.json();
        const uploadedFilePath = uploadResult.file_path; // Matches Backend

        if (!uploadedFilePath) throw new Error("No Path Returned");

        if (!uploadedFilePath) throw new Error("No Path Returned");

        const encryptResp = await fetch(`${API_BASE}/api/vault/encrypt?name=${encodeURIComponent(state.currentVaultName)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                file_path: uploadedFilePath,
                delete_original: true
            })
        });

        const result = await encryptResp.json();
        hideLoading();

        if (result.status === 'success') {
            loadVaultFiles();
            checkVaultStatus();
        } else {
            if (encryptResp.status === 401 || encryptResp.status === 403) {
                alert("Session expired or vault locked. Please unlock again.");
                showVaultView(false);
            } else {
                alert(`❌ Encryption failed: ${result.message || result.detail}`);
            }
        }

    } catch (error) {
        hideLoading();
        console.error("Vault add error:", error);
        alert(`Failed with Error: ${error.message}`);
    }
}

async function exportPublicKey() {
    try {
        showLoading('Retrieving public key...');
        const response = await fetch(`${API_BASE}/api/vault/keys/public?name=${encodeURIComponent(state.currentVaultName)}`);
        const data = await response.json();
        hideLoading();

        if (data.public_key) {
            const blob = new Blob([data.public_key], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${state.currentVaultName}_public.pub`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            alert("✅ Public key exported successfully!");
        } else {
            alert("❌ Failed to export public key: " + (data.detail || "Unknown error"));
        }
    } catch (error) {
        hideLoading();
        console.error("Export key error:", error);
        alert("❌ Error exporting key: " + error.message);
    }
}

async function importRecipientKey() {
    try {
        const keyName = prompt("Enter a name/label for this recipient key (e.g., Alice):");
        if (!keyName) return;

        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.pub,.pem,.txt';

        input.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = async (event) => {
                const publicKey = event.target.result;

                try {
                    showLoading('Importing key...');
                    const response = await fetch(`${API_BASE}/api/vault/keys/import?name=${encodeURIComponent(state.currentVaultName)}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            name: keyName,
                            public_key: publicKey
                        })
                    });

                    const result = await response.json();
                    hideLoading();

                    if (result.status === 'success') {
                        alert(`✅ Key "${keyName}" imported successfully!`);
                    } else {
                        alert("❌ Failed to import key: " + (result.message || result.detail));
                    }
                } catch (err) {
                    hideLoading();
                    alert("❌ Error sending key: " + err.message);
                }
            };
            reader.readAsText(file);
        };

        input.click();
    } catch (error) {
        console.error("Import key UI error:", error);
    }
}

function formatFileSize(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Initialized via main DOMContentLoaded above

console.log('SilentSeal Enhanced initialized');

// Audit Log Feature
async function initAuditLog() {
    const auditBtn = document.querySelector('.nav-item[data-page="audit"]');
    if (auditBtn) {
        auditBtn.addEventListener('click', loadAuditLogs);
    }
}

async function loadAuditLogs() {
    const container = document.getElementById('audit-log-container');
    if (!container) return;

    container.innerHTML = '<div class="loading-spinner"></div> Loading logs...';

    try {
        console.log("Fetching audit logs...");
        const response = await fetch(`${API_BASE}/api/audit/logs?limit=50`);
        console.log("Audit response status:", response.status);
        if (!response.ok) {
            const errText = await response.text();
            throw new Error(`Server returned ${response.status}: ${errText}`);
        }

        const data = await response.json();
        console.log("Audit data received:", data);
        renderAuditLogs(data.logs);
    } catch (error) {
        console.error("Audit log error:", error);
        container.innerHTML = `<p class="error-state">Failed to load audit logs: ${error.message}</p>`;
    }
}

async function clearAuditLogs() {
    if (!confirm("⚠️ Are you sure you want to clear ALL audit logs? This action cannot be undone.")) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/audit/clear-all`, {
            method: 'POST'
        });

        if (response.ok) {
            alert("✅ Audit logs cleared successfully.");
            loadAuditLogs();
        } else {
            const err = await response.json();
            alert("❌ Failed to clear logs: " + (err.detail || "Unknown error"));
        }
    } catch (error) {
        alert("❌ Error clearing logs: " + error.message);
    }
}

function renderAuditLogs(logs) {
    const container = document.getElementById('audit-log-container');
    if (!container) return;

    // Safety check: Ensure logs is an array
    if (!Array.isArray(logs)) {
        console.error("Invalid logs data format:", logs);
        container.innerHTML = '<p class="error-state">Failed to render logs: Data is not in a list format.</p>';
        return;
    }

    if (logs.length === 0) {
        container.innerHTML = '<p class="empty-state">No audit records found.</p>';
        return;
    }

    const tableHtml = `
                <table class="audit-table" style="width: 100%; border-collapse: collapse; margin-top: 20px;">
                    <thead>
                        <tr style="background: rgba(99, 102, 241, 0.1); text-align: left;">
                            <th style="padding: 12px; border-bottom: 2px solid rgba(99, 102, 241, 0.2);">Time</th>
                            <th style="padding: 12px; border-bottom: 2px solid rgba(99, 102, 241, 0.2);">Action</th>
                            <th style="padding: 12px; border-bottom: 2px solid rgba(99, 102, 241, 0.2);">File</th>
                            <th style="padding: 12px; border-bottom: 2px solid rgba(99, 102, 241, 0.2);">Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${logs.map(log => {
        let timeDisplay = '-';
        try {
            // If it's a number, it's a unix timestamp. If it's a string, try parsing it.
            // SQLite stored ISO string or CURRENT_TIMESTAMP
            let ts = log.timestamp;
            let date;

            if (!isNaN(ts)) {
                // Unix timestamp
                date = new Date(ts * 1000);
            } else {
                // ISO String. If it doesn't have a timezone, assume UTC if it's from our backend
                if (ts && !ts.includes('+') && !ts.endsWith('Z')) {
                    ts += 'Z';
                }
                date = new Date(ts);
            }

            // Format to be readable but compact
            timeDisplay = date.toLocaleString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (e) {
            console.warn("Date parse error:", e, log.timestamp);
            timeDisplay = log.timestamp || '-';
        }

        let details = '-';
        try {
            const data = typeof log.details === 'string' ? JSON.parse(log.details) : log.details;
            details = `<pre style="font-size: 11px; margin: 0; color: var(--text-muted); max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${JSON.stringify(data)}</pre>`;
        } catch (e) {
            details = log.details || '-';
        }

        return `
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;">
                <td style="padding: 12px; font-size: 13px; color: var(--text-secondary); white-space: nowrap;">${timeDisplay}</td>
                <td style="padding: 12px;">
                    <span class="badge" style="background: ${log.action_type === 'UPLOAD' ? 'rgba(99, 102, 241, 0.2)' : 'rgba(16, 185, 129, 0.2)'}; 
                          color: ${log.action_type === 'UPLOAD' ? '#818cf8' : '#34d399'};">
                        ${log.action_type}
                    </span>
                </td>
                <td style="padding: 12px; font-size: 13px;">${log.file_name || '-'}</td>
                <td style="padding: 12px;">${details}</td>
            </tr>
        `;
    }).join('')}
                    </tbody>
                </table>
            `;

    container.innerHTML = tableHtml;
}

// Processed Documents Feature
async function initProcessedDocuments() {
    const docsBtn = document.querySelector('.nav-item[data-page="documents"]');
    if (docsBtn) {
        docsBtn.addEventListener('click', loadProcessedDocuments);
    }
}

async function loadProcessedDocuments() {
    const container = document.getElementById('documents-grid');
    if (!container) return;

    container.innerHTML = '<div class="loading-spinner"></div> Loading documents...';

    try {
        console.log("Fetching processed documents...");
        // Try to fetch from inventory if available
        const response = await fetch(`${API_BASE}/api/inventory/files?sort_by=risk_score`);

        let files = [];
        if (response.ok) {
            const data = await response.json();
            files = data.files || [];
            console.log("Inventory files received:", files);
        } else {
            // Fallback to audit logs
            console.log("Inventory fetch failed, trying audit fallback...");
            const auditResp = await fetch(`${API_BASE}/api/audit/logs?limit=20&action=upload`);
            if (auditResp.ok) {
                const data = await auditResp.json();
                files = data.logs.map(log => ({
                    file_name: log.file_name || 'Unknown',
                    risk_level: 'SCANNED',
                    timestamp: log.timestamp
                }));
            }
        }

        renderProcessedDocuments(files);
    } catch (error) {
        console.error("Documents error:", error);
        container.innerHTML = '<p class="error-state">Failed to load documents.</p>';
    }
}

function renderProcessedDocuments(files) {
    const container = document.getElementById('documents-grid');
    if (!container) return;

    if (!files || files.length === 0) {
        container.innerHTML = '<p class="empty-state">No processed documents found.</p>';
        return;
    }

    container.innerHTML = files.map(file => {
        let timeDisplay = '-';
        try {
            const date = isNaN(file.timestamp) ? new Date(file.timestamp) : new Date(file.timestamp * 1000);
            if (isNaN(date.getTime()) && !file.timestamp) {
                timeDisplay = new Date().toLocaleDateString();
            } else {
                timeDisplay = date.toLocaleDateString();
            }
        } catch (e) {
            timeDisplay = new Date().toLocaleDateString();
        }

        const riskColor = file.risk_level === 'HIGH' || file.risk_level === 'CRITICAL' ? '#ef4444' : file.risk_level === 'MEDIUM' ? '#f59e0b' : '#22c55e';
        return `
                    <div class="document-card" style="background: rgba(255,255,255,0.05); padding: 16px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.1); width: 100%;">
                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
                            <div style="font-size: 24px;">📄</div>
                            <span style="background: ${riskColor}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: bold;">${file.risk_level || 'SCANNED'}</span>
                        </div>
                        <h3 style="font-size: 14px; margin-bottom: 4px; word-break: break-all; color: #fff;">${file.file_name || (file.path ? file.path.split(/[\\/]/).pop() : 'Unknown File')}</h3>
                        <p style="font-size: 12px; color: #9ca3af;">${timeDisplay}</p>
                    </div>
                 `;
    }).join('');
}

// ============== REMEDIATION WORKFLOWS ==============

function initRemediation() {
    // Buttons inside remediation list are dynamic
}

async function loadRemediationHistory() {
    const list = document.getElementById('remediation-history-list');
    if (!list) return;

    list.innerHTML = '<div class="loading-spinner"></div> Loading history...';
    try {
        const response = await fetch(`${API_BASE}/api/remediation/history`);
        const data = await response.json();
        const history = data.history || [];

        if (history.length === 0) {
            list.innerHTML = '<p class="empty-state">No remediation actions recorded.</p>';
            return;
        }

        list.innerHTML = history.map(item => `
            <div class="file-item" style="border-left: 4px solid var(--accent-primary);">
                <div style="flex: 1;">
                    <span class="file-name">${item.action_type}</span>
                    <span style="font-size: 12px; color: var(--text-muted);">
                        ${item.file_path} • ${new Date(item.timestamp).toLocaleString()}
                    </span>
                </div>
                <span class="status-badge status-${item.status.toLowerCase()}">${item.status}</span>
            </div>
        `).join('');
    } catch (e) {
        list.innerHTML = `<p class="error-state">Error: ${e.message}</p>`;
    }
}

// ============== INCIDENT PLAYBOOKS ==============

window.app = window.app || {};
window.app.playbooks = {
    list: async () => {
        const incidentsList = document.getElementById('incidents-list');
        const playbooksList = document.getElementById('playbooks-list');
        if (!incidentsList || !playbooksList) return;

        incidentsList.classList.add('hidden');
        playbooksList.classList.remove('hidden');
        playbooksList.innerHTML = '<div class="loading-spinner"></div> Loading playbooks...';

        try {
            const response = await fetch(`${API_BASE}/api/playbooks`);
            const data = await response.json();
            const playbooks = data.playbooks || [];

            if (playbooks.length === 0) {
                playbooksList.innerHTML = '<p class="empty-state">No playbooks found.</p>';
                return;
            }

            playbooksList.innerHTML = `
                <div style="margin-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 10px;">
                    <h3 style="font-size: 16px;">Standard Response Playbooks</h3>
                </div>
                ${playbooks.map(pb => `
                    <div class="file-item" style="border-left: 4px solid var(--accent-primary);">
                        <div style="flex: 1;">
                            <span class="file-name">${pb.name}</span>
                            <span style="font-size: 12px; color: var(--text-muted);">
                                ${pb.description} • Severity: ${pb.severity}
                            </span>
                        </div>
                        <button class="btn btn-sm btn-primary" onclick="app.playbooks.open('${pb.id}')">View Details</button>
                    </div>
                `).join('')}
            `;
        } catch (e) {
            playbooksList.innerHTML = `<p class="error-state">Error: ${e.message}</p>`;
        }
    },
    open: async (id) => {
        const modal = elements.modal;
        const body = elements.modalBody;

        modal.classList.add('active');
        body.innerHTML = '<div class="loading-spinner"></div> Loading details...';

        try {
            // First check if it's a known incident ID by fetching incidents
            let incident = null;
            try {
                const incResp = await fetch(`${API_BASE}/api/incidents`);
                const incData = await incResp.json();
                incident = (incData.incidents || []).find(i => i.incident_id === id);
            } catch (e) {
                console.warn("Incident lookup failed", e);
            }

            const pbResp = await fetch(`${API_BASE}/api/playbooks`);
            const pbData = await pbResp.json();
            const playbooks = pbData.playbooks || [];

            // If it's an incident, try to find a matching playbook or use default
            let playbook = null;
            if (incident) {
                // Mock logic: choose playbook based on severity or default to pii_leak
                playbook = playbooks.find(p => p.id === 'pii_leak_response') || playbooks[0];
            } else {
                playbook = playbooks.find(p => p.id === id);
            }

            if (!playbook) {
                body.innerHTML = `<h3>Item Not Found: ${id}</h3><p>Could not locate playbook details.</p>`;
                return;
            }

            body.innerHTML = `
                <div style="margin-bottom: 20px;">
                    <span class="badge" style="background: var(--accent-primary); margin-bottom: 10px; display: inline-block;">
                        ${incident ? 'INCIDENT RESPONSE' : 'PLAYBOOK TEMPLATE'}
                    </span>
                    <h3>${playbook.name}</h3>
                    ${incident ? `<p style="font-size: 13px; color: #ef4444; margin-top: 5px;">Responding to Incident #${incident.incident_id.substring(0, 8)}</p>` : ''}
                </div>
                
                <p style="color: var(--text-secondary); margin-bottom: 20px;">${playbook.description}</p>
                
                <div class="playbook-steps" style="margin-top:20px;">
                    <p style="font-weight: bold; margin-bottom: 10px;">Recommended Response Steps:</p>
                    <div style="display: flex; flex-direction: column; gap: 10px; max-height: 300px; overflow-y: auto; padding-right: 5px;">
                        ${Array.from({ length: playbook.steps_count || 4 }).map((_, i) => `
                            <div class="step-item" style="padding:12px; background:rgba(255,255,255,0.05); border-radius:8px; border-left: 3px solid #6366f1;">
                                <div style="display: flex; justify-content: space-between;">
                                    <strong>Step ${i + 1}</strong>
                                    <span style="font-size: 10px; color: var(--text-muted);">REQUIRED</span>
                                </div>
                                <p style="font-size: 13px; margin-top: 5px; color: var(--text-secondary);">
                                    ${i === 0 ? 'Initial assessment and triage.' :
                    i === 1 ? 'Containment and risk mitigation.' :
                        i === 2 ? 'Notification and documentation.' :
                            'Post-incident review and follow-up.'}
                                </p>
                            </div>
                        `).join('')}
                    </div>
                </div>
                <div style="margin-top: 20px; display: flex; gap: 10px;">
                    <button class="btn btn-secondary" onclick="document.getElementById('explanation-modal').classList.remove('active')">Close</button>
                    <button class="btn btn-primary" onclick="alert('In practice, this would initiate a tracked incident response workflow.')">Initiate Response</button>
                </div>
            `;
        } catch (e) {
            body.innerHTML = `<p class="error-state">${e.message}</p>`;
        }
    }
};

function initIncidents() {
    // Initialize playbook buttons if any
}

async function loadIncidents() {
    const list = document.getElementById('incidents-list');
    const playbooksList = document.getElementById('playbooks-list');
    if (!list) return;

    if (playbooksList) {
        playbooksList.classList.add('hidden');
        list.classList.remove('hidden');
    }

    list.innerHTML = `
        <div style="margin-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 10px;">
            <h3 style="font-size: 16px;">Active Detections & Incidents</h3>
        </div>
        <div class="loading-spinner"></div> Loading incidents...
    `;
    try {
        const response = await fetch(`${API_BASE}/api/incidents`);
        const data = await response.json();
        const incidents = data.incidents || [];

        if (incidents.length === 0) {
            list.innerHTML = `
                <div style="margin-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 10px;">
                    <h3 style="font-size: 16px;">Active Detections & Incidents</h3>
                </div>
                <p class="empty-state">No active incidents detected.</p>
            `;
            return;
        }

        list.innerHTML = `
            <div style="margin-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 10px;">
                <h3 style="font-size: 16px;">Active Detections & Incidents</h3>
            </div>
            ${incidents.map(inc => `
                <div class="file-item" style="border-left: 4px solid #ef4444;">
                    <div style="flex: 1;">
                        <span class="file-name">Incident #${inc.incident_id.substring(0, 8)}</span>
                        <span style="font-size: 12px; color: var(--text-muted);">
                            Status: ${inc.status} • Severity: ${inc.severity || 'High'}
                        </span>
                    </div>
                    <button class="btn btn-outline btn-sm" onclick="app.playbooks.open('${inc.incident_id}')">Respond</button>
                </div>
            `).join('')}
        `;
    } catch (e) {
        list.innerHTML = `<p class="error-state">Error: ${e.message}</p>`;
    }
}

// Export to app namespace for button accessibility
window.app = window.app || {};
window.app.showReport = showReport;
window.app.showRemediationOptions = showRemediationOptions;
window.app.previewRedaction = previewRedaction;
window.app.loadIncidents = loadIncidents;
window.app.loadRemediationHistory = loadRemediationHistory;
window.app.clearAuditLogs = clearAuditLogs;
window.app.closeModal = () => {
    elements.modal.classList.remove('active');
    elements.previewContainer.classList.add('hidden');
    if (elements.previewObject) {
        elements.previewObject.data = '';
    }
};

// ============== RBAC & AUTH ==============

window.app = window.app || {};
window.app.rbac = {
    showUsers: async () => {
        const container = document.getElementById('rbac-content');
        container.innerHTML = '<div class="loading-spinner"></div> Loading users...';
        try {
            const res = await fetch(`${API_BASE}/api/auth/users`);
            const data = await res.json();
            container.innerHTML = `
                <table class="audit-table" style="width:100%">
                    <thead><tr><th>User</th><th>Role</th><th>Status</th></tr></thead>
                    <tbody>
                        ${(data.users || []).map(u => `
                            <tr>
                                <td>${u.username}</td>
                                <td><span class="badge badge-primary">${u.role}</span></td>
                                <td>${u.is_active ? 'Active' : 'Inactive'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
                <button class="btn btn-primary" style="margin-top: 15px;">+ Invite User</button>
            `;
        } catch (e) {
            container.innerHTML = `<p class="error-state">Error: ${e.message}</p>`;
        }
        // Update active tab UI
        document.querySelectorAll('#page-rbac .tab-btn, #page-rbac .btn-outline').forEach(b => b.classList.remove('active'));
        document.querySelector('#page-rbac button:first-child').classList.add('active'); // Assumption
    },
    showApprovals: async () => {
        const container = document.getElementById('rbac-content');
        container.innerHTML = '<div class="loading-spinner"></div> Loading approvals...';
        try {
            const res = await fetch(`${API_BASE}/api/auth/approvals/pending`);
            const data = await res.json();
            if ((data.pending || []).length === 0) {
                container.innerHTML = '<p class="empty-state">No pending approvals.</p>';
                return;
            }
            container.innerHTML = (data.pending || []).map(req => `
                <div class="card" style="margin-bottom: 10px;">
                    <div style="display:flex; justify-content:space-between;">
                        <strong>${req.action_type}</strong>
                        <span>By: ${req.requester}</span>
                    </div>
                    <p>${req.resource}</p>
                    <div style="margin-top:10px;">
                        <button class="btn btn-success btn-sm" onclick="app.rbac.approve('${req.request_id}', true)">Approve</button>
                        <button class="btn btn-danger btn-sm" onclick="app.rbac.approve('${req.request_id}', false)">Deny</button>
                    </div>
                </div>
            `).join('');
        } catch (e) {
            container.innerHTML = `<p class="error-state">Error: ${e.message}</p>`;
        }
    },
    approve: async (id, approved) => {
        if (!confirm(approved ? "Approve request?" : "Deny request?")) return;
        try {
            await fetch(`${API_BASE}/api/auth/approve`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ request_id: id, approved: approved, note: 'Reviewed via UI' })
            });
            app.rbac.showApprovals();
        } catch (e) { alert(e.message); }
    }
};

function initRBAC() {
    // Initial load handled by navigation
}

async function loadRBAC() {
    app.rbac.showUsers();
}

// ============== DETECTION RULES ==============

window.app.rules = {
    setMode: async (mode) => {
        try {
            await fetch(`${API_BASE}/api/detection/mode`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode })
            });
            loadRules(); // Refresh display
        } catch (e) { alert(e.message); }
    },
    showAddForm: () => {
        const name = prompt("Rule Name:");
        if (!name) return;
        const pattern = prompt("Regex Pattern:");
        if (!pattern) return;
        app.rules.add(name, pattern, 'custom');
    },
    add: async (name, pattern, type) => {
        try {
            await fetch(`${API_BASE}/api/detection/rules`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, entity_type: type, pattern })
            });
            loadRules();
        } catch (e) { alert(e.message); }
    }
};

function initRules() { }

async function loadRules() {
    const list = document.getElementById('custom-rules-list');
    const modeDisplay = document.getElementById('current-mode-display');

    try {
        // Get mode
        const modeRes = await fetch(`${API_BASE}/api/detection/mode`);
        const modeData = await modeRes.json();
        if (modeDisplay) modeDisplay.textContent = `Current Mode: ${modeData.mode?.toUpperCase()}`;

        // Get rules
        const rulesRes = await fetch(`${API_BASE}/api/detection/rules`);
        const rulesData = await rulesRes.json();

        if (list) {
            const customs = rulesData.custom_rules || [];
            if (customs.length === 0) {
                list.innerHTML = '<p class="empty-state">No custom rules defined.</p>';
            } else {
                list.innerHTML = customs.map(r => `
                    <div class="file-item">
                        <span class="file-name">${r.name}</span>
                        <code style="background:rgba(0,0,0,0.3); padding:2px 4px; border-radius:4px;">${r.pattern}</code>
                    </div>
                `).join('');
            }
        }
    } catch (e) { console.error(e); }
}

// ============== COMPLIANCE ==============

function initCompliance() { }

async function loadComplianceTemplates() {
    const list = document.getElementById('compliance-templates-list');
    if (!list) return;

    list.innerHTML = '<div class="loading-spinner"></div>';
    try {
        const res = await fetch(`${API_BASE}/api/compliance/templates`);
        const data = await res.json();

        list.innerHTML = (data.templates || []).map(t => `
            <div class="card" style="display:flex; flex-direction:column; height:100%;">
                <h3>${t.name}</h3>
                <p style="flex:1; color:var(--text-secondary); font-size:13px; margin:10px 0;">
                    Includes: ${t.sections.slice(0, 3).join(', ')}...
                </p>
                <button class="btn btn-outline" onclick="generateComplianceReport('${t.id}')">Generate Report</button>
            </div>
        `).join('');
    } catch (e) {
        list.innerHTML = `<p class="error-state">${e.message}</p>`;
    }
}

async function generateComplianceReport(id) {
    if (!confirm("Generate report? This may take a moment.")) return;
    try {
        const res = await fetch(`${API_BASE}/api/compliance/generate`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ template_id: id })
        });
        const data = await res.json();
        alert(`Report Generated: ${data.report_name}\nSaved to: ${data.report_path}`);
    } catch (e) { alert(e.message); }
}

// ============== OBSERVABILITY ==============

function initObservability() { }

async function loadObservabilityDashboard() {
    const container = document.getElementById('observability-dashboard');
    if (!container) return;

    container.innerHTML = '<div class="loading-spinner"></div> Fetching metrics...';
    try {
        const res = await fetch(`${API_BASE}/api/observability/dashboard`);
        const data = await res.json();
        const h = data.health || {};
        const sys = h.system || {};

        container.innerHTML = `
            <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
                <div class="stat-card">
                    <div class="stat-icon">💾</div>
                    <div class="stat-info">
                        <span class="stat-value">${sys.memory_percent}%</span>
                        <span class="stat-label">Memory Usage</span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">💿</div>
                    <div class="stat-info">
                        <span class="stat-value">${sys.disk_percent}%</span>
                        <span class="stat-label">Disk Usage</span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">⚡</div>
                    <div class="stat-info">
                        <span class="stat-value">${sys.cpu_percent}%</span>
                        <span class="stat-label">CPU Load</span>
                    </div>
                </div>
                <div class="stat-card accent">
                    <div class="stat-icon">🎯</div>
                    <div class="stat-info">
                        <span class="stat-value">${data.slo_status?.slos_met || 0}/${data.slo_status?.slos_total || 0}</span>
                        <span class="stat-label">SLOs Met</span>
                    </div>
                </div>
            </div>
            
            <div class="card" style="margin-top:20px;">
                <h3>System Health</h3>
                <p>Status: <span style="color:${h.status === 'healthy' ? 'var(--success)' : 'var(--danger)'}; font-weight:bold;">${h.status.toUpperCase()}</span></p>
                <p>Platform: ${sys.platform}</p>
                <p>Last Update: ${new Date(data.timestamp).toLocaleTimeString()}</p>
            </div>
        `;
    } catch (e) {
        container.innerHTML = `<p class="error-state">${e.message}</p>`;
    }
}

// ============== PRIVACY GRAPH ==============

window.app.privacyGraph = {
    simulation: null,
    docs: [],
    selectedDocs: new Set(),

    refresh: async () => {
        const container = document.getElementById('privacy-graph-container');
        const chainsList = document.getElementById('risk-chains-list');
        const docsList = document.getElementById('graph-docs-list');

        if (!container) return;

        // Show loading
        container.innerHTML = '<div style="display:flex; height:100%; align-items:center; justify-content:center; color:white;">Analyzing links...</div>';

        try {
            // 1. Fetch Documents List first to initialize selection if empty
            const docsRes = await fetch(`${API_BASE}/api/privacy/documents`);
            const docsData = await docsRes.json();
            app.privacyGraph.docs = docsData.documents || [];

            // Initialize selection with all docs if new
            if (app.privacyGraph.selectedDocs.size === 0 && app.privacyGraph.docs.length > 0) {
                app.privacyGraph.docs.forEach(d => app.privacyGraph.selectedDocs.add(d.doc_id));
            }

            // Render Docs List UI
            app.privacyGraph.renderDocsList();

            // 2. Fetch Graph Data & Chains
            const [graphRes, chainsRes, summaryRes] = await Promise.all([
                fetch(`${API_BASE}/api/privacy/graph`),
                fetch(`${API_BASE}/api/privacy/chains`),
                fetch(`${API_BASE}/api/privacy/summary`)
            ]);

            let graphData = await graphRes.json();
            const chainsData = await chainsRes.json();
            const summaryData = await summaryRes.json();

            // 3. Filter Graph Data based on selectedDocs
            // Remove document nodes not in selection
            graphData.nodes = graphData.nodes.filter(n => {
                if (n.type === 'document') return app.privacyGraph.selectedDocs.has(n.id);
                return true; // Keep all entities for now, or filter if orphan?
            });

            // Filter links to only connect to selected docs
            graphData.links = graphData.links.filter(l => {
                const targetId = typeof l.target === 'object' ? l.target.id : l.target;
                return app.privacyGraph.selectedDocs.has(targetId);
            });

            // Filter entities that no longer have links
            const activeEntityIds = new Set(graphData.links.map(l => typeof l.source === 'object' ? l.source.id : l.source));
            graphData.nodes = graphData.nodes.filter(n => {
                if (n.type === 'entity') return activeEntityIds.has(n.id);
                return true;
            });

            // Update Summary Stats
            document.getElementById('graph-stat-entities').textContent = graphData.nodes.filter(n => n.type === 'entity').length;
            document.getElementById('graph-stat-docs').textContent = app.privacyGraph.selectedDocs.size;
            document.getElementById('graph-stat-critical').textContent = summaryData.critical_links_count;

            // Update Chains List (Filtered by selected docs)
            const filteredChains = (chainsData.chains || []).filter(c =>
                c.connected_files.some(f => app.privacyGraph.docs.some(d => d.file_name === f && app.privacyGraph.selectedDocs.has(d.doc_id)))
            );

            if (filteredChains.length === 0) {
                chainsList.innerHTML = '<div class="empty-state" style="padding:20px; text-align:center;">No high-risk chains detected in selection.</div>';
            } else {
                chainsList.innerHTML = filteredChains.map(chain => `
                    <div class="card" style="margin-bottom:12px; border-left: 4px solid var(--accent-danger);">
                        <div style="font-weight:bold; margin-bottom:4px;">${chain.entity_type} Chain</div>
                        <div style="font-family:monospace; font-size:11px; background:rgba(255,255,255,0.05); padding:4px; margin-bottom:8px;">${chain.identifier}</div>
                        <div style="font-size:11px; color:var(--text-secondary); margin-bottom:8px;">
                            Connects: ${chain.connected_files.join(', ')}
                        </div>
                        <div style="font-size:11px; color:var(--accent-warning);">
                            💡 ${chain.recommendation}
                        </div>
                    </div>
                `).join('');
            }

            // Render Graph
            app.privacyGraph.render(graphData);

        } catch (e) {
            console.error("Graph error:", e);
            container.innerHTML = `<div style="padding:20px; color:var(--accent-danger);">Error loading graph: ${e.message}</div>`;
        }
    },

    renderDocsList: () => {
        const docsList = document.getElementById('graph-docs-list');
        if (!docsList) return;

        if (app.privacyGraph.docs.length === 0) {
            docsList.innerHTML = '<div class="empty-state" style="padding: 10px; text-align: center; font-size: 12px;">No documents analyzed.</div>';
            return;
        }

        docsList.innerHTML = app.privacyGraph.docs.map(doc => `
            <div style="display: flex; align-items: center; gap: 10px; padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.05);">
                <input type="checkbox" id="check-${doc.doc_id}" 
                    ${app.privacyGraph.selectedDocs.has(doc.doc_id) ? 'checked' : ''}
                    onchange="window.app.privacyGraph.toggleDoc('${doc.doc_id}')">
                <div style="flex: 1; min-width: 0; cursor: pointer;" onclick="document.getElementById('check-${doc.doc_id}').click()">
                    <div style="font-size: 12px; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${doc.file_name}</div>
                    <div style="font-size: 10px; color: var(--text-secondary);">${doc.entity_count} entities</div>
                </div>
                <button title="Remove from graph" style="background: none; border: none; cursor: pointer; color: var(--accent-danger); font-size: 14px;" 
                    onclick="window.app.privacyGraph.deleteDoc('${doc.doc_id}')">🗑️</button>
            </div>
        `).join('');
    },

    toggleDoc: (docId) => {
        if (app.privacyGraph.selectedDocs.has(docId)) {
            app.privacyGraph.selectedDocs.delete(docId);
        } else {
            app.privacyGraph.selectedDocs.add(docId);
        }
        app.privacyGraph.refresh();
    },

    deleteDoc: async (docId) => {
        if (!confirm("Are you sure you want to permanently remove this document from the Privacy Graph? This will not delete the original file.")) return;

        try {
            const res = await fetch(`${API_BASE}/api/privacy/documents/${docId}`, { method: 'DELETE' });
            if (res.ok) {
                app.privacyGraph.selectedDocs.delete(docId);
                app.privacyGraph.refresh();
            }
        } catch (e) {
            alert("Failed to delete: " + e.message);
        }
    },

    render: (data) => {
        const container = document.getElementById('privacy-graph-container');
        if (!container) return;
        container.innerHTML = ''; // Clear

        const width = container.clientWidth;
        const height = container.clientHeight;

        if (data.nodes.length === 0) {
            container.innerHTML = '<div style="display:flex; height:100%; align-items:center; justify-content:center; color:white;">No documents selected for visualization.</div>';
            return;
        }

        const svg = d3.select("#privacy-graph-container")
            .append("svg")
            .attr("width", width)
            .attr("height", height)
            .attr("viewBox", [0, 0, width, height]);

        const simulation = d3.forceSimulation(data.nodes)
            .force("link", d3.forceLink(data.links).id(d => d.id).distance(120))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2));

        const link = svg.append("g")
            .attr("stroke", "#444")
            .attr("stroke-opacity", 0.6)
            .selectAll("line")
            .data(data.links)
            .join("line")
            .attr("stroke-width", d => Math.sqrt(d.value) * 2);

        const node = svg.append("g")
            .selectAll("g")
            .data(data.nodes)
            .join("g")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        // Add circles
        node.append("circle")
            .attr("r", d => d.val ? Math.min(d.val, 25) : 10)
            .attr("fill", d => d.type === 'entity' ? 'var(--accent-primary)' : '#fff')
            .attr("stroke", "#000")
            .attr("stroke-width", 1.5);

        // Add labels
        node.append("text")
            .text(d => d.label)
            .attr("x", 14)
            .attr("y", 4)
            .attr("fill", "#fff")
            .attr("font-size", "11px")
            .attr("pointer-events", "none")
            .style("text-shadow", "1px 1px 3px #000");

        node.append("title")
            .text(d => d.label);

        simulation.on("tick", () => {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node.attr("transform", d => `translate(${d.x},${d.y})`);
        });

        function dragstarted(event) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }

        function dragged(event) {
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        }

        function dragended(event) {
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        }

        if (window.app.privacyGraph.simulation) {
            window.app.privacyGraph.simulation.stop();
        }
        window.app.privacyGraph.simulation = simulation;
    }
};

function initPrivacyGraph() {
    // Initial load handled by navigation
}

async function loadPrivacyGraph() {
    if (window.app.privacyGraph && window.app.privacyGraph.refresh) {
        window.app.privacyGraph.refresh();
    }
}

