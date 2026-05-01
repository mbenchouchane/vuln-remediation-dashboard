const API_BASE = 'http://localhost:5000/api';

let trendRawData = [];
let currentScanVulns = [];
let currentAsset = null;

// Utility: compute simple trend label (up/down/flat) between last two points
function computeTrend(values) {
    if (!values || values.length < 2) return { label: '—', className: '' };
    const last = values[values.length - 1];
    const prev = values[values.length - 2];
    if (last > prev) return { label: `↑ ${((last - prev) / Math.max(prev, 1) * 100).toFixed(0)}%`, className: 'trend-up' };
    if (last < prev) return { label: `↓ ${((prev - last) / Math.max(prev, 1) * 100).toFixed(0)}%`, className: 'trend-down' };
    return { label: '→ stable', className: '' };
}

// Heuristic remediation suggestion based on vulnerability name
function suggestRemediation(vulnName) {
    const name = (vulnName || '').toLowerCase();

    if (name.includes('ms17-010') || name.includes('eternalblue') || name.includes('smb')) {
        return "Désactiver SMBv1 sur l'hôte (registre + service LanmanServer) et appliquer les correctifs MS17-010 correspondants, puis vérifier avec Metasploit et un rescan Nessus.";
    }

    if (name.includes('ms11-030') || name.includes('2509553') || name.includes('dns resolution')) {
        return "Installer le correctif de sécurité Microsoft KB2509553 (MS11-030) sur le serveur concerné, puis vérifier via Get-HotFix et un rescan Nessus ciblé.";
    }

    if (name.includes('unsupported windows os') || name.includes('end-of-life')) {
        return "Planifier une mise à niveau de l'OS vers une version supportée. En attendant, appliquer toutes les mises à jour de sécurité disponibles et restreindre l'exposition réseau (segmentation, filtrage).";
    }

    if (name.includes('brotli')) {
        return "Mettre à jour la bibliothèque Python 'brotli' vers une version corrigée (>= 1.1.0) sur l'environnement concerné, puis redémarrer les services applicatifs qui l'utilisent.";
    }

    return "Consulter la description de la vulnérabilité dans Nessus et appliquer le correctif recommandé (patch KB, désactivation de fonctionnalité ou mise à jour logicielle), puis lancer un rescan de validation.";
}

// Quick alerts based on stats
function updateAlerts(stats) {
    const alertsEl = document.getElementById('alerts-section');
    alertsEl.innerHTML = '';

    const alerts = [];

    if (stats.critical_vulnerabilities > 0) {
        alerts.push({
            type: 'critical',
            text: `${stats.critical_vulnerabilities} vulnérabilités critiques ouvertes – à traiter en priorité`,
            action: 'showCritical'
        });
    }

    if (stats.open_vulnerabilities > 0 && stats.critical_vulnerabilities === 0) {
        alerts.push({
            type: 'warning',
            text: `${stats.open_vulnerabilities} vulnérabilités ouvertes – surveiller la tendance`
        });
    }

    if (stats.open_vulnerabilities === 0) {
        alerts.push({
            type: 'ok',
            text: 'Aucune vulnérabilité ouverte – posture propre sur la période analysée'
        });
    }

    if (stats.active_remediations > 0) {
        alerts.push({
            type: 'ok',
            text: `${stats.active_remediations} cas de remédiation en cours`
        });
    }

    alerts.forEach(alert => {
        const pill = document.createElement('div');
        pill.className = `alert-pill ${alert.type}`;
        pill.innerHTML = `
            <span class="alert-dot ${alert.type}"></span>
            <span>${alert.text}</span>
        `;

        if (alert.action === 'showCritical') {
            pill.classList.add('clickable');
            pill.addEventListener('click', () => {
                showCriticalVulnerabilities();
            });
        }

        alertsEl.appendChild(pill);
    });
}

// Trigger remediation for a specific vulnerability ID
async function remediateVulnerability(vulnId, vulnName, host) {
    if (!confirm(`Lancer la remédiation pour :\n${vulnName}\nHost: ${host || 'inconnu'} ?`)) return;

    try {
        const remResponse = await fetch(`${API_BASE}/remediate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vulnerability_id: vulnId })
        });
        const result = await remResponse.json();

        if (result.success) {
            alert(`Remediation case #${result.case_id} created!`);
            loadStats();
            loadCases();
        } else {
            const msg = result.error || result.message || 'Unknown error from remediation agent';
            alert(`Failed: ${msg}`);
        }
    } catch (error) {
        alert('Failed to trigger remediation');
    }
}

function toggleVulnDetails(id) {
    const el = document.getElementById(id);
    if (!el) return;
    const isHidden = el.style.display === 'none' || !el.style.display;
    el.style.display = isHidden ? 'table-row' : 'none';
}

// Load and display all open critical vulnerabilities in a modal
async function showCriticalVulnerabilities() {
    const modal = document.getElementById('vuln-list-modal');
    const body = document.getElementById('vuln-list-body');

    body.innerHTML = '<p style="color:#6b7280;">Chargement des vulnérabilités critiques...</p>';
    modal.classList.remove('hidden');

    try {
        const scansResp = await fetch(`${API_BASE}/scans`);
        const scans = await scansResp.json();

        const allCritical = [];

        for (const scan of scans) {
            const resp = await fetch(`${API_BASE}/scans/${scan.id}`);
            const data = await resp.json();
            const criticals = (data.vulnerabilities || []).filter(v => v.severity === 'Critical');

            criticals.forEach(v => {
                allCritical.push({
                    scanName: scan.name,
                    scanTime: scan.timestamp,
                    ...v
                });
            });
        }

        if (!allCritical.length) {
            body.innerHTML = '<p style="color:#6b7280;">Aucune vulnérabilité critique ouverte trouvée.</p>';
            return;
        }

        const list = document.createElement('div');
        allCritical.forEach(v => {
            const detailId = `vuln-details-${v.id}`;
            const safeName = (v.name || '').replace(/'/g, "\\'");
            const safeHost = (v.host || '').replace(/'/g, "\\'");
            const suggestion = suggestRemediation(v.name);

            const item = document.createElement('div');
            item.className = 'scan-item';
            item.innerHTML = `
                <div class="scan-header vuln-header-click" onclick="toggleVulnDetails('${detailId}')">
                    <div>
                        <div class="scan-name">${v.name}</div>
                        <div class="scan-meta">
                            <span>Host: ${v.host}</span>
                            ${v.port ? `<span>Port: ${v.port}</span>` : ''}
                            <span>Scan: ${v.scanName}</span>
                        </div>
                    </div>
                    <span class="scan-status status-open">CRITICAL</span>
                </div>
                <div id="${detailId}" class="vuln-details" style="display:none;">
                    <p><strong>Proposition de correction :</strong> ${suggestion}</p>
                    <div class="scan-actions" style="margin-top:8px;">
                        <button class="btn btn-secondary btn-small" onclick="event.stopPropagation(); remediateVulnerability(${v.id}, '${safeName}', '${safeHost}')">Lancer la remédiation</button>
                    </div>
                </div>
            `;
            list.appendChild(item);
        });

        body.innerHTML = '';
        body.appendChild(list);
    } catch (error) {
        console.error('Error loading critical vulnerabilities:', error);
        body.innerHTML = '<p style="color:#b91c1c;">Erreur lors du chargement des vulnérabilités critiques.</p>';
    }
}

// Load dashboard stats
async function loadStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`);
        const stats = await response.json();
        document.getElementById('total-scans').textContent = stats.total_scans;
        document.getElementById('total-vulns').textContent = stats.open_vulnerabilities;
        document.getElementById('critical-vulns').textContent = stats.critical_vulnerabilities;
        document.getElementById('active-remediations').textContent = stats.active_remediations;

        // KPI cards → VulnBot auto-question
        document.querySelector('.stat-card:nth-child(1)').onclick = () =>
            vulnbotAsk(`Il y a ${stats.total_scans} scans importés. Donne-moi un résumé de la couverture.`);
        document.querySelector('.stat-card:nth-child(2)').onclick = () =>
            vulnbotAsk(`Il y a ${stats.open_vulnerabilities} vulnérabilités ouvertes. Quelles sont les plus urgentes ?`);
        document.querySelector('.stat-card:nth-child(3)').onclick = () =>
            vulnbotAsk('Quelles sont les vulnérabilités critiques ouvertes ?');
        document.querySelector('.stat-card:nth-child(4)').onclick = () =>
            vulnbotAsk('Historique des remédiations actives et leur statut.');

        renderSeverityPie(stats);

        // Part des vulnérabilités critiques
        const criticalShare = stats.open_vulnerabilities > 0
            ? Math.round((stats.critical_vulnerabilities / stats.open_vulnerabilities) * 100)
            : 0;
        document.getElementById('critical-share').textContent = `${criticalShare}%`;

        // Placeholder simple pour le "taux de remédiation" (basé sur ratio cas actifs / vulnérabilités)
        const remediationRate = stats.open_vulnerabilities > 0
            ? Math.round((stats.active_remediations / stats.open_vulnerabilities) * 100)
            : 0;
        document.getElementById('remediation-rate').textContent = stats.open_vulnerabilities > 0
            ? `${remediationRate}% des vulnérabilités en cours de traitement`
            : 'Rien à remédier';

        updateAlerts({
            open_vulnerabilities: stats.open_vulnerabilities,
            critical_vulnerabilities: stats.critical_vulnerabilities,
            active_remediations: stats.active_remediations
        });
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Load imported scans list
async function loadScans(dateFrom = null, dateTo = null) {
    try {
        const response = await fetch(`${API_BASE}/scans`);
        let scans = await response.json();

        // Apply date filter
        if (dateFrom || dateTo) {
            const from = dateFrom ? new Date(dateFrom).getTime() : 0;
            const to   = dateTo   ? new Date(dateTo + 'T23:59:59').getTime() : Infinity;
            scans = scans.filter(s => {
                const t = new Date(s.timestamp).getTime();
                return t >= from && t <= to;
            });
        }
        const scansList = document.getElementById('scans-list');
        scansList.innerHTML = '';

        if (scans.length === 0) {
            scansList.innerHTML = '<p style="color:#666;">No scans imported yet. Use "Import from Nessus" to get started.</p>';
            return;
        }

        scans.forEach(scan => {
            const item = document.createElement('div');
            item.className = 'scan-item';

            const riskLabel = scan.risk_level || 'N/A';
            const crit = scan.critical_count ?? null;
            const high = scan.high_count ?? null;
            const medium = scan.medium_count ?? null;

            const countsText = (crit || high || medium) !== null
                ? `Critical: ${crit ?? 0} · High: ${high ?? 0} · Medium: ${medium ?? 0}`
                : '';

            item.innerHTML = `
                <div class="scan-header">
                    <div>
                        <div class="scan-name">${scan.name}</div>
                        <div class="scan-meta">
                            <span>Target: ${scan.target}</span>
                            <span>Risk: ${riskLabel}</span>
                        </div>
                    </div>
                    <span class="scan-status status-${scan.status}">${scan.status}</span>
                </div>
                <div class="scan-details">
                    <p>Time: ${new Date(scan.timestamp).toLocaleString()}</p>
                    ${countsText ? `<p>${countsText}</p>` : ''}
                </div>
                <div class="scan-actions">
                    <button class="btn btn-primary btn-small" onclick="viewScan('${scan.id}', '${scan.name.replace(/'/g, "\\'")}', '${scan.target.replace(/'/g, "\\'")}', '${scan.status}')">View Details</button>
                    <button class="btn btn-kali-remediate btn-small" onclick="kaliRemediate('${scan.target.replace(/'/g, "\\'")}', this)">Remediate (Kali)</button>
                </div>`;
            scansList.appendChild(item);
        });
    } catch (error) {
        console.error('Error loading scans:', error);
    }
}

// Load available Nessus scans
async function loadNessusScans() {
    const list = document.getElementById('nessus-scans-list');
    list.innerHTML = '<p style="color:#666;">Loading from Nessus...</p>';
    try {
        const response = await fetch(`${API_BASE}/scans/nessus`);
        const scans = await response.json();
        list.innerHTML = '';

        if (!scans.length) {
            list.innerHTML = '<p style="color:#666;">No scans found on Nessus.</p>';
            return;
        }

        scans.forEach(scan => {
            const item = document.createElement('div');
            item.className = 'scan-item';
            item.innerHTML = `
                <div class="scan-header">
                    <span class="scan-name">${scan.name}</span>
                    <span class="scan-status status-${scan.status}">${scan.status}</span>
                </div>
                <div class="scan-details">
                    <p>ID: ${scan.id} | Last modified: ${new Date(scan.last_modification_date * 1000).toLocaleString()}</p>
                </div>
                <div class="scan-actions">
                    <button class="btn btn-primary btn-small" onclick="importScan(${scan.id})">Import</button>
                </div>`;
            list.appendChild(item);
        });
    } catch (error) {
        list.innerHTML = '<p style="color:#c00;">Could not reach Nessus. Check backend connection.</p>';
    }
}

// Import a scan from Nessus
async function importScan(nessusId) {
    try {
        const response = await fetch(`${API_BASE}/scans/import/${nessusId}`, { method: 'POST' });
        const result = await response.json();
        if (result.success) {
            alert('Scan imported successfully!');
            document.getElementById('nessus-modal').classList.add('hidden');
            loadStats();
            loadScans();
            loadTrendAndStats();
        } else {
            alert(`Failed: ${result.error}`);
        }
    } catch (error) {
        alert('Failed to import scan');
    }
}

function severityClass(sev) {
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return { row: 'vuln-row-critical', badge: 'vuln-sev-critical' };
    if (s === 'high') return { row: 'vuln-row-high', badge: 'vuln-sev-high' };
    if (s === 'medium') return { row: 'vuln-row-medium', badge: 'vuln-sev-medium' };
    if (s === 'low') return { row: 'vuln-row-low', badge: 'vuln-sev-low' };
    if (s === 'info' || s === 'informational') return { row: '', badge: '' };
    return { row: '', badge: '' };
}

function isInfoOnlyVuln(v) {
    const sev = (v.severity || '').toLowerCase();
    if (sev === 'info' || sev === 'informational') return true;
    const name = (v.name || '').toLowerCase();
    return name.includes('traceroute') ||
        name.includes('nessus scan information') ||
        name.includes('ws-management server detection') ||
        name.includes('scan information');
}

function setFilterMode(mode) {
    const sevBar  = document.getElementById('filter-severity-bar');
    const hostBar = document.getElementById('filter-host-bar');
    const btnSev  = document.getElementById('mode-severity');
    const btnHost = document.getElementById('mode-host');

    if (mode === 'severity') {
        sevBar.style.display  = 'flex';
        hostBar.style.display = 'none';
        btnSev.classList.add('active-mode');
        btnHost.classList.remove('active-mode');
        renderScanDetailsTable('all');
    } else {
        sevBar.style.display  = 'none';
        hostBar.style.display = 'flex';
        btnSev.classList.remove('active-mode');
        btnHost.classList.add('active-mode');
        const host = document.getElementById('host-filter-select').value;
        renderScanDetailsTable('all', host);
    }
}

function renderScanDetailsTable(filterSeverity = 'all', filterHost = 'all') {
    const body = document.getElementById('scan-details-body');
    if (!body) return;

    if (!currentScanVulns.length) {
        body.innerHTML = '<p style="color:#6b7280;">No vulnerabilities found for this scan.</p>';
        return;
    }

    const filtered = currentScanVulns.filter(v => {
        const sevOk  = filterSeverity === 'all' || v.severity === filterSeverity;
        const hostOk = filterHost === 'all' || v.host === filterHost;
        return sevOk && hostOk;
    });

    if (!filtered.length) {
        body.innerHTML = '<p style="color:#6b7280;">No vulnerabilities match this severity filter.</p>';
        return;
    }

    const table = document.createElement('table');
    table.className = 'vuln-table';

    table.innerHTML = `
        <thead>
            <tr>
                <th>Severity</th>
                <th>Name</th>
                <th>Host</th>
                <th>Port</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            ${filtered.map(v => {
                const cls = severityClass(v.severity);
                const safeName = (v.name || '').replace(/'/g, "\\'");
                const safeHost = (v.host || '').replace(/'/g, "\\'");
                const suggestion = suggestRemediation(v.name);
                const detailRowId = `scan-vuln-detail-${v.id}`;
                const infoOnly = isInfoOnlyVuln(v);
                const remediateButton = infoOnly
                    ? `<button class="btn btn-secondary btn-small" disabled title="Non remédiable automatiquement (info only)">Remediate</button>`
                    : `<button class="btn btn-secondary btn-small" onclick="event.stopPropagation(); remediateVulnerability(${v.id}, '${safeName}', '${safeHost}')">Remediate</button>`;
                return `
                    <tr class="${cls.row}" onclick="toggleVulnDetails('${detailRowId}'); vulnbotAsk('Explique cette vulnérabilité et propose un plan de correction.', {source:'vulnerability-row', vulnerability_id:${v.id}, selected_vulnerability: ${JSON.stringify({id:v.id, name:v.name, severity:v.severity, host:v.host, port:v.port})}})">>
                        <td><span class="vuln-sev-badge ${cls.badge}">${v.severity}</span></td>
                        <td>${v.name}</td>
                        <td>${v.host || '-'}</td>
                        <td>${v.port || '-'}</td>
                        <td>
                            ${remediateButton}
                        </td>
                    </tr>
                    <tr id="${detailRowId}" class="vuln-details-row" style="display:none;">
                        <td colspan="5">
                            <div class="vuln-details">
                                <p><strong>Détail :</strong> Aucune description détaillée en base. Réfère-toi au rapport Nessus pour le texte complet.</p>
                                <p><strong>Proposition de correction :</strong> ${suggestion}</p>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('')}
        </tbody>
    `;

    body.innerHTML = '';
    body.appendChild(table);
}

// View scan details in a modal with table and filter
async function viewScan(scanId, scanName, scanTarget, scanStatus) {
    const modal = document.getElementById('scan-details-modal');
    const titleEl = document.getElementById('scan-details-title');
    const metaEl = document.getElementById('scan-details-meta');

    titleEl.textContent = scanName || `Scan ${scanId}`;
    metaEl.innerHTML = `
        <p><strong>Target:</strong> ${scanTarget}</p>
        <p><strong>Status:</strong> ${scanStatus}</p>
    `;

    modal.classList.remove('hidden');
    document.getElementById('scan-details-body').innerHTML = '<p style="color:#6b7280;">Loading vulnerabilities...</p>';

    try {
        const response = await fetch(`${API_BASE}/scans/${scanId}`);
        const data = await response.json();
        currentScanVulns = data.vulnerabilities || [];

        // Compute counts per severity for filter buttons
        const counts = { all: currentScanVulns.length, Critical: 0, High: 0, Medium: 0, Low: 0 };
        currentScanVulns.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });

        document.querySelectorAll('.btn-filter').forEach(btn => {
            const sev = btn.getAttribute('data-sev');
            const n = counts[sev] ?? 0;
            btn.textContent = sev === 'all' ? `All (${counts.all})` : `${sev} (${n})`;
        });

        // Populate host filter
        const hosts = [...new Set(currentScanVulns.map(v => v.host).filter(Boolean))].sort();
        const hostSelect = document.getElementById('host-filter-select');
        hostSelect.innerHTML = `<option value="all">Tous les hôtes (${currentScanVulns.length})</option>`;
        hosts.forEach(h => {
            const cnt = currentScanVulns.filter(v => v.host === h).length;
            const opt = document.createElement('option');
            opt.value = h;
            opt.textContent = `${h} (${cnt})`;
            hostSelect.appendChild(opt);
        });

        // Reset to severity mode
        setFilterMode('severity');
        renderScanDetailsTable('all');
    } catch (error) {
        console.error('Failed to load scan details', error);
        document.getElementById('scan-details-body').innerHTML = '<p style="color:#b91c1c;">Failed to load scan details.</p>';
    }
}

// Trigger AI remediation (top vuln of a scan)
async function triggerRemediation(scanId) {
    try {
        const response = await fetch(`${API_BASE}/scans/${scanId}/prioritize`);
        const vulns = await response.json();

        if (!vulns.length) { alert('No vulnerabilities found. Re-import the scan first.'); return; }

        const topVuln = vulns[0];
        if (!topVuln || !topVuln.id) { alert('Vulnerability data incomplete. Try re-importing the scan.'); return; }

        if (!confirm(`Remediate top vulnerability?\n[${topVuln.severity}] ${topVuln.name}\nHost: ${topVuln.host}`)) return;

        const remResponse = await fetch(`${API_BASE}/remediate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vulnerability_id: topVuln.id })
        });
        const result = await remResponse.json();

        if (result.success) {
            alert(`Remediation case #${result.case_id} created!`);
            loadStats();
            loadCases();
        } else {
            const msg = result.error || result.message || 'Unknown error from remediation agent';
            alert(`Failed: ${msg}`);
        }
    } catch (error) {
        alert('Failed to trigger remediation');
    }
}

function isMetasploitVerifiableName(name) {
    return false; // Metasploit features removed
}

// Load remediation cases
async function loadCases() {
    try {
        const response = await fetch(`${API_BASE}/cases`);
        const cases = await response.json();
        const casesList = document.getElementById('cases-list');
        casesList.innerHTML = '';

        if (!cases.length) {
            casesList.innerHTML = '<p style="color:#666;">No remediation cases yet.</p>';
            return;
        }

        cases.forEach(c => {
            const item = document.createElement('div');
            item.className = 'scan-item case-card';
            item.style.cursor = 'pointer';

            const severity = (c.severity || '').toLowerCase();
            const severityClass = severity ? `case-severity-${severity}` : '';
            const severityLabel = c.severity ? c.severity.toUpperCase() : 'N/A';
            const impact = c.affected_hosts ? `${c.affected_hosts} host(s)` : '';
            const slaText = c.sla_due ? `SLA: ${new Date(c.sla_due).toLocaleDateString()}` : '';

            const verificationBadge = c.verification_status
                ? `<span class="scan-status status-${c.verification_status === 'verified' ? 'completed' : 'running'}">${c.verification_status}</span>`
                : '';

            const badges = `
                <div class="case-badges">
                    ${severityClass ? `<span class="${severityClass}">${severityLabel}</span>` : ''}
                    ${impact ? `<span class="case-impact">Impact: ${impact}</span>` : ''}
                    ${slaText ? `<span class="case-sla">${slaText}</span>` : ''}
                </div>`;

            item.innerHTML = `
                <div class="scan-header">
                    <div>
                        <div class="scan-name">Case #${c.id}: ${c.vulnerability_name}</div>
                        ${badges}
                    </div>
                    <div style="display:flex; gap:8px; align-items:center;">
                        ${verificationBadge}
                        <span class="scan-status status-${c.status}">${c.status}</span>
                    </div>
                </div>
                <div class="scan-details">
                    <p>Started: ${new Date(c.started_at).toLocaleString()}</p>
                    ${c.completed_at ? `<p>Completed: ${new Date(c.completed_at).toLocaleString()}</p>` : ''}
                </div>
                <div class="scan-actions" style="margin-top:4px;">
                    <button class="btn btn-export-csv btn-small" onclick="event.stopPropagation(); exportCase(${c.id}, 'csv')">⬇ CSV</button>
                    <button class="btn btn-export-pdf btn-small" onclick="event.stopPropagation(); exportCase(${c.id}, 'pdf')">⬇ PDF</button>
                </div>
                <div class="case-remediations-details" id="case-remediations-${c.id}" style="display:none; margin-top:8px;"></div>
            `;

            // Entire card is clickable to toggle remediation details
            item.addEventListener('click', () => {
                toggleCaseRemediations(c.id);
            });

            casesList.appendChild(item);
        });
    } catch (error) {
        console.error('Error loading cases:', error);
    }
}

// Toggle + load remediation details for a case
async function toggleCaseRemediations(caseId) {
    const container = document.getElementById(`case-remediations-${caseId}`);
    if (!container) return;

    const isHidden = container.style.display === 'none' || !container.style.display;

    if (!isHidden) {
        // Already visible → collapse
        container.style.display = 'none';
        return;
    }

    // Show loading state while fetching
    container.style.display = 'block';
    container.innerHTML = '<p style="color:#6b7280;">Chargement des remédiations...</p>';

    try {
        const resp = await fetch(`${API_BASE}/cases/${caseId}`);
        const data = await resp.json();

        // Try a few common field names; adjust based on your backend shape
        const steps = data.remediations || data.steps || data.actions || [];

        if (!steps.length) {
            container.innerHTML = '<p style="color:#6b7280;">Aucune action de remédiation enregistrée pour ce cas.</p>';
            return;
        }

        const list = document.createElement('ul');
        list.className = 'case-remediations-list';

        steps.forEach(step => {
            const li = document.createElement('li');
            li.innerHTML = `
                <div class="case-remediation-step">
                    <div>
                        <strong>${step.action || step.name || 'Action'}</strong>
                        ${step.status ? ` – <span>${step.status}</span>` : ''}
                    </div>
                    ${step.timestamp ? `<div class="case-remediation-time">${new Date(step.timestamp).toLocaleString()}</div>` : ''}
                    ${step.details ? `<div class="case-remediation-details-text">${step.details}</div>` : ''}
                </div>
            `;
            list.appendChild(li);
        });

        container.innerHTML = '';
        container.appendChild(list);
    } catch (err) {
        console.error('Error loading case remediations:', err);
        container.innerHTML = '<p style="color:#b91c1c;">Erreur lors du chargement des remédiations.</p>';
    }
}

// Vulnerability severity pie chart
let severityPieChart = null;

function renderSeverityPie(stats) {
    const ctx = document.getElementById('severity-pie-chart');
    if (!ctx) return;

    const critical = stats.critical_vulnerabilities || 0;
    const total    = stats.open_vulnerabilities || 0;
    const high     = stats.high_vulnerabilities || 0;
    const medium   = stats.medium_vulnerabilities || 0;
    const low      = stats.low_vulnerabilities || 0;

    // Fallback: if breakdown not in stats, derive from total - critical
    const other = Math.max(0, total - critical - high - medium - low);

    const data = [critical, high, medium, low, other].filter((_, i) => {
        return [critical, high, medium, low, other][i] > 0;
    });
    const labels = ['Critical', 'High', 'Medium', 'Low', 'Other'].filter((_, i) => {
        return [critical, high, medium, low, other][i] > 0;
    });
    const colors = ['#dc2626', '#f97316', '#eab308', '#22c55e', '#94a3b8'];
    const filteredColors = colors.filter((_, i) => [critical, high, medium, low, other][i] > 0);

    if (severityPieChart) severityPieChart.destroy();

    severityPieChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels,
            datasets: [{
                data,
                backgroundColor: filteredColors,
                borderColor: '#fff',
                borderWidth: 2,
                hoverOffset: 18,
                offset: 8
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom', labels: { font: { size: 12 }, padding: 14 } },
                tooltip: {
                    callbacks: {
                        label: (ctx) => {
                            const sum = ctx.dataset.data.reduce((a, b) => a + b, 0);
                            const pct = sum > 0 ? ((ctx.parsed / sum) * 100).toFixed(1) : 0;
                            return ` ${ctx.label}: ${ctx.parsed} (${pct}%)`;
                        }
                    }
                },
                datalabels: false
            },
            animation: { animateRotate: true, duration: 600 }
        },
        plugins: [{
            id: 'pieLabels',
            afterDatasetDraw(chart) {
                const { ctx: c, data } = chart;
                const dataset = data.datasets[0];
                const meta = chart.getDatasetMeta(0);
                const total = dataset.data.reduce((a, b) => a + b, 0);
                if (!total) return;

                meta.data.forEach((arc, i) => {
                    const value = dataset.data[i];
                    const pct = ((value / total) * 100).toFixed(1);
                    const { x, y } = arc.tooltipPosition();

                    c.save();
                    c.fillStyle = '#fff';
                    c.font = 'bold 11px sans-serif';
                    c.textAlign = 'center';
                    c.textBaseline = 'middle';
                    c.fillText(`${pct}%`, x, y);
                    c.restore();
                });
            }
        }]
    });
}

// Vulnerability trend chart
let trendChart = null;

function filterTrendByRange(data, rangeValue) {
    if (rangeValue === 'all') return data;
    const days = parseInt(rangeValue, 10);
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    return data.filter(d => new Date(d.timestamp).getTime() >= cutoff);
}

async function loadTrendAndStats() {
    try {
        const response = await fetch(`${API_BASE}/stats/trend`);
        trendRawData = await response.json();
        renderTrendChart();
    } catch (error) {
        console.error('Error loading trend chart:', error);
    }
}

function renderTrendChart() {
    if (!trendRawData || !trendRawData.length) return;

    const rangeValue = document.getElementById('time-range').value;
    const data = filterTrendByRange(trendRawData, rangeValue);
    if (!data.length) return;

    const labels = data.map(d => {
        const date = new Date(d.timestamp);
        return `${d.label.substring(0, 15)} (${date.toLocaleDateString()})`;
    });

    const totals = data.map(d => d.total);
    const criticals = data.map(d => d.critical);

    const ctx = document.getElementById('trend-chart').getContext('2d');
    if (trendChart) trendChart.destroy();

    trendChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [
                {
                    label: 'Total',
                    data: totals,
                    borderColor: '#4f46e5',
                    backgroundColor: 'rgba(79,70,229,0.12)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'Critical',
                    data: criticals,
                    borderColor: '#dc2626',
                    backgroundColor: 'rgba(220,38,38,0.08)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'High',
                    data: data.map(d => d.high),
                    borderColor: '#f97316',
                    backgroundColor: 'rgba(249,115,22,0.08)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'Medium',
                    data: data.map(d => d.medium),
                    borderColor: '#eab308',
                    backgroundColor: 'rgba(234,179,8,0.08)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'Closed',
                    data: data.map(d => d.closed ?? d.remediated ?? 0),
                    borderColor: '#22c55e',
                    backgroundColor: 'rgba(34,197,94,0.06)',
                    tension: 0.3,
                    fill: false,
                    borderDash: [4, 4]
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
                tooltip: { mode: 'index', intersect: false }
            },
            scales: {
                y: { beginAtZero: true, title: { display: true, text: 'Vulnerabilities' } },
                x: { title: { display: true, text: 'Scan' } }
            }
        }
    });

    // Trend badges based on totals and criticals
    const totalTrend = computeTrend(totals);
    const critTrend = computeTrend(criticals);
    const openVulnTrendEl = document.getElementById('open-vulns-trend');
    const scansTrendEl = document.getElementById('scans-trend-indicator');

    openVulnTrendEl.textContent = totalTrend.label;
    openVulnTrendEl.className = `trend-indicator ${totalTrend.className}`;

    scansTrendEl.textContent = critTrend.label;
    scansTrendEl.className = `trend-indicator ${critTrend.className}`;
}

// Load and render assets / stations
async function loadAssets() {
    try {
        // Optionally refresh the assets table on the backend
        await fetch(`${API_BASE}/assets/refresh`, { method: 'POST' });

        const resp = await fetch(`${API_BASE}/assets`);
        const assets = await resp.json();
        const list = document.getElementById('assets-list');
        list.innerHTML = '';

        if (!assets.length) {
            list.innerHTML = '<p style="color:#6b7280;">Aucune station détectée. Importez un scan Nessus pour commencer.</p>';
            return;
        }

        assets.forEach(a => {
            const riskClass = a.critical_count > 0
                ? 'asset-risk-high'
                : (a.vulnerability_count > 0 ? 'asset-risk-medium' : 'asset-risk-low');

            const item = document.createElement('div');
            item.className = 'asset-item';
            item.innerHTML = `
                <div class="asset-header">
                    <div class="asset-hostname">${a.hostname}</div>
                    <span class="asset-risk-badge ${riskClass}">
                        ${a.critical_count > 0 ? a.critical_count + ' critical' : (a.vulnerability_count > 0 ? a.vulnerability_count + ' vulns' : 'Clean')}
                    </span>
                </div>
                <div class="asset-meta">
                    <span>${a.ip_address || 'IP inconnue'}</span>
                    <span>Dernier scan: ${a.last_scan ? new Date(a.last_scan).toLocaleString() : 'N/A'}</span>
                </div>
            `;
            item.addEventListener('click', () => {
                viewAssetDetails(a.hostname);
            });
            list.appendChild(item);
        });
    } catch (err) {
        console.error('Error loading assets:', err);
        const list = document.getElementById('assets-list');
        list.innerHTML = '<p style="color:#b91c1c;">Erreur lors du chargement des assets.</p>';
    }
}

async function viewAssetDetails(hostname) {
    try {
        const resp = await fetch(`${API_BASE}/assets/${encodeURIComponent(hostname)}`);
        const asset = await resp.json();
        currentAsset = asset;

        const modal = document.getElementById('asset-modal');
        const titleEl = document.getElementById('asset-modal-title');
        const bodyEl = document.getElementById('asset-modal-body');

        titleEl.textContent = `Station: ${asset.hostname}`;

        const vulns = asset.vulnerabilities || [];
        const cases = asset.cases || [];

        const vulnsHtml = vulns.length
            ? `<ul class="asset-vuln-list">${vulns.map(v => {
                    const safeName = (v.name || '').replace(/'/g, "\\'");
                    const infoOnly = isInfoOnlyVuln(v);
                    const remediateButton = infoOnly
                        ? `<button class="btn btn-secondary asset-vuln-remediate-btn" disabled title="Non remédiable automatiquement (info only)">Remediate</button>`
                        : `<button class="btn btn-secondary asset-vuln-remediate-btn" onclick="event.stopPropagation(); remediateVulnerability(${v.id}, '${safeName}', '${asset.hostname || ''}')">Remediate</button>`;
                    return `
                    <li class="asset-vuln-item">
                        <div class="asset-vuln-main">
                            <span class="asset-vuln-severity">[${v.severity}]</span>
                            <span>${v.name}</span>
                            <span style="margin-left:6px; color:#6b7280;">(port ${v.port || '-'})</span>
                        </div>
                        <div class="asset-vuln-actions">
                            ${remediateButton}
                        </div>
                    </li>`;
                }).join('')}</ul>`
            : '<p style="color:#6b7280;">Aucune vulnérabilité enregistrée pour cette station.</p>';

        const casesHtml = cases.length
            ? `<ul class="asset-case-list">${cases.map(c => `
                    <li class="asset-case-item">
                        <strong>Case #${c.id}</strong> – ${c.vulnerability_name}
                        <span style="margin-left:6px;">[${c.status}]</span>
                        <div style="color:#6b7280; font-size:0.78em; margin-top:2px;">
                            Début: ${c.started_at ? new Date(c.started_at).toLocaleString() : 'N/A'}
                            ${c.completed_at ? ` · Fin: ${new Date(c.completed_at).toLocaleString()}` : ''}
                        </div>
                    </li>
                `).join('')}</ul>`
            : '<p style="color:#6b7280;">Aucun case de remédiation pour cette station.</p>';

        bodyEl.innerHTML = `
            <div class="asset-modal-meta">
                <p><strong>IP:</strong> ${asset.ip_address || 'N/A'}</p>
                <p><strong>Dernier scan:</strong> ${asset.last_scan ? new Date(asset.last_scan).toLocaleString() : 'N/A'}</p>
                <p><strong>Vulnérabilités:</strong> ${asset.vulnerability_count} (dont ${asset.critical_count} critiques)</p>
            </div>
            <div>
                <div class="asset-modal-section-title">Vulnérabilités sur cette station</div>
                ${vulnsHtml}
            </div>
            <div style="margin-top:10px;">
                <div class="asset-modal-section-title">Remédiations associées</div>
                ${casesHtml}
            </div>
        `;

        modal.classList.remove('hidden');
    } catch (err) {
        console.error('Error loading asset details:', err);
        alert('Erreur lors du chargement du détail de la station');
    }
}

// ── Toast notification system ──
function showToast(type, title, message, duration = 5000) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div class="toast-body">
            <div class="toast-title">${title}</div>
            ${message ? `<div class="toast-msg">${message}</div>` : ''}
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
    `;
    container.appendChild(toast);
    if (duration > 0) setTimeout(() => toast.remove(), duration);
}

// ── Kali API calls ──
async function kaliRemediate(targetIp, btn) {
    if (!targetIp) {
        targetIp = prompt('IP cible pour la remédiation Kali :');
        if (!targetIp) return;
    }
    const original = btn ? btn.textContent : '';
    if (btn) { btn.textContent = '⏳ En cours...'; btn.disabled = true; }

    try {
        const resp = await fetch(`${API_BASE}/kali/remediate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: targetIp })
        });
        const result = await resp.json();

        if (result.success !== false && resp.ok) {
            showToast('success', '✅ Remédiation lancée',
                `Cible: ${targetIp} — ${result.message || result.status || 'Agent IA démarré'}`);
            loadStats();
            loadCases();
        } else {
            showToast('error', '❌ Remédiation échouée',
                result.error || result.message || 'Erreur inconnue');
        }
    } catch (err) {
        showToast('error', '❌ Connexion impossible', 'Impossible de joindre l\'API Kali (192.168.56.104:5000)');
    } finally {
        if (btn) { btn.textContent = original; btn.disabled = false; }
    }
}

// ── VulnBot Chat ──
let vulnbotContext = {};

function toggleVulnBot() {
    const panel = document.getElementById('vulnbot-panel');
    const icon = document.getElementById('vulnbot-toggle-icon');
    const isOpen = panel.classList.contains('vulnbot-open');
    panel.classList.toggle('vulnbot-open', !isOpen);
    panel.classList.toggle('vulnbot-closed', isOpen);
    icon.textContent = isOpen ? '▲' : '▼';
}

function vulnbotAppendMsg(role, text, loading = false) {
    const container = document.getElementById('vulnbot-messages');
    const div = document.createElement('div');
    div.className = `vulnbot-msg ${role}${loading ? ' loading' : ''}`;
    div.innerHTML = `<div class="vulnbot-bubble">${text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br>')}</div>`;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    return div;
}

async function vulnbotAsk(question, uiContext = {}) {
    // Open panel if closed
    const panel = document.getElementById('vulnbot-panel');
    if (panel.classList.contains('vulnbot-closed')) toggleVulnBot();

    vulnbotAppendMsg('user', question);
    const loadingEl = vulnbotAppendMsg('bot', '⏳ Analyse en cours...', true);

    try {
        const resp = await fetch(`${API_BASE}/chatbot/query`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question, context: uiContext })
        });
        const data = await resp.json();
        loadingEl.remove();
        vulnbotAppendMsg('bot', data.answer || 'Pas de réponse disponible.');
    } catch (err) {
        loadingEl.remove();
        vulnbotAppendMsg('bot', '❌ Impossible de joindre VulnBot. Vérifie que le backend est démarré.');
    }
}

async function vulnbotAnalyzeNessus(input) {
    const file = input.files[0];
    if (!file) return;
    input.value = '';

    const panel = document.getElementById('vulnbot-panel');
    if (panel.classList.contains('vulnbot-closed')) toggleVulnBot();

    vulnbotAppendMsg('user', `📂 Analyse du fichier : ${file.name}`);
    const loadingEl = vulnbotAppendMsg('bot', '⏳ Parsing du fichier Nessus en cours...', true);

    try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('question', 'Analyse ce fichier Nessus et donne-moi un résumé des vulnérabilités critiques avec les recommandations de remédiation.');

        const resp = await fetch(`${API_BASE}/chatbot/analyze-nessus`, {
            method: 'POST',
            body: formData
        });
        const data = await resp.json();
        loadingEl.remove();

        if (!data.success) {
            vulnbotAppendMsg('bot', `❌ Erreur: ${data.error}`);
            return;
        }

        const s = data.summary;
        const sev = s.severity_counts || {};
        const statsMsg = `📊 Fichier analysé: ${s.total_hosts} hôtes, ${s.total_findings} findings\n` +
            `🔴 Critical: ${sev.critical||0}  🟠 High: ${sev.high||0}  🟡 Medium: ${sev.medium||0}  🟢 Low: ${sev.low||0}`;
        vulnbotAppendMsg('bot', statsMsg);

        if (data.answer) vulnbotAppendMsg('bot', data.answer);

    } catch (err) {
        loadingEl.remove();
        vulnbotAppendMsg('bot', '❌ Impossible d\'analyser le fichier. Vérifie que le backend est démarré.');
    }
}

function vulnbotSend() {
    const input = document.getElementById('vulnbot-input');
    const q = input.value.trim();
    if (!q) return;
    input.value = '';
    vulnbotAsk(q, vulnbotContext);
}

// ── Export functions ──
function exportCaseCSV(c, steps) {
    const rows = [
        ['Case ID', 'Vulnerability', 'Host', 'Status', 'Started', 'Completed', 'Verification'],
        [c.id, c.vulnerability_name, c.host || '', c.status,
         c.started_at || '', c.completed_at || '', c.verification_status || ''],
        [],
        ['Step', 'Action', 'Status', 'Timestamp', 'Details']
    ];
    steps.forEach((s, i) => {
        rows.push([i + 1, s.action || '', s.status || '', s.timestamp || '', (s.details || '').replace(/\n/g, ' ')]);
    });

    const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `case_${c.id}_${(c.vulnerability_name || 'export').replace(/\s+/g, '_').substring(0, 40)}.csv`;
    a.click();
}

async function exportCasePDF(c, steps) {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ unit: 'mm', format: 'a4' });
    const margin = 15;
    let y = 20;

    const addLine = (text, size = 10, bold = false) => {
        doc.setFontSize(size);
        doc.setFont('helvetica', bold ? 'bold' : 'normal');
        const lines = doc.splitTextToSize(String(text), 180);
        lines.forEach(line => {
            if (y > 275) { doc.addPage(); y = 20; }
            doc.text(line, margin, y);
            y += size * 0.45;
        });
        y += 2;
    };

    // Header
    doc.setFillColor(99, 102, 241);
    doc.rect(0, 0, 210, 14, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('Vulnerability Management Hub — Remediation Report', margin, 10);
    doc.setTextColor(0, 0, 0);
    y = 22;

    addLine(`Case #${c.id}: ${c.vulnerability_name}`, 14, true);
    addLine(`Host: ${c.host || 'N/A'}   |   Status: ${c.status}   |   Verification: ${c.verification_status || 'N/A'}`, 10);
    addLine(`Started: ${c.started_at ? new Date(c.started_at).toLocaleString() : 'N/A'}`, 9);
    if (c.completed_at) addLine(`Completed: ${new Date(c.completed_at).toLocaleString()}`, 9);
    y += 4;

    addLine('Remediation Steps', 12, true);
    doc.setDrawColor(200, 200, 200);
    doc.line(margin, y, 195, y);
    y += 4;

    if (!steps.length) {
        addLine('No remediation steps recorded.', 10);
    } else {
        steps.forEach((s, i) => {
            addLine(`${i + 1}. ${s.action || 'Action'}  [${s.status || ''}]`, 10, true);
            if (s.timestamp) addLine(`   ${new Date(s.timestamp).toLocaleString()}`, 8);
            if (s.details)   addLine(`   ${s.details}`, 9);
            y += 2;
        });
    }

    doc.save(`case_${c.id}_${(c.vulnerability_name || 'export').replace(/\s+/g, '_').substring(0, 40)}.pdf`);
}

async function exportCase(caseId, format) {
    try {
        const resp = await fetch(`${API_BASE}/cases/${caseId}`);
        const data = await resp.json();
        const steps = data.steps || data.remediations || data.actions || [];
        if (format === 'csv') exportCaseCSV(data, steps);
        else await exportCasePDF(data, steps);
    } catch (err) {
        showToast('error', 'Export échoué', err.message);
    }
}

// Button listeners
document.getElementById('import-nessus-btn').addEventListener('click', () => {
    document.getElementById('nessus-modal').classList.remove('hidden');
    loadNessusScans();
});

document.getElementById('close-nessus-modal').addEventListener('click', () => {
    document.getElementById('nessus-modal').classList.add('hidden');
});

const vulnModalClose = document.getElementById('close-vuln-modal');
if (vulnModalClose) {
    vulnModalClose.addEventListener('click', () => {
        document.getElementById('vuln-list-modal').classList.add('hidden');
    });
}

const scanDetailsClose = document.getElementById('close-scan-details-modal');
if (scanDetailsClose) {
    scanDetailsClose.addEventListener('click', () => {
        document.getElementById('scan-details-modal').classList.add('hidden');
        currentScanVulns = [];
    });
}

// Filter buttons in scan details modal
const filterButtons = document.querySelectorAll('.btn-filter');
filterButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        const sev = btn.getAttribute('data-sev');
        renderScanDetailsTable(sev, 'all');
    });
});

// Host filter select
const hostFilterSelect = document.getElementById('host-filter-select');
if (hostFilterSelect) {
    hostFilterSelect.addEventListener('change', () => {
        renderScanDetailsTable('all', hostFilterSelect.value);
    });
}

const assetModalClose = document.getElementById('close-asset-modal');
if (assetModalClose) {
    assetModalClose.addEventListener('click', () => {
        document.getElementById('asset-modal').classList.add('hidden');
    });
}

document.getElementById('refresh-btn').addEventListener('click', () => {
    loadStats();
    loadScans();
    loadCases();
    loadTrendAndStats();
    loadAssets();
});


// Time range filter for trend chart
const timeRangeSelect = document.getElementById('time-range');
if (timeRangeSelect) {
    timeRangeSelect.addEventListener('change', () => {
        renderTrendChart();
    });
}

// Initial load
loadStats();
loadScans();
loadCases();
loadTrendAndStats();
loadAssets();
