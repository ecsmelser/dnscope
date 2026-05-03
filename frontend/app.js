const API_BASE = "http://127.0.0.1:8000";

let selectedDomainId = null;
let selectedScanRunId = null;
let currentScanFindings = [];


const els = {
  totalDomains: document.querySelector("#totalDomains"),
  totalScanRuns: document.querySelector("#totalScanRuns"),
  totalFailedScans: document.querySelector("#totalFailedScans"),
  totalFindings: document.querySelector("#totalFindings"),
  domainList: document.querySelector("#domainList"),
  openAlertCount: document.querySelector("#openAlertCount"),
  openAlerts: document.querySelector("#openAlerts"),
  recentScans: document.querySelector("#recentScans"),
  severityTotals: document.querySelector("#severityTotals"),
  domainForm: document.querySelector("#domainForm"),
  domainInput: document.querySelector("#domainInput"),
  formMessage: document.querySelector("#formMessage"),
  refreshButton: document.querySelector("#refreshButton"),
  domainDetailPanel: document.querySelector("#domainDetailPanel"),
  detailTitle: document.querySelector("#detailTitle"),
  detailSubtitle: document.querySelector("#detailSubtitle"),
  latestScanDetail: document.querySelector("#latestScanDetail"),
  scanDiffDetail: document.querySelector("#scanDiffDetail"),
  dnsRecordsDetail: document.querySelector("#dnsRecordsDetail"),
  scheduleStateBadge: document.querySelector("#scheduleStateBadge"),
  scheduleEnabledCheckbox: document.querySelector("#scheduleEnabledCheckbox"),
  scheduleIntervalInput: document.querySelector("#scheduleIntervalInput"),
  saveScheduleButton: document.querySelector("#saveScheduleButton"),
  scheduleStatusDetail: document.querySelector("#scheduleStatusDetail"),
  dnsRecordCount: document.querySelector("#dnsRecordCount"),
  scanCandidateCount: document.querySelector("#scanCandidateCount"),
  scanCandidatesDetail: document.querySelector("#scanCandidatesDetail"),
  scanCandidatesButton: document.querySelector("#scanCandidatesButton"),
  scanHistoryDetail: document.querySelector("#scanHistoryDetail"),
  scanDetailPanel: document.querySelector("#scanDetailPanel"),
  scanDetailTitle: document.querySelector("#scanDetailTitle"),
  scanDetailSubtitle: document.querySelector("#scanDetailSubtitle"),
  scanFindingList: document.querySelector("#scanFindingList"),
  findingSearchInput: document.querySelector("#findingSearchInput"),
  severityFilterSelect: document.querySelector("#severityFilterSelect"),
  hideInfoCheckbox: document.querySelector("#hideInfoCheckbox"),
};

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.detail || "request failed");
  }

  return data;
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "not available";
}

function statusClass(status) {
  return status || "unknown";
}

function renderTotals(summary) {
  els.totalDomains.textContent = summary.totals?.domains ?? 0;
  els.totalScanRuns.textContent = summary.totals?.scan_runs ?? 0;
  els.totalFailedScans.textContent = summary.totals?.failed_scan_runs ?? 0;
  els.totalFindings.textContent = summary.totals?.findings ?? 0;
}

function renderSeverityTotals(summary) {
  const severities = summary.severity_totals || {};

  els.severityTotals.innerHTML = Object.entries(severities)
    .map(([name, count]) => `
      <div class="severity-item">
        <span>${name}</span>
        <strong>${count}</strong>
      </div>
    `)
    .join("");
}

function renderDomains(summary) {
  const latestScans = summary.latest_scans || [];

  if (!latestScans.length) {
    els.domainList.innerHTML = `<p class="empty">no domains are being monitored yet.</p>`;
    return;
  }

  els.domainList.innerHTML = latestScans
    .map(({ domain, latest_scan }) => {
      const status = latest_scan?.status || "not scanned";
      const findings = latest_scan?.findings_count ?? 0;
      const lastScan = latest_scan ? formatDate(latest_scan.completed_at || latest_scan.started_at) : "never";

      return `
        <article class="domain-row">
          <div>
            <div class="domain-title">${domain.domain_name}</div>
            <div class="domain-meta">last scan: ${lastScan}</div>
            <div class="badge-row">
              <span class="status ${statusClass(status)}">${status}</span>
              <span class="badge">${findings} findings</span>
            </div>
          </div>
          <div class="domain-actions">
            <button class="secondary-button" data-view-domain-id="${domain.id}">View</button>
            <button class="scan-button" data-scan-domain-id="${domain.id}">Scan now</button>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderRecentScans(summary) {
  const scans = summary.recent_scan_runs || [];

  if (!scans.length) {
    els.recentScans.innerHTML = `<p class="empty">no scans have run yet.</p>`;
    return;
  }

  els.recentScans.innerHTML = scans
    .map((scan) => renderScanRow(scan))
    .join("");
}

function renderScanRow(scan) {
  const errorHtml = scan.status === "failed" && scan.error_message
    ? `<div class="scan-error">${escapeHtml(scan.error_message)}</div>`
    : "";

  return `
    <article class="scan-row">
      <div class="scan-title">${scan.target}</div>
      <div class="scan-meta">scan #${scan.id} - ${formatDate(scan.started_at)}</div>
      <div class="badge-row">
        <span class="status ${statusClass(scan.status)}">${scan.status}</span>
        <span class="badge">${scan.findings_count} findings</span>
        <button class="secondary-button" data-view-scan-id="${scan.id}">View findings</button>
      </div>
      ${errorHtml}
    </article>
  `;
}


function renderLatestScan(data) {
  const latestScan = data.latest_scan;

  if (!latestScan) {
    els.latestScanDetail.innerHTML = `<p class="empty">this domain has not been scanned yet.</p>`;
    return;
  }

  const errorHtml = latestScan.status === "failed" && latestScan.error_message
    ? `<div class="scan-error">${escapeHtml(latestScan.error_message)}</div>`
    : "";

  els.latestScanDetail.innerHTML = `
    <div class="scan-title">${latestScan.target}</div>
    <div class="scan-meta">scan #${latestScan.id} - ${formatDate(latestScan.started_at)}</div>
    <div class="badge-row">
      <span class="status ${statusClass(latestScan.status)}">${latestScan.status}</span>
      <span class="badge">${latestScan.findings_count} findings</span>
      <button class="secondary-button" data-view-scan-id="${latestScan.id}">View findings</button>
    </div>
    ${errorHtml}
  `;
}


function renderScanDiff(diff) {
  els.scanDiffDetail.innerHTML = `
    <div class="diff-grid">
      <div class="diff-item">
        <span>new</span>
        <strong>${diff.summary?.new ?? 0}</strong>
      </div>
      <div class="diff-item">
        <span>resolved</span>
        <strong>${diff.summary?.resolved ?? 0}</strong>
      </div>
      <div class="diff-item">
        <span>persisting</span>
        <strong>${diff.summary?.persisting ?? 0}</strong>
      </div>
    </div>
  `;
}

function renderScanHistory(history) {
  const scans = history.scan_runs || [];

  if (!scans.length) {
    els.scanHistoryDetail.innerHTML = `<p class="empty">no scan history yet.</p>`;
    return;
  }

  els.scanHistoryDetail.innerHTML = scans.map((scan) => renderScanRow(scan)).join("");
}

function renderDnsRecords(data) {
  const records = data.records || [];

  els.dnsRecordCount.textContent = records.length;

  if (!records.length) {
    els.dnsRecordsDetail.innerHTML = `<p class="empty">no DNS records have been imported for this domain.</p>`;
    return;
  }

  els.dnsRecordsDetail.innerHTML = records
    .map((record) => `
      <article class="record-row">
        <div class="record-heading">
          <span class="record-type">${escapeHtml(record.record_type || "unknown")}</span>
          <strong>${escapeHtml(record.name || "unknown record")}</strong>
        </div>
        <div class="record-value">${escapeHtml(record.value || "no value")}</div>
        <div class="scan-meta">ttl: ${record.ttl ?? "not available"}</div>
      </article>
    `)
    .join("");
}


function renderScanCandidates(data) {
  const candidates = data.candidates || [];

  els.scanCandidateCount.textContent = candidates.length;
  els.scanCandidatesButton.disabled = !candidates.length;

  if (!candidates.length) {
    els.scanCandidatesDetail.innerHTML = `<p class="empty">no CNAME records are available as scan candidates.</p>`;
    return;
  }

  els.scanCandidatesDetail.innerHTML = candidates
    .map((candidate) => `
      <article class="record-row candidate-row">
        <div class="record-heading">
          <span class="record-type">${escapeHtml(candidate.record_type || "unknown")}</span>
          <strong>${escapeHtml(candidate.name || "unknown candidate")}</strong>
        </div>
        <div class="record-value">${escapeHtml(candidate.value || "no value")}</div>
        <div class="scan-meta">scan target: ${escapeHtml(candidate.scan_target || "not available")}</div>
      </article>
    `)
    .join("");
}




function renderScanDetail(scanRun) {
  selectedScanRunId = scanRun.id;

  els.scanDetailTitle.textContent = `Scan #${scanRun.id}`;
  els.scanDetailSubtitle.textContent = `${scanRun.target} - ${scanRun.status} - ${formatDate(scanRun.started_at)}`;

  currentScanFindings = scanRun.findings || [];

  renderFilteredFindings();
}

function renderFilteredFindings() {
  const searchText = els.findingSearchInput.value.trim().toLowerCase();
  const selectedSeverity = els.severityFilterSelect.value;
  const hideInfo = els.hideInfoCheckbox.checked;

  const filteredFindings = currentScanFindings.filter((finding) => {
    const severity = finding.severity || "unknown";

    if (hideInfo && severity === "info") {
      return false;
    }

    if (selectedSeverity !== "all" && severity !== selectedSeverity) {
      return false;
    }

    if (!searchText) {
      return true;
    }

    return findingMatchesSearch(finding, searchText);
  });

  if (!currentScanFindings.length) {
    els.scanFindingList.innerHTML = `<p class="empty">select a scan to review findings.</p>`;
    return;
  }

  if (!filteredFindings.length) {
    els.scanFindingList.innerHTML = `<p class="empty">no findings match the current filters.</p>`;
    return;
  }


  els.scanFindingList.innerHTML = filteredFindings
    .map((finding) => renderFindingRow(finding))
    .join("");
}

function renderOpenAlerts(summary) {
  const alerts = summary.open_alerts || [];
  const alertCount = summary.open_alert_count ?? alerts.length;

  els.openAlertCount.textContent = alertCount;

  if (!alerts.length) {
    els.openAlerts.innerHTML = `<p class="empty">no open alerts right now.</p>`;
    return;
  }

  els.openAlerts.innerHTML = alerts
    .map((alert) => `
      <article class="alert-row">
        <div>
          <div class="alert-title">${escapeHtml(alert.finding_name || "open alert")}</div>
          <div class="scan-meta">${escapeHtml(alert.severity || "unknown")} - ${escapeHtml(alert.target || "unknown target")}</div>
          <div class="alert-guidance">
            Review this DNS entry and confirm the connected service is still active, owned, and intentionally configured.
          </div>
        </div>
        <div class="domain-actions">
          <button class="secondary-button" data-view-domain-id="${alert.domain_id}">View domain</button>
          <button class="secondary-button" data-view-scan-id="${alert.scan_run_id}">View finding</button>
        </div>
      </article>
    `)
    .join("");
}

function renderSchedule(domain, schedulerStatus) {
  const domainSchedule = (schedulerStatus.domains || [])
    .find((item) => item.domain_id === domain.id);

  const enabled = Boolean(domain.scheduled_scans_enabled);
  const interval = domain.scan_interval_minutes || 60;

  els.scheduleEnabledCheckbox.checked = enabled;
  els.scheduleIntervalInput.value = interval;
  els.scheduleStateBadge.textContent = enabled ? "on" : "off";
  els.scheduleStateBadge.classList.toggle("schedule-on", enabled);

  const lastScan = domainSchedule?.last_scheduled_scan_at
    ? formatDate(domainSchedule.last_scheduled_scan_at)
    : "not run yet";

  const nextScan = domainSchedule?.next_scheduled_scan_at
    ? formatDate(domainSchedule.next_scheduled_scan_at)
    : enabled ? "due now" : "not scheduled";

  const dueText = domainSchedule?.is_due ? "due now" : "not due";

  els.scheduleStatusDetail.innerHTML = `
    <div class="schedule-status-item">
      <span>status</span>
      <strong>${enabled ? "enabled" : "disabled"}</strong>
    </div>
    <div class="schedule-status-item">
      <span>last scheduled scan</span>
      <strong>${lastScan}</strong>
    </div>
    <div class="schedule-status-item">
      <span>next scheduled scan</span>
      <strong>${nextScan}</strong>
    </div>
    <div class="schedule-status-item">
      <span>due state</span>
      <strong>${enabled ? dueText : "off"}</strong>
    </div>
  `;
}





function isTakeoverFinding(finding) {
  const takeoverText = [
    finding.finding_name,
    finding.template_id,
    finding.risk_type,
    finding.matched_at,
    finding.finding_type,
    finding.matcher_name,
    finding.evidence,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return [
    "takeover",
    "unclaimed",
    "dangling",
    "github",
    "pages",
    "cname",
    "service disconnect",
    "not found",
  ].some((keyword) => takeoverText.includes(keyword));
}


function findingMatchesSearch(finding, searchText) {
  const searchableText = [
    finding.finding_name,
    finding.template_id,
    finding.risk_type,
    finding.matched_at,
    finding.finding_type,
    finding.matcher_name,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return searchableText.includes(searchText);
}

function renderFindingRow(finding) {
  const title = finding.finding_name || finding.template_id || finding.risk_type || "unknown finding";
  const target = finding.matched_at || "unknown target";
  const takeoverFinding = isTakeoverFinding(finding);
  const reviewBadge = takeoverFinding
    ? `<span class="review-badge">review takeover risk</span>`
    : "";

  const guidanceHtml = takeoverFinding
    ? `
      <div class="finding-guidance">
        Review the related DNS record and confirm the service at this URL is still owned, active, and intentionally connected. If the service is no longer in use, remove or update the DNS record before someone else can claim the target.
      </div>
    `
    : "";


  return `
    <article class="finding-row${takeoverFinding ? " takeover-finding" : ""}">
      <div class="finding-row-title">${escapeHtml(title)}</div>
      <div class="scan-meta">${escapeHtml(finding.severity || "unknown")} - ${escapeHtml(target)}</div>
      <div class="badge-row">
        ${reviewBadge}
        <span class="badge">${escapeHtml(finding.template_id || finding.risk_type || "unknown")}</span>
        <span class="badge">${escapeHtml(finding.finding_type || "unknown type")}</span>
      </div>
      ${guidanceHtml}
      <details class="evidence">
        <summary>raw evidence</summary>
        <pre>${escapeHtml(finding.evidence || "")}</pre>
      </details>
    </article>
  `;
}


function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

async function loadDashboard() {
  els.formMessage.textContent = "loading dashboard...";

  try {
    const summary = await api("/dashboard/summary");

    renderTotals(summary);
    renderSeverityTotals(summary);
    renderOpenAlerts(summary);
    renderDomains(summary);
    renderRecentScans(summary);

    if (selectedDomainId) {
      await loadDomainDetail(selectedDomainId, false);
    }

    if (selectedScanRunId) {
      await loadScanDetail(selectedScanRunId, false);
    }

    els.formMessage.textContent = "";
  } catch (error) {
    els.formMessage.textContent = error.message;
  }
}

async function loadDomainDetail(domainId, shouldScroll = true) {
  selectedDomainId = domainId;
  els.formMessage.textContent = "loading domain detail...";

  try {
    const [
      domain,
      latestScan,
      history,
      diff,
      dnsRecords,
      scanCandidates,
      schedulerStatus,
    ] = await Promise.all([
      api(`/domains/${domainId}`),
      api(`/domains/${domainId}/latest-scan`),
      api(`/domains/${domainId}/scan-runs`),
      api(`/domains/${domainId}/scan-diff`),
      api(`/domains/${domainId}/dns-records`),
      api(`/domains/${domainId}/scan-candidates`),
      api("/scheduler/status"),
    ]);

    els.detailTitle.textContent = domain.domain_name;
    els.detailSubtitle.textContent = `domain #${domain.id} - created ${formatDate(domain.created_at)}`;

    renderLatestScan(latestScan);
    renderScanDiff(diff);
    renderSchedule(domain, schedulerStatus);
    renderDnsRecords(dnsRecords);
    renderScanCandidates(scanCandidates);
    renderScanHistory(history);

    els.formMessage.textContent = "";

    if (shouldScroll) {
      els.domainDetailPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  } catch (error) {
    els.formMessage.textContent = error.message;
  }
}


async function scanCandidatesForSelectedDomain() {
  if (!selectedDomainId) {
    els.formMessage.textContent = "select a domain first.";
    return;
  }

  els.scanCandidatesButton.disabled = true;
  els.formMessage.textContent = "running candidate scans...";

  try {
    const result = await api(`/domains/${selectedDomainId}/scan-candidates`, {
      method: "POST",
      body: JSON.stringify({}),
    });

    const createdRuns = result.scan_runs || [];
    const latestCreatedRun = createdRuns.length ? createdRuns[createdRuns.length - 1].scan_run : null;

    if (latestCreatedRun?.id) {
      selectedScanRunId = latestCreatedRun.id;
    }

    await loadDashboard();

    if (selectedScanRunId) {
      await loadScanDetail(selectedScanRunId, false);
    }

    els.formMessage.textContent = `candidate scans finished: ${result.scan_runs_created} scans, ${result.findings_saved} findings.`;
  } catch (error) {
    els.formMessage.textContent = error.message;
    els.scanCandidatesButton.disabled = false;
  }
}


async function saveScheduleForSelectedDomain() {
  if (!selectedDomainId) {
    els.formMessage.textContent = "select a domain first.";
    return;
  }

  const interval = Number(els.scheduleIntervalInput.value);

  if (!Number.isInteger(interval) || interval < 1) {
    els.formMessage.textContent = "schedule interval must be at least 1 minute.";
    return;
  }

  els.formMessage.textContent = "saving schedule...";

  try {
    await api(`/domains/${selectedDomainId}/schedule`, {
      method: "PATCH",
      body: JSON.stringify({
        scheduled_scans_enabled: els.scheduleEnabledCheckbox.checked,
        scan_interval_minutes: interval,
      }),
    });

    els.formMessage.textContent = "schedule saved.";
    await loadDashboard();
    await loadDomainDetail(selectedDomainId, false);
  } catch (error) {
    els.formMessage.textContent = error.message;
  }
}




async function loadScanDetail(scanRunId, shouldScroll = true) {
  els.formMessage.textContent = "loading scan findings...";

  try {
    const scanRun = await api(`/scan-runs/${scanRunId}`);
    renderScanDetail(scanRun);
    els.formMessage.textContent = "";

    if (shouldScroll) {
      els.scanDetailPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  } catch (error) {
    els.formMessage.textContent = error.message;
  }
}

async function createDomain(event) {
  event.preventDefault();

  const domainName = els.domainInput.value.trim();

  if (!domainName) {
    els.formMessage.textContent = "enter a domain first.";
    return;
  }

  els.formMessage.textContent = "adding domain...";

  try {
    const domain = await api("/domains", {
      method: "POST",
      body: JSON.stringify({ domain_name: domainName }),
    });

    els.domainInput.value = "";
    selectedDomainId = domain.id;
    els.formMessage.textContent = "domain added.";
    await loadDashboard();
    await loadDomainDetail(domain.id);
  } catch (error) {
    els.formMessage.textContent = error.message;
  }
}

async function scanDomain(domainId) {
  els.formMessage.textContent = `running scan for domain ${domainId}...`;

  try {
    const scanResult = await api(`/scan/domain/${domainId}`, {
      method: "POST",
      body: JSON.stringify({}),
    });

    selectedDomainId = domainId;
    selectedScanRunId = scanResult.scan_run_id;
    els.formMessage.textContent = "scan finished.";
    await loadDashboard();
    await loadDomainDetail(domainId, false);
    await loadScanDetail(scanResult.scan_run_id);
  } catch (error) {
    els.formMessage.textContent = error.message;
  }
}

els.domainForm.addEventListener("submit", createDomain);
els.refreshButton.addEventListener("click", loadDashboard);
els.findingSearchInput.addEventListener("input", renderFilteredFindings);
els.severityFilterSelect.addEventListener("change", renderFilteredFindings);
els.hideInfoCheckbox.addEventListener("change", renderFilteredFindings);
els.scanCandidatesButton.addEventListener("click", scanCandidatesForSelectedDomain);
els.saveScheduleButton.addEventListener("click", saveScheduleForSelectedDomain);




document.addEventListener("click", (event) => {
  const scanButton = event.target.closest("[data-scan-domain-id]");
  const viewDomainButton = event.target.closest("[data-view-domain-id]");
  const viewScanButton = event.target.closest("[data-view-scan-id]");

  if (scanButton) {
    scanDomain(scanButton.dataset.scanDomainId);
    return;
  }

  if (viewDomainButton) {
    loadDomainDetail(viewDomainButton.dataset.viewDomainId);
    return;
  }

  if (viewScanButton) {
    loadScanDetail(viewScanButton.dataset.viewScanId);
  }
});

loadDashboard();
