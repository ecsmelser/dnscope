const API_BASE = "http://127.0.0.1:8000";

let selectedDomainId = null;
let selectedScanRunId = null;

const els = {
  totalDomains: document.querySelector("#totalDomains"),
  totalScanRuns: document.querySelector("#totalScanRuns"),
  totalFindings: document.querySelector("#totalFindings"),
  domainList: document.querySelector("#domainList"),
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
  scanHistoryDetail: document.querySelector("#scanHistoryDetail"),
  scanDetailPanel: document.querySelector("#scanDetailPanel"),
  scanDetailTitle: document.querySelector("#scanDetailTitle"),
  scanDetailSubtitle: document.querySelector("#scanDetailSubtitle"),
  scanFindingList: document.querySelector("#scanFindingList"),
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
  return `
    <article class="scan-row">
      <div class="scan-title">${scan.target}</div>
      <div class="scan-meta">scan #${scan.id} - ${formatDate(scan.started_at)}</div>
      <div class="badge-row">
        <span class="status ${statusClass(scan.status)}">${scan.status}</span>
        <span class="badge">${scan.findings_count} findings</span>
        <button class="secondary-button" data-view-scan-id="${scan.id}">View findings</button>
      </div>
    </article>
  `;
}

function renderLatestScan(data) {
  const latestScan = data.latest_scan;

  if (!latestScan) {
    els.latestScanDetail.innerHTML = `<p class="empty">this domain has not been scanned yet.</p>`;
    return;
  }

  els.latestScanDetail.innerHTML = `
    <div class="scan-title">${latestScan.target}</div>
    <div class="scan-meta">scan #${latestScan.id} - ${formatDate(latestScan.started_at)}</div>
    <div class="badge-row">
      <span class="status ${statusClass(latestScan.status)}">${latestScan.status}</span>
      <span class="badge">${latestScan.findings_count} findings</span>
      <button class="secondary-button" data-view-scan-id="${latestScan.id}">View findings</button>
    </div>
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

function renderScanDetail(scanRun) {
  selectedScanRunId = scanRun.id;

  els.scanDetailTitle.textContent = `Scan #${scanRun.id}`;
  els.scanDetailSubtitle.textContent = `${scanRun.target} - ${scanRun.status} - ${formatDate(scanRun.started_at)}`;

  const findings = scanRun.findings || [];

  if (!findings.length) {
    els.scanFindingList.innerHTML = `<p class="empty">this scan did not save any findings.</p>`;
    return;
  }

  els.scanFindingList.innerHTML = findings
    .map((finding) => {
      const title = finding.finding_name || finding.template_id || finding.risk_type || "unknown finding";
      const target = finding.matched_at || "unknown target";

      return `
        <article class="finding-row">
          <div class="finding-row-title">${title}</div>
          <div class="scan-meta">${finding.severity} - ${target}</div>
          <div class="badge-row">
            <span class="badge">${finding.template_id || finding.risk_type || "unknown"}</span>
            <span class="badge">${finding.finding_type || "unknown type"}</span>
          </div>
          <details class="evidence">
            <summary>raw evidence</summary>
            <pre>${escapeHtml(finding.evidence || "")}</pre>
          </details>
        </article>
      `;
    })
    .join("");
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
    const [domain, latestScan, history, diff] = await Promise.all([
      api(`/domains/${domainId}`),
      api(`/domains/${domainId}/latest-scan`),
      api(`/domains/${domainId}/scan-runs`),
      api(`/domains/${domainId}/scan-diff`),
    ]);

    els.detailTitle.textContent = domain.domain_name;
    els.detailSubtitle.textContent = `domain #${domain.id} - created ${formatDate(domain.created_at)}`;

    renderLatestScan(latestScan);
    renderScanDiff(diff);
    renderScanHistory(history);

    els.formMessage.textContent = "";

    if (shouldScroll) {
      els.domainDetailPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    }
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
