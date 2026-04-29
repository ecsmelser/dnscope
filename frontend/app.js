const API_BASE = "http://127.0.0.1:8000";

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
  if (!value) {
    return "not available";
  }

  return new Date(value).toLocaleString();
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
    .map(([name, count]) => {
      return `
        <div class="severity-item">
          <span>${name}</span>
          <strong>${count}</strong>
        </div>
      `;
    })
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
          <button class="scan-button" data-domain-id="${domain.id}">Scan now</button>
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
    .map((scan) => {
      return `
        <article class="scan-row">
          <div class="scan-title">${scan.target}</div>
          <div class="scan-meta">scan #${scan.id} · ${formatDate(scan.started_at)}</div>
          <div class="badge-row">
            <span class="status ${statusClass(scan.status)}">${scan.status}</span>
            <span class="badge">${scan.findings_count} findings</span>
          </div>
        </article>
      `;
    })
    .join("");
}

async function loadDashboard() {
  els.formMessage.textContent = "loading dashboard...";

  try {
    const summary = await api("/dashboard/summary");

    renderTotals(summary);
    renderSeverityTotals(summary);
    renderDomains(summary);
    renderRecentScans(summary);

    els.formMessage.textContent = "";
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
    await api("/domains", {
      method: "POST",
      body: JSON.stringify({ domain_name: domainName }),
    });

    els.domainInput.value = "";
    els.formMessage.textContent = "domain added.";
    await loadDashboard();
  } catch (error) {
    els.formMessage.textContent = error.message;
  }
}

async function scanDomain(domainId) {
  els.formMessage.textContent = `running scan for domain ${domainId}...`;

  try {
    await api(`/scan/domain/${domainId}`, {
      method: "POST",
      body: JSON.stringify({}),
    });

    els.formMessage.textContent = "scan finished.";
    await loadDashboard();
  } catch (error) {
    els.formMessage.textContent = error.message;
  }
}

els.domainForm.addEventListener("submit", createDomain);
els.refreshButton.addEventListener("click", loadDashboard);

els.domainList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-domain-id]");

  if (!button) {
    return;
  }

  scanDomain(button.dataset.domainId);
});

loadDashboard();
