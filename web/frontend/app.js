"use strict";

const SEV_COLORS = {
  critical: "var(--crit)", high: "var(--high)", medium: "var(--med)",
  low: "var(--low)", info: "var(--info)",
};

const $ = (sel) => document.querySelector(sel);

async function loadHistory() {
  const res = await fetch("/api/scans");
  const scans = await res.json();
  const tbody = $("#history tbody");
  tbody.innerHTML = "";
  scans.forEach((s) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td><a href="#" data-id="${s.id}">${s.id}</a></td>
      <td>${s.target}</td><td>${s.modules.join(", ")}</td>
      <td class="st-${s.status}">${s.status}</td>`;
    tr.querySelector("a").addEventListener("click", (e) => {
      e.preventDefault();
      pollReport(s.id);
    });
    tbody.appendChild(tr);
  });
}

function addProgress(evt) {
  const ul = $("#progress");
  const li = document.createElement("li");
  li.className = "st-" + (evt.status || "");
  const detail = evt.detail ? " — " + evt.detail : "";
  li.textContent = `[${evt.status}] ${evt.module}${detail}`;
  ul.appendChild(li);
  ul.scrollTop = ul.scrollHeight;
}

function streamEvents(jobId) {
  $("#progress").innerHTML = "";
  const es = new EventSource(`/api/scans/${jobId}/events`);
  es.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.status === "complete") {
      es.close();
      pollReport(jobId);
      loadHistory();
      return;
    }
    addProgress(data);
  };
  es.onerror = () => es.close();
}

async function pollReport(jobId) {
  const res = await fetch(`/api/scans/${jobId}`);
  const job = await res.json();
  renderReport(job);
}

function renderReport(job) {
  const report = job.report;
  const summaryEl = $("#summary");
  const reportEl = $("#report");
  const dlEl = $("#downloads");
  summaryEl.innerHTML = "";
  reportEl.innerHTML = "";
  dlEl.innerHTML = "";

  if (!report) {
    reportEl.innerHTML = `<p class="st-${job.status}">Status: ${job.status}${job.error ? " — " + job.error : ""}</p>`;
    return;
  }

  const counts = {critical: 0, high: 0, medium: 0, low: 0, info: 0};
  const findings = [];
  (report.modules || []).forEach((m) => (m.findings || []).forEach((f) => {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    findings.push(f);
  }));
  const rank = {critical: 5, high: 4, medium: 3, low: 2, info: 1};
  findings.sort((a, b) => rank[b.severity] - rank[a.severity]);

  Object.keys(counts).forEach((sev) => {
    const pill = document.createElement("span");
    pill.className = "pill";
    pill.style.background = SEV_COLORS[sev];
    pill.textContent = `${sev} ${counts[sev]}`;
    summaryEl.appendChild(pill);
  });

  let html = `<p><strong>Target:</strong> ${report.target.input} &nbsp;
    <strong>IPs:</strong> ${(report.target.resolved_ips || []).join(", ") || "n/a"} &nbsp;
    <strong>Authorized:</strong> ${report.scope_authorized}</p>`;
  html += `<h3>Findings</h3><table><thead><tr><th>Severity</th><th>Module</th><th>Finding</th></tr></thead><tbody>`;
  if (findings.length === 0) html += `<tr><td colspan="3">No findings.</td></tr>`;
  findings.forEach((f) => {
    html += `<tr><td><span class="sev" style="background:${SEV_COLORS[f.severity]}">${f.severity.toUpperCase()}</span></td>
      <td>${f.module}</td>
      <td><strong>${f.title}</strong><br><small>${f.description || ""}</small>
      ${f.evidence ? `<br><code>${escapeHtml(f.evidence)}</code>` : ""}</td></tr>`;
  });
  html += `</tbody></table>`;

  if (report.remediation) {
    html += `<h3>Remediation <small>(${report.remediation.generated_by})</small></h3>`;
    html += `<p>${report.remediation.summary || ""}</p><ol>`;
    (report.remediation.prioritized_steps || []).forEach((s) => {
      html += `<li><span class="sev" style="background:${SEV_COLORS[s.severity]}">${s.severity.toUpperCase()}</span>
        <strong>${s.title}</strong> — ${s.action}</li>`;
    });
    html += `</ol>`;
  }
  reportEl.innerHTML = html;

  if (job.exports) {
    const links = Object.entries(job.exports)
      .filter(([, p]) => p)
      .map(([kind, p]) => {
        const name = p.split("/").pop();
        return `<a href="/api/reports/${name}" target="_blank">${kind}</a>`;
      });
    dlEl.className = "dl";
    dlEl.innerHTML = links.length ? "Download: " + links.join("") : "";
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

$("#scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const modules = [...form.querySelectorAll("input[name=modules]:checked")].map((x) => x.value);
  const body = {
    target: form.target.value.trim(),
    modules,
    authorized: form.authorized.checked,
    profile: form.profile.value.trim() || null,
    pcap: form.pcap.value.trim() || null,
    url: form.url.value.trim() || null,
    params: form.params.value.trim() || null,
  };
  const res = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const job = await res.json();
  streamEvents(job.id);
  loadHistory();
});

loadHistory();
