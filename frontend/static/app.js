(function () {
  const form = document.getElementById("login-form");
  const status = document.getElementById("auth-status");
  if (!form) return;

  form.addEventListener("submit", async (evt) => {
    evt.preventDefault();
    const data = new FormData(form);
    status.textContent = "signing in...";
    try {
      const resp = await fetch("/api/v1/auth/token", {
        method: "POST",
        body: data,
      });
      if (!resp.ok) {
        status.textContent = "auth failed: " + resp.status;
        return;
      }
      const json = await resp.json();
      sessionStorage.setItem("pegase_token", json.access_token);
      status.textContent = "signed in. token stored in sessionStorage.";
    } catch (err) {
      status.textContent = "error: " + err.message;
    }
  });
})();

// --- AutoPilot live panel ---------------------------------------------
//
// A lightweight poll loop (no SPA framework, matching the rest of this
// dashboard): clicking a mission's round count polls GET
// /api/v1/missions/{id} every 3s and re-renders the round-by-round summary,
// stopping automatically once the mission is no longer "running".
(function () {
  const panel = document.getElementById("autopilot-panel");
  if (!panel) return;

  const title = document.getElementById("autopilot-panel-title");
  const statusEl = document.getElementById("autopilot-panel-status");
  const roundsEl = document.getElementById("autopilot-rounds");
  const closeBtn = document.getElementById("autopilot-panel-close");
  let pollHandle = null;

  function stopPolling() {
    if (pollHandle) {
      clearTimeout(pollHandle);
      pollHandle = null;
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function renderRounds(state) {
    const rounds = (state && state.rounds) || [];
    if (!rounds.length) {
      roundsEl.innerHTML = "<p class=\"muted\">No rounds recorded yet.</p>";
      return;
    }
    const html = rounds.map((r) => {
      const modules = r.modules_run.map((m) => {
        const reason = (r.reasons && r.reasons[m]) || "";
        return `<li><code>${escapeHtml(m)}</code> <span class="muted">${escapeHtml(reason)}</span></li>`;
      }).join("");
      const verdicts = (r.jury_verdicts || []).map((v) => {
        const mark = v.confirmed ? "✅" : "❌";
        return `<li>${mark} ${escapeHtml(v.finding)} <span class="muted">(confidence=${v.confidence})</span></li>`;
      }).join("");
      return `
        <div class="autopilot-round">
          <h3>Round ${r.index} &mdash; ${r.new_findings} finding(s)</h3>
          <ul>${modules}</ul>
          ${verdicts ? `<p class="muted">Jury:</p><ul>${verdicts}</ul>` : ""}
          ${r.errors && r.errors.length ? `<p class="badge badge-failed">${r.errors.length} error(s)</p>` : ""}
        </div>`;
    }).join("");
    roundsEl.innerHTML = html;
  }

  async function poll(missionId) {
    const token = sessionStorage.getItem("pegase_token");
    if (!token) {
      statusEl.textContent = "sign in above to watch a live run.";
      return;
    }
    try {
      const resp = await fetch(`/api/v1/missions/${missionId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!resp.ok) {
        statusEl.textContent = `could not load mission: ${resp.status}`;
        return;
      }
      const mission = await resp.json();
      statusEl.textContent = `status: ${mission.status}` +
        (mission.autopilot_state ? ` (stopped: ${mission.autopilot_state.stopped_reason || "running"})` : "");
      renderRounds(mission.autopilot_state);
      if (mission.status === "running") {
        pollHandle = setTimeout(() => poll(missionId), 3000);
      }
    } catch (err) {
      statusEl.textContent = "error: " + err.message;
    }
  }

  document.addEventListener("click", (evt) => {
    const link = evt.target.closest(".watch-autopilot");
    if (!link) return;
    evt.preventDefault();
    stopPolling();
    const missionId = link.dataset.missionId;
    title.textContent = link.dataset.missionName || missionId;
    panel.classList.remove("hidden");
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    poll(missionId);
  });

  closeBtn.addEventListener("click", () => {
    stopPolling();
    panel.classList.add("hidden");
  });
})();
