// static/dashboard.js
document.addEventListener("DOMContentLoaded", () => {
  const tokenEl = document.getElementById("userToken");
  const resourceEl = document.getElementById("resource");
  const btnGetRisk = document.getElementById("btnGetRisk");
  const btnClear = document.getElementById("btnClear");

  const resultHeader = document.getElementById("resultHeader");
  const resultMain = document.getElementById("resultMain");
  const resultDetails = document.getElementById("resultDetails");
  const resultRaw = document.getElementById("resultRaw");

  function pretty(obj) {
    try { return JSON.stringify(obj, null, 2); } catch(e) { return String(obj); }
  }

  function handle401(json) {
    const msg = (json && (json.error || json.message)) ? (json.error || json.message) : "Unauthorized";
    resultHeader.textContent = "Unauthorized - session issue";
    resultMain.textContent = msg;
    try { localStorage.removeItem('access_token'); } catch(e){}
    setTimeout(()=> { window.location.href = "/login_page"; }, 1000);
  }

  function renderOutcome(status, json) {
    resultRaw.textContent = pretty(json || {});
    const res = json || {};

    if (status === 401) {
      handle401(res);
      return;
    }

    const mode = res.mode || (res.result && res.result.mode) || (res.decision && res.decision.mode) || null;
    const reason = res.reason || (res.result && res.result.reason) || "";
    const resource = res.resource || resourceEl.value;
    const risk_level = res.risk_level || (res.details && res.details.risk_level) || "";
    const risk_score = (res.risk_score !== undefined) ? res.risk_score : (res.risk_pct !== undefined) ? res.risk_pct : "";

    resultHeader.innerHTML = `<strong>mode:</strong> ${mode || "(n/a)"} &nbsp; <strong>reason:</strong> ${reason} &nbsp; <strong>resource:</strong> ${resource} &nbsp; <strong>risk_score:</strong> ${risk_score}`;

    if (status === 200) {
      if (mode === "full") resultMain.textContent = `FULL access granted to resource ${resource}.`;
      else if (mode === "read-only") resultMain.textContent = `READ-ONLY access to resource ${resource} (limited view).`;
      else resultMain.textContent = `Request succeeded (mode: ${mode}).`;
    } else if (status === 403) {
      resultMain.textContent = `Access denied (403). Reason: ${reason || "deny"}.`;
    } else {
      resultMain.textContent = `HTTP ${status}. See raw response below.`;
    }

    resultDetails.textContent = res.details ? (typeof res.details === "string" ? res.details : pretty(res.details)) : "(no details)";
  }

  async function callResource() {
    resultHeader.textContent = "Sending request...";
    resultMain.textContent = "";
    resultDetails.textContent = "";
    resultRaw.textContent = "";

    // find token (textarea or localStorage)
    let tokenValue = tokenEl.value.trim();
    if (!tokenValue) {
      try {
        const saved = localStorage.getItem('access_token');
        if (saved) tokenValue = saved;
      } catch(e){}
    }
    if (!tokenValue) {
      resultHeader.textContent = "No token present. Please login first.";
      setTimeout(()=> window.location.href="/login_page", 800);
      return;
    }
    if (tokenValue.toLowerCase().startsWith("bearer ")) {
      tokenValue = tokenValue.split(/\s+/, 2)[1] || "";
    }

    const resource = resourceEl.value.trim() || "test-resource";
    const url = `/resource/${encodeURIComponent(resource)}`;
    const headers = {};
    if (tokenValue) headers["Authorization"] = "Bearer " + tokenValue;

    try {
      const resp = await fetch(url, { method: "POST", headers });
      const text = await resp.text();
      let json = {};
      try { json = text ? JSON.parse(text) : {}; } catch(e) { json = { raw: text }; }
      renderOutcome(resp.status, json);
    } catch (err) {
      resultHeader.textContent = "Network error: " + err.message;
    }
  }

  btnGetRisk.addEventListener("click", callResource);
  btnClear.addEventListener("click", () => {
    resultHeader.textContent = "No request made yet.";
    resultMain.textContent = "";
    resultDetails.textContent = "(no details)";
    resultRaw.textContent = "(no response)";
  });
});
