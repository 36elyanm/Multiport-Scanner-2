(() => {
  "use strict";

  /* ---------- OS detection → font ---------- */

  function detectOS() {
    const ua = navigator.userAgent || "";
    if (/Android/i.test(ua)) return "android";
    if (/Windows/i.test(ua)) return "windows";
    return "apple";
  }
  document.documentElement.classList.add("os-" + detectOS());

  /* ---------- Tabs ---------- */

  const segments = document.querySelectorAll(".segment");
  const panels = document.querySelectorAll(".tab-panel");
  let activeTab = "url";

  segments.forEach((btn) => {
    btn.addEventListener("click", () => {
      segments.forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      activeTab = btn.dataset.tab;
      panels.forEach((p) => p.classList.toggle("active", p.dataset.panel === activeTab));
    });
  });

  /* ---------- File dropzone ---------- */

  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");
  const dropzoneLabel = document.getElementById("dropzone-label");
  let selectedFile = null;

  fileInput.addEventListener("change", () => {
    selectedFile = fileInput.files[0] || null;
    dropzoneLabel.textContent = selectedFile ? selectedFile.name : "Drop a file here, or click to choose one";
  });

  ["dragover", "dragenter"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    })
  );
  ["dragleave", "dragend"].forEach((evt) =>
    dropzone.addEventListener(evt, () => dropzone.classList.remove("dragover"))
  );
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    if (file) {
      selectedFile = file;
      fileInput.files = e.dataTransfer.files;
      dropzoneLabel.textContent = file.name;
    }
  });

  /* ---------- More apps toggle ---------- */

  const moreToggle = document.getElementById("more-apps-toggle");
  const morePanel = document.getElementById("more-apps-panel");
  moreToggle.addEventListener("click", () => {
    const open = moreToggle.getAttribute("aria-expanded") === "true";
    moreToggle.setAttribute("aria-expanded", String(!open));
    morePanel.hidden = open;
  });

  /* ---------- Heuristic engines ---------- */

  const SUSPICIOUS_TLDS = ["zip", "review", "country", "kim", "cricket", "science", "work", "party", "gq", "tk", "ml", "ga", "cf", "top", "xyz", "click", "link"];
  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy"];
  const BRANDS = ["paypal", "apple", "microsoft", "amazon", "google", "netflix", "bankofamerica", "wellsfargo", "chase", "facebook", "instagram", "irs", "usps", "fedex", "dhl"];
  const SUSPICIOUS_PATH_WORDS = ["login", "verify", "secure", "account", "update", "confirm", "signin", "billing", "reset", "unlock"];

  function safeParseURL(raw) {
    let candidate = raw.trim();
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) {
      candidate = "http://" + candidate;
    }
    try {
      return new URL(candidate);
    } catch {
      return null;
    }
  }

  function analyzeUrl(raw) {
    const checks = [];
    const url = safeParseURL(raw);

    if (!url) {
      checks.push({ name: "URL Structure", status: "flagged", detail: "This doesn't parse as a valid URL." });
      return checks;
    }

    const host = url.hostname.toLowerCase();
    const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":");

    checks.push(
      isIP
        ? { name: "Hostname Type", status: "flagged", detail: `Links directly to a raw IP address (${host}) instead of a domain name.` }
        : { name: "Hostname Type", status: "clean", detail: "Uses a normal domain name, not a raw IP." }
    );

    checks.push(
      url.protocol === "https:"
        ? { name: "Transport Security", status: "clean", detail: "Connects over HTTPS." }
        : { name: "Transport Security", status: "flagged", detail: "Does not use HTTPS — traffic could be intercepted." }
    );

    const isPunycode = host.includes("xn--");
    checks.push(
      isPunycode
        ? { name: "Homograph / Punycode", status: "flagged", detail: "Domain uses Punycode encoding, often used to mimic a trusted brand with lookalike characters." }
        : { name: "Homograph / Punycode", status: "clean", detail: "No Punycode / lookalike-character encoding detected." }
    );

    const subdomainCount = Math.max(0, host.split(".").length - 2);
    checks.push(
      subdomainCount >= 3
        ? { name: "Subdomain Depth", status: "flagged", detail: `${subdomainCount} subdomains deep — often used to bury the real domain.` }
        : { name: "Subdomain Depth", status: "clean", detail: "Normal subdomain depth." }
    );

    const tld = host.split(".").pop();
    checks.push(
      SUSPICIOUS_TLDS.includes(tld)
        ? { name: "Domain Extension", status: "info", detail: `".${tld}" is a low-cost TLD that's disproportionately used for abuse. Not proof of anything by itself.` }
        : { name: "Domain Extension", status: "clean", detail: `".${tld}" isn't on our watch list of frequently-abused TLDs.` }
    );

    const isShortener = SHORTENERS.some((s) => host === s || host.endsWith("." + s));
    checks.push(
      isShortener
        ? { name: "URL Shortener", status: "info", detail: "This is a shortened link — the real destination is hidden until you visit it." }
        : { name: "URL Shortener", status: "clean", detail: "Not a known link-shortening service." }
    );

    const hasAt = raw.includes("@") && raw.indexOf("@") < raw.indexOf(host);
    checks.push(
      hasAt
        ? { name: "Embedded Credentials Marker", status: "flagged", detail: "Contains an '@' before the host — everything before it is decorative and can hide the real destination." }
        : { name: "Embedded Credentials Marker", status: "clean", detail: "No '@' obfuscation trick detected." }
    );

    const hyphenCount = (host.match(/-/g) || []).length;
    checks.push(
      hyphenCount >= 3
        ? { name: "Domain Formatting", status: "flagged", detail: `Domain contains ${hyphenCount} hyphens — a common pattern in disposable phishing domains.` }
        : { name: "Domain Formatting", status: "clean", detail: "Domain formatting looks normal." }
    );

    const registrableParts = host.split(".").slice(-2, -1)[0] || "";
    const impersonated = BRANDS.find((b) => host.includes(b) && registrableParts !== b);
    checks.push(
      impersonated
        ? { name: "Brand Impersonation", status: "flagged", detail: `Mentions "${impersonated}" but that isn't the actual domain — a common phishing tactic.` }
        : { name: "Brand Impersonation", status: "clean", detail: "No known brand name found outside its real domain." }
    );

    const path = (url.pathname + url.search).toLowerCase();
    const pathHit = SUSPICIOUS_PATH_WORDS.find((w) => path.includes(w));
    checks.push(
      pathHit
        ? { name: "Path Keywords", status: "info", detail: `Path contains "${pathHit}" — common in credential-harvesting pages, though also used legitimately.` }
        : { name: "Path Keywords", status: "clean", detail: "No high-pressure account/login keywords in the path." }
    );

    checks.push(
      raw.length > 90
        ? { name: "Link Length", status: "info", detail: "Unusually long link — can be used to bury a suspicious domain deep in the string." }
        : { name: "Link Length", status: "clean", detail: "Link length is unremarkable." }
    );

    return checks;
  }

  const SCAM_KEYWORDS = [
    "wire transfer", "gift card", "gift cards", "act now", "urgent action", "verify your account",
    "account suspended", "account has been locked", "claim your prize", "you have won", "lottery",
    "inheritance", "bitcoin", "crypto wallet", "seed phrase", "social security number", "one-time code",
    "one time passcode", "otp code", "bank details", "routing number", "limited time", "click here immediately",
    "confirm your identity", "unusual activity", "irs", "tax refund", "processing fee", "reactivate your account"
  ];

  function extractUrls(text) {
    const matches = text.match(/\b((https?:\/\/|www\.)[^\s<>"')]+|[a-z0-9-]+\.(com|net|org|xyz|top|zip|info|biz|ru|tk|ml|ga|cf)(\/[^\s<>"')]*)?)\b/gi) || [];
    return [...new Set(matches)].slice(0, 5);
  }

  function analyzeText(text) {
    const checks = [];
    const lower = text.toLowerCase();

    const foundKeywords = SCAM_KEYWORDS.filter((k) => lower.includes(k));
    checks.push(
      foundKeywords.length
        ? { name: "Scam Language", status: "flagged", detail: `Contains common scam phrasing: ${foundKeywords.slice(0, 5).join(", ")}.` }
        : { name: "Scam Language", status: "clean", detail: "No common scam phrases detected." }
    );

    const ssnLike = /\b\d{3}-\d{2}-\d{4}\b/.test(text);
    const cardLike = /\b(?:\d[ -]*?){13,16}\b/.test(text);
    checks.push(
      ssnLike || cardLike
        ? { name: "Sensitive Data Request", status: "flagged", detail: "Message contains what looks like an SSN or card number pattern — never send these over chat or email." }
        : { name: "Sensitive Data Request", status: "clean", detail: "No SSN- or card-number-shaped patterns found." }
    );

    const letters = text.replace(/[^a-zA-Z]/g, "");
    const upper = text.replace(/[^A-Z]/g, "");
    const capsRatio = letters.length > 20 ? upper.length / letters.length : 0;
    checks.push(
      capsRatio > 0.4
        ? { name: "Urgency Tone", status: "info", detail: "Unusually high use of ALL CAPS — a common pressure tactic." }
        : { name: "Urgency Tone", status: "clean", detail: "Tone doesn't show excessive urgency markers." }
    );

    const exclCount = (text.match(/!/g) || []).length;
    checks.push(
      exclCount >= 3
        ? { name: "Punctuation Pressure", status: "info", detail: `${exclCount} exclamation marks — often paired with urgency-based scams.` }
        : { name: "Punctuation Pressure", status: "clean", detail: "Punctuation looks normal." }
    );

    const urls = extractUrls(text);
    if (urls.length === 0) {
      checks.push({ name: "Embedded Links", status: "clean", detail: "No links found in the text." });
    } else {
      urls.forEach((u) => {
        const urlChecks = analyzeUrl(u);
        const flaggedCount = urlChecks.filter((c) => c.status === "flagged").length;
        checks.push({
          name: `Embedded Link: ${u.slice(0, 40)}${u.length > 40 ? "…" : ""}`,
          status: flaggedCount > 0 ? "flagged" : "info",
          detail: flaggedCount > 0 ? `${flaggedCount} of ${urlChecks.length} link checks flagged this URL.` : "Link found — ran through the same checks as the Link tab.",
        });
      });
    }

    return checks;
  }

  const RISKY_EXTENSIONS = ["exe", "scr", "bat", "cmd", "com", "vbs", "js", "jar", "msi", "ps1", "apk", "wsf", "hta", "reg", "lnk"];

  async function sha256(file) {
    const buf = await file.arrayBuffer();
    const hashBuf = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function analyzeFile(file) {
    const checks = [];
    const nameParts = file.name.split(".");
    const ext = nameParts.length > 1 ? nameParts.pop().toLowerCase() : "";

    checks.push(
      RISKY_EXTENSIONS.includes(ext)
        ? { name: "File Type", status: "flagged", detail: `".${ext}" is an executable/script type capable of running code on your machine.` }
        : { name: "File Type", status: "clean", detail: ext ? `".${ext}" isn't in our list of high-risk executable types.` : "No file extension found." }
    );

    const doubleExt = nameParts.length > 1 && RISKY_EXTENSIONS.includes(ext);
    checks.push(
      doubleExt && nameParts.length > 1
        ? { name: "Double Extension", status: "info", detail: `Filename has multiple extensions ("${file.name}") — a classic trick to disguise an executable as a document.` }
        : { name: "Double Extension", status: "clean", detail: "No double-extension pattern detected." }
    );

    checks.push(
      file.size === 0
        ? { name: "File Size", status: "info", detail: "File is empty (0 bytes)." }
        : { name: "File Size", status: "clean", detail: `${(file.size / 1024).toFixed(1)} KB — nothing unusual.` }
    );

    let hash = null;
    try {
      hash = await sha256(file);
      checks.push({ name: "SHA-256 Hash", status: "clean", detail: hash, hash: true });
    } catch {
      checks.push({ name: "SHA-256 Hash", status: "info", detail: "Couldn't compute a hash for this file in-browser." });
    }

    return { checks, hash };
  }

  /* ---------- VirusTotal (via our own /api/* server functions) ---------- */

  async function callApi(path, options) {
    let res;
    try {
      res = await fetch(path, options);
    } catch {
      throw new Error("Couldn't reach the scan server.");
    }
    let json;
    try {
      json = await res.json();
    } catch {
      throw new Error("Scan server returned an unexpected response.");
    }
    if (!res.ok) throw new Error(json.error || "VirusTotal lookup failed.");
    return json;
  }

  function vtUrlReport(url) {
    return callApi("/api/url-report", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url }),
    });
  }

  function vtFileReport(hash) {
    return callApi("/api/file-report", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hash }),
    });
  }

  function vtFileUpload(file) {
    const fd = new FormData();
    fd.append("file", file);
    return callApi("/api/file-upload", { method: "POST", body: fd });
  }

  async function pollAnalysis(id, { attempts = 12, delayMs = 4000 } = {}) {
    for (let i = 0; i < attempts; i++) {
      const json = await callApi(`/api/analysis?id=${encodeURIComponent(id)}`);
      if (json.status === "completed") return json;
      await new Promise((r) => setTimeout(r, delayMs));
    }
    throw new Error("VirusTotal is still scanning this — check back in a moment.");
  }

  /* ---------- Rendering ---------- */

  const resultsSection = document.getElementById("results");
  const ring = document.getElementById("ring");
  const ringValue = document.getElementById("ring-value");
  const verdictEl = document.getElementById("verdict");
  const verdictTarget = document.getElementById("verdict-target");
  const engineGrid = document.getElementById("engine-grid");
  const verifyRow = document.getElementById("verify-row");
  const scanButton = document.getElementById("scan-button");
  const vtSection = document.getElementById("vt-section");
  const vtBadge = document.getElementById("vt-badge");
  const vtNote = document.getElementById("vt-note");
  const vtGrid = document.getElementById("vt-grid");
  const vtUploadBtn = document.getElementById("vt-upload-btn");

  const ICONS = {
    clean: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    flagged: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="3" stroke-linecap="round"/></svg>',
    info: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2.4"/><path d="M12 8v5m0 3h.01" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>',
  };

  // Holds the currently displayed scan so the ring/verdict can be recomputed
  // once the VirusTotal call resolves (heuristics render immediately, VT follows).
  const current = { heuristicChecks: [], vtStats: null };

  function engineCardHTML(status, name, detail) {
    return `
      <div class="engine-card">
        <span class="engine-icon ${status}">${ICONS[status]}</span>
        <div>
          <div class="engine-name">${escapeHTML(name)}</div>
          <div class="engine-detail">${escapeHTML(detail)}</div>
        </div>
      </div>`;
  }

  function vtCategoryStatus(category) {
    if (category === "malicious" || category === "suspicious") return "flagged";
    if (category === "harmless" || category === "undetected") return "clean";
    return "info";
  }

  function updateSummary(targetLabel) {
    let flagged = current.heuristicChecks.filter((c) => c.status === "flagged").length;
    let total = current.heuristicChecks.length;

    if (current.vtStats) {
      flagged += (current.vtStats.malicious || 0) + (current.vtStats.suspicious || 0);
      total += Object.values(current.vtStats).reduce((a, b) => a + b, 0);
    }

    ringValue.textContent = `${flagged}/${total}`;
    const pct = total ? Math.round((flagged / total) * 100) : 0;
    ring.style.setProperty("--pct", pct);

    let verdictText, color;
    if (flagged === 0) {
      verdictText = "Likely Safe";
      color = "var(--green)";
    } else if (flagged <= 2) {
      verdictText = "Use Caution";
      color = "var(--yellow)";
    } else {
      verdictText = "Likely a Scam";
      color = "var(--red)";
    }
    ring.style.setProperty("--ring-color", color);
    verdictEl.textContent = verdictText;
    verdictEl.style.color = color;
    verdictTarget.textContent = targetLabel;
  }

  function renderHeuristics(checks, targetLabel, extraLinks) {
    current.heuristicChecks = checks;
    current.vtStats = null;
    updateSummary(targetLabel);

    engineGrid.innerHTML = checks.map((c) => engineCardHTML(c.status, c.name, c.detail)).join("");

    verifyRow.innerHTML = (extraLinks || [])
      .map((l) => `<a class="verify-link" href="${l.href}" target="_blank" rel="noopener">${escapeHTML(l.label)}</a>`)
      .join("");

    vtSection.hidden = true;
    vtGrid.innerHTML = "";
    vtUploadBtn.hidden = true;
    vtBadge.className = "vt-badge";
    vtBadge.textContent = "";
    vtNote.textContent = "";

    resultsSection.hidden = false;
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function setVtBadge(state, label) {
    vtBadge.className = `vt-badge ${state}`;
    vtBadge.textContent = label;
  }

  function showVtLoading(note) {
    vtSection.hidden = false;
    setVtBadge("loading", "Scanning…");
    vtNote.textContent = note || "Checking VirusTotal's live database…";
    vtUploadBtn.hidden = true;
    vtGrid.innerHTML = "";
  }

  function showVtReport(targetLabel, report) {
    current.vtStats = report.stats || {};
    updateSummary(targetLabel);

    const total = Object.values(current.vtStats).reduce((a, b) => a + b, 0);
    const flagged = (current.vtStats.malicious || 0) + (current.vtStats.suspicious || 0);
    setVtBadge("ready", `${flagged}/${total} vendors flagged`);
    vtNote.textContent = "";
    vtUploadBtn.hidden = true;

    const sorted = [...(report.results || [])].sort((a, b) => {
      const rank = { malicious: 0, suspicious: 1, timeout: 2, undetected: 3, harmless: 4, "type-unsupported": 5 };
      return (rank[a.category] ?? 9) - (rank[b.category] ?? 9);
    });

    vtGrid.innerHTML = sorted
      .map((r) => engineCardHTML(vtCategoryStatus(r.category), r.engine, r.result || r.category))
      .join("");

    if (report.permalink) {
      verifyRow.insertAdjacentHTML(
        "afterbegin",
        `<a class="verify-link" href="${report.permalink}" target="_blank" rel="noopener">Open full report on VirusTotal ↗</a>`
      );
    }
  }

  function showVtError(message) {
    vtSection.hidden = false;
    setVtBadge("error", "Unavailable");
    vtNote.textContent = message;
    vtUploadBtn.hidden = true;
    vtGrid.innerHTML = "";
  }

  function showVtUnknownFile(file) {
    vtSection.hidden = false;
    setVtBadge("unknown", "Not seen before");
    vtNote.textContent = "VirusTotal has no record of this file's hash. Upload the file itself to get it scanned by their engines.";
    vtUploadBtn.hidden = false;
    vtUploadBtn.disabled = false;
    vtUploadBtn.textContent = "Upload & scan with VirusTotal";
    vtGrid.innerHTML = "";

    vtUploadBtn.onclick = async () => {
      vtUploadBtn.disabled = true;
      vtUploadBtn.textContent = "Uploading…";
      try {
        const submit = await vtFileUpload(file);
        showVtLoading("VirusTotal is scanning the uploaded file…");
        const report = await pollAnalysis(submit.analysisId);
        showVtReport(file.name, report);
      } catch (err) {
        showVtError(err.message);
      }
    };
  }

  function escapeHTML(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  /* ---------- Scan action ---------- */

  scanButton.addEventListener("click", async () => {
    scanButton.disabled = true;
    const originalLabel = scanButton.querySelector(".scan-button-label").textContent;
    scanButton.querySelector(".scan-button-label").textContent = "Scanning…";

    try {
      if (activeTab === "url") {
        const raw = document.getElementById("url-input").value.trim();
        if (!raw) return;
        const checks = analyzeUrl(raw);
        renderHeuristics(checks, raw, [
          { href: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(raw)}`, label: "Google Safe Browsing ↗" },
          { href: `https://urlscan.io/search/#${encodeURIComponent(raw)}`, label: "urlscan.io ↗" },
        ]);

        showVtLoading();
        try {
          let report = await vtUrlReport(raw);
          if (report.status === "queued") {
            showVtLoading("First time seeing this link — VirusTotal is scanning it now…");
            report = await pollAnalysis(report.analysisId);
          }
          showVtReport(raw, report);
        } catch (err) {
          showVtError(err.message);
        }
      } else if (activeTab === "file") {
        if (!selectedFile) return;
        const file = selectedFile;
        const { checks, hash } = await analyzeFile(file);
        renderHeuristics(checks, file.name, hash ? [{ href: `https://www.virustotal.com/gui/file/${hash}`, label: "Open file report on VirusTotal ↗" }] : []);

        if (hash) {
          showVtLoading("Checking this file's hash against VirusTotal…");
          try {
            const report = await vtFileReport(hash);
            if (report.status === "unknown") {
              showVtUnknownFile(file);
            } else {
              showVtReport(file.name, report);
            }
          } catch (err) {
            showVtError(err.message);
          }
        }
      } else {
        const text = document.getElementById("text-input").value.trim();
        if (!text) return;
        const checks = analyzeText(text);
        renderHeuristics(checks, "Pasted text", [
          { href: "https://reportfraud.ftc.gov/", label: "Report to the FTC ↗" },
        ]);
      }
    } finally {
      scanButton.disabled = false;
      scanButton.querySelector(".scan-button-label").textContent = originalLabel;
    }
  });
})();
