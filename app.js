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

  /* ---------- Rendering ---------- */

  const resultsSection = document.getElementById("results");
  const ring = document.getElementById("ring");
  const ringValue = document.getElementById("ring-value");
  const verdictEl = document.getElementById("verdict");
  const verdictTarget = document.getElementById("verdict-target");
  const engineGrid = document.getElementById("engine-grid");
  const verifyRow = document.getElementById("verify-row");
  const scanButton = document.getElementById("scan-button");

  const ICONS = {
    clean: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    flagged: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="3" stroke-linecap="round"/></svg>',
    info: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2.4"/><path d="M12 8v5m0 3h.01" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>',
  };

  function renderResults(checks, targetLabel, extraLinks) {
    const flagged = checks.filter((c) => c.status === "flagged").length;
    const total = checks.length;

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

    engineGrid.innerHTML = checks
      .map(
        (c) => `
      <div class="engine-card">
        <span class="engine-icon ${c.status}">${ICONS[c.status]}</span>
        <div>
          <div class="engine-name">${escapeHTML(c.name)}</div>
          <div class="engine-detail">${escapeHTML(c.detail)}</div>
        </div>
      </div>`
      )
      .join("");

    verifyRow.innerHTML = (extraLinks || [])
      .map((l) => `<a class="verify-link" href="${l.href}" target="_blank" rel="noopener">${escapeHTML(l.label)}</a>`)
      .join("");

    resultsSection.hidden = false;
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
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
        renderResults(checks, raw, [
          { href: `https://www.virustotal.com/gui/search/${encodeURIComponent(raw)}`, label: "Check on VirusTotal ↗" },
          { href: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(raw)}`, label: "Google Safe Browsing ↗" },
          { href: `https://urlscan.io/search/#${encodeURIComponent(raw)}`, label: "urlscan.io ↗" },
        ]);
      } else if (activeTab === "file") {
        if (!selectedFile) return;
        const { checks, hash } = await analyzeFile(selectedFile);
        const links = [];
        if (hash) links.push({ href: `https://www.virustotal.com/gui/file/${hash}`, label: "Check hash on VirusTotal ↗" });
        renderResults(checks, selectedFile.name, links);
      } else {
        const text = document.getElementById("text-input").value.trim();
        if (!text) return;
        const checks = analyzeText(text);
        renderResults(checks, "Pasted text", [
          { href: "https://reportfraud.ftc.gov/", label: "Report to the FTC ↗" },
        ]);
      }
    } finally {
      scanButton.disabled = false;
      scanButton.querySelector(".scan-button-label").textContent = originalLabel;
    }
  });
})();
