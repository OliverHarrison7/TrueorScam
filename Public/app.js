/* Elements */
const html = document.documentElement;
const form = document.getElementById("detect-form");
const input = document.getElementById("detector-input");
const fileInput = document.getElementById("file-input");
const contextInput = document.getElementById("context-input");
const result = document.getElementById("result");
const runBtn = document.getElementById("run-btn");
const copyBtn = document.getElementById("copy-json");
const clearBtn = document.getElementById("clear-result");
const themeBtn = document.getElementById("theme-toggle");
const toast = document.getElementById("toast");

/* Helpers */
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])
  );
const pillClass = (v) =>
  v?.includes?.("likely") || v === "flagged"
    ? "bad"
    : v?.includes?.("suspicious")
    ? "warn"
    : "ok";
const show = (html) => {
  result.innerHTML = html;
};
const showCard = (inner) => show(`<div class="card glass">${inner}</div>`);
const showToast = (msg) => {
  toast.textContent = msg;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 1800);
};

/* Theme (persist) */
function applyTheme(pref) {
  html.setAttribute("data-theme", pref);
  localStorage.setItem("theme", pref);
}
const savedTheme = localStorage.getItem("theme");
if (savedTheme) applyTheme(savedTheme);
themeBtn.addEventListener("click", () => {
  const cur = html.getAttribute("data-theme") || "system";
  applyTheme(cur === "dark" ? "light" : "dark");
});

/* Drag & drop */
["dragenter", "dragover"].forEach((ev) =>
  form.addEventListener(ev, (e) => {
    e.preventDefault();
    e.stopPropagation();
    form.classList.add("drag");
  })
);
["dragleave", "drop"].forEach((ev) =>
  form.addEventListener(ev, (e) => {
    e.preventDefault();
    e.stopPropagation();
    form.classList.remove("drag");
  })
);
form.addEventListener("drop", (e) => {
  if (e.dataTransfer.files?.[0]) fileInput.files = e.dataTransfer.files;
});

/* Shortcut */
input.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") form.requestSubmit();
});

/* Renderers */
function renderImageUrl(data) {
  return `
    <p>Detected: <span class="pill ok">image URL</span></p>
    <p>Verdict: <span class="pill ${pillClass(data.verdict)}">${esc(
    data.verdict
  )}</span></p>
    ${
      data.ai && !data.ai._error
        ? `
      <p><b>Indicators</b></p>
      <ul>${(data.ai.indicators || [])
        .map((s) => `<li>${esc(s)}</li>`)
        .join("")}</ul>
      <p class="muted"><b>Advice:</b> ${esc(data.ai.advice)}</p>
    `
        : `<p class="muted">${esc(
            (data.ai && data.ai._error) || "No AI verdict"
          )}</p>`
    }
  `;
}
function renderVideoUrl(data) {
  return `
    <p>Detected: <span class="pill ok">video URL</span></p>
    ${
      data.thumbnailUrl
        ? `<div style="margin:.2rem 0 .8rem"><img class="thumb" src="${esc(
            data.thumbnailUrl
          )}" alt="Thumbnail" /></div>`
        : ""
    }
    ${
      data.ai && !data.ai._error
        ? `
      <p>Meta risk: <span class="pill ${pillClass(data.ai.risk)}">${esc(
            data.ai.risk
          )}</span></p>
      <p><b>Signals</b></p>
      <ul>${(data.ai.signals || [])
        .map((s) => `<li>${esc(s)}</li>`)
        .join("")}</ul>
      <p class="muted"><b>Advice:</b> ${esc(data.ai.advice)}</p>
    `
        : `<p class="muted">${esc(
            (data.ai && data.ai._error) || "No AI verdict"
          )}</p>`
    }
  `;
}
function renderLink(data) {
  return `
    <p>Detected: <span class="pill ok">link</span> — <code>${esc(
      data.url
    )}</code></p>
    <p>Verdict: <span class="pill ${pillClass(data.verdict)}">${esc(
    data.verdict
  )}</span></p>
    <p>Google Safe Browsing: <span class="pill ${pillClass(
      data.safeBrowsing
    )}">${esc(data.safeBrowsing)}</span></p>
    ${
      data.ai && !data.ai._error
        ? `
      <p><b>Signals</b></p>
      <ul>${(data.ai.signals || [])
        .map((s) => `<li>${esc(s)}</li>`)
        .join("")}</ul>
      <p class="muted"><b>Advice:</b> ${esc(data.ai.advice)}</p>
    `
        : `<p class="muted">${esc(
            (data.ai && data.ai._error) || "No AI verdict"
          )}</p>`
    }
    ${
      data.signals
        ? `
      <details>
        <summary>Technical signals</summary>
        <div class="content"><pre id="tech-json">${esc(
          JSON.stringify(data.signals, null, 2)
        )}</pre></div>
      </details>
    `
        : ""
    }
  `;
}
function renderFile(data) {
  return `
    <p>Detected: <span class="pill warn">uploaded image</span></p>
    ${
      data.ai && !data.ai._error
        ? `
      <p>Vision verdict: <span class="pill ${pillClass(data.ai.verdict)}">${esc(
            data.ai.verdict
          )}</span></p>
      <p><b>Indicators</b></p>
      <ul>${(data.ai.indicators || [])
        .map((s) => `<li>${esc(s)}</li>`)
        .join("")}</ul>
      <p class="muted"><b>Advice:</b> ${esc(data.ai.advice)}</p>
    `
        : `<p class="muted">${esc(
            (data.ai && data.ai._error) || "No AI verdict"
          )}</p>`
    }
    ${
      data.exif
        ? `
      <details>
        <summary>EXIF</summary>
        <div class="content"><pre>${esc(
          JSON.stringify(data.exif, null, 2)
        )}</pre></div>
      </details>`
        : ""
    }
  `;
}
function renderClaim(data) {
  return `
    <p>Detected: <span class="pill ok">claim / text</span></p>
    <p>Preliminary verdict: <span class="pill ${pillClass(data.verdict)}">${esc(
    data.verdict || "unverified"
  )}</span></p>
    ${
      data.ai && !data.ai._error
        ? `
      ${
        Array.isArray(data.ai.checks)
          ? `<p><b>Verification steps</b></p><ol>${data.ai.checks
              .map(
                (c) =>
                  `<li><b>${esc(c.step)}</b> — <span class="muted">${esc(
                    c.why
                  )}</span></li>`
              )
              .join("")}</ol>`
          : ""
      }
      ${
        data.ai.what_to_collect
          ? `<p><b>What to collect</b></p><ul>${data.ai.what_to_collect
              .map((s) => `<li>${esc(s)}</li>`)
              .join("")}</ul>`
          : ""
      }
      ${
        data.ai.advice
          ? `<p class="muted"><b>Advice:</b> ${esc(data.ai.advice)}</p>`
          : ""
      }
    `
        : `<p class="muted">${esc(
            (data.ai && data.ai._error) || "No AI verdict"
          )}</p>`
    }
  `;
}

/* Run detection */
async function runDetection() {
  runBtn.disabled = true;
  runBtn.innerHTML = `<span class="loader"></span> Analyzing…`;

  try {
    let body,
      headers = {};
    if (fileInput.files?.length) {
      const fd = new FormData();
      fd.append("file", fileInput.files[0]);
      fd.append("context", contextInput.value.trim());
      body = fd;
    } else {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify({
        input: input.value,
        context: contextInput.value.trim(),
      });
    }

    const r = await fetch("/api/detect", { method: "POST", headers, body });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || r.statusText);

    let html = "";
    if (data.mode === "file") html = renderFile(data);
    else if (data.mode === "url") {
      if (data.type === "image_url") html = renderImageUrl(data);
      else if (data.type === "video_url") html = renderVideoUrl(data);
      else html = renderLink(data);
    } else {
      html = renderClaim(data);
    }

    showCard(
      html +
        `
      <details>
        <summary>Raw JSON</summary>
        <div class="content"><pre id="raw-json">${esc(
          JSON.stringify(data, null, 2)
        )}</pre></div>
      </details>
    `
    );
  } catch (err) {
    showCard(
      `<p class="pill bad">Error</p><p class="muted">${esc(err.message)}</p>`
    );
  } finally {
    runBtn.disabled = false;
    runBtn.innerHTML = `<span class="btn-icon">▶</span> Run detection`;
  }
}

/* Events */
form.addEventListener("submit", (e) => {
  e.preventDefault();
  runDetection();
});

copyBtn.addEventListener("click", async () => {
  const pre = document.getElementById("raw-json");
  const txt = pre ? pre.textContent : "";
  if (!txt) {
    showToast("Nothing to copy");
    return;
  }
  try {
    await navigator.clipboard.writeText(txt);
    showToast("JSON copied");
  } catch {
    showToast("Copy failed");
  }
});

clearBtn.addEventListener("click", () => {
  show(`
    <div class="placeholder">
      <div class="placeholder-icon">🧪</div>
      <p class="muted">Your analysis will appear here.</p>
    </div>
  `);
  showToast("Cleared");
});
