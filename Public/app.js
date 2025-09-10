/* Elements */
const html = document.documentElement;
const form = document.getElementById("detect-form");
const input = document.getElementById("detector-input");
const fileInput = document.getElementById("file-input");
const contextInput = document.getElementById("context-input");
const result = document.getElementById("result");
const runBtn = document.getElementById("run-btn");
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
  setTimeout(() => toast.classList.remove("show"), 1500);
};

/* Theme (deterministic, no 'system' mode switching after load) */
const THEME_KEY = "tos_theme";
function setTheme(t) {
  html.setAttribute("data-theme", t);
  localStorage.setItem(THEME_KEY, t);
}
(function initTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === "light" || saved === "dark") {
    setTheme(saved);
  } else {
    setTheme(
      window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light"
    );
  }
})();
themeBtn.addEventListener("click", () => {
  const next = html.getAttribute("data-theme") === "dark" ? "light" : "dark";
  setTheme(next);
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

/* Renderers (simplified: no raw JSON, no technical details) */
function renderImageUrl(data) {
  return `
    <p>Detected: <span class="pill ok">image URL</span></p>
    <p>Verdict: <span class="pill ${pillClass(data.verdict)}">${esc(
    data.verdict
  )}</span></p>
    ${
      data.ai && !data.ai._error
        ? `
      ${
        (data.ai.indicators || []).length
          ? `<p><b>Indicators</b></p><ul>${data.ai.indicators
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
      <p>Risk: <span class="pill ${pillClass(data.ai.risk)}">${esc(
            data.ai.risk
          )}</span></p>
      ${
        (data.ai.signals || []).length
          ? `<p><b>Signals</b></p><ul>${data.ai.signals
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
function renderLink(data) {
  return `
    <p>Detected: <span class="pill ok">link</span> — <code>${esc(
      data.url
    )}</code></p>
    <p>Verdict: <span class="pill ${pillClass(data.verdict)}">${esc(
    data.verdict
  )}</span></p>
    <p>Safe Browsing: <span class="pill ${pillClass(data.safeBrowsing)}">${esc(
    data.safeBrowsing
  )}</span></p>
    ${
      data.ai && !data.ai._error
        ? `
      ${
        (data.ai.signals || []).length
          ? `<p><b>Signals</b></p><ul>${data.ai.signals
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
function renderFile(data) {
  return `
    <p>Detected: <span class="pill warn">uploaded image</span></p>
    ${
      data.ai && !data.ai._error
        ? `
      <p>Verdict: <span class="pill ${pillClass(data.ai.verdict)}">${esc(
            data.ai.verdict
          )}</span></p>
      ${
        (data.ai.indicators || []).length
          ? `<p><b>Indicators</b></p><ul>${data.ai.indicators
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
function renderClaim(data) {
  return `
    <p>Detected: <span class="pill ok">claim / text</span></p>
    <p>Verdict: <span class="pill ${pillClass(data.verdict)}">${esc(
    data.verdict || "unverified"
  )}</span></p>
    ${
      data.ai && !data.ai._error
        ? `
      ${
        Array.isArray(data.ai.checks) && data.ai.checks.length
          ? `<p><b>How to verify</b></p><ol>${data.ai.checks
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
        Array.isArray(data.ai.what_to_collect) && data.ai.what_to_collect.length
          ? `<p><b>Collect this</b></p><ul>${data.ai.what_to_collect
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

    showCard(html);
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
