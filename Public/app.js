const form = document.getElementById("detect-form");
const input = document.getElementById("detector-input");
const fileInput = document.getElementById("file-input");
const contextInput = document.getElementById("context-input");
const result = document.getElementById("result");

const pillClass = (v) =>
  v?.includes("likely") || v === "flagged"
    ? "bad"
    : v?.includes("suspicious")
    ? "warn"
    : "ok";
const show = (html) => (result.innerHTML = `<div class="result">${html}</div>`);
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])
  );

/* drag & drop -> file input */
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

function aiMsg(ai, fallback = "No AI verdict") {
  return `<p class="muted">${esc(ai?._error || fallback)}</p>`;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = form.querySelector("button");
  btn.disabled = true;
  show("Detecting…");

  try {
    let body;
    let headers = {};
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

    if (data.mode === "file") {
      show(`
        <p>Detected: <span class="pill warn">uploaded image</span></p>
        ${
          data.ai && !data.ai._error
            ? `
          <p>Vision verdict: <span class="pill ${pillClass(
            data.ai.verdict
          )}">${esc(data.ai.verdict)}</span></p>
          <ul>${(data.ai.indicators || [])
            .map((s) => `<li>${esc(s)}</li>`)
            .join("")}</ul>
          <p class="muted"><b>Advice:</b> ${esc(data.ai.advice)}</p>
        `
            : aiMsg(data.ai)
        }
      `);
      return;
    }

    if (data.mode === "url") {
      if (data.type === "image_url") {
        show(`
          <p>Detected: <span class="pill ok">image URL</span></p>
          <p>Verdict: <span class="pill ${pillClass(data.verdict)}">${esc(
          data.verdict
        )}</span></p>
          ${
            data.ai && !data.ai._error
              ? `
            <ul>${(data.ai.indicators || [])
              .map((s) => `<li>${esc(s)}</li>`)
              .join("")}</ul>
            <p class="muted"><b>Advice:</b> ${esc(data.ai.advice)}</p>
          `
              : aiMsg(data.ai)
          }
        `);
        return;
      }
      if (data.type === "video_url") {
        show(`
          <p>Detected: <span class="pill ok">video URL</span></p>
          ${
            data.thumbnailUrl
              ? `<div><img class="thumb" src="${esc(
                  data.thumbnailUrl
                )}" alt="Thumbnail" /></div>`
              : ""
          }
          ${
            data.vision && !data.vision._error
              ? `
            <p>Thumbnail analysis: <span class="pill ${pillClass(
              data.vision.verdict
            )}">${esc(data.vision.verdict)}</span></p>
            <ul>${(data.vision.indicators || [])
              .map((s) => `<li>${esc(s)}</li>`)
              .join("")}</ul>
          `
              : data.vision
              ? aiMsg(data.vision)
              : ""
          }
          ${
            data.ai && !data.ai._error
              ? `
            <p>Meta risk: <span class="pill ${pillClass(data.ai.risk)}">${esc(
                  data.ai.risk
                )}</span></p>
            <ul>${(data.ai.signals || [])
              .map((s) => `<li>${esc(s)}</li>`)
              .join("")}</ul>
            <p class="muted"><b>Advice:</b> ${esc(data.ai.advice)}</p>
          `
              : aiMsg(data.ai)
          }
        `);
        return;
      }
      // generic link
      show(`
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
            : aiMsg(data.ai)
        }
      `);
      return;
    }

    // text/claim
    show(`
      <p>Detected: <span class="pill ok">claim / text</span></p>
      <p>Preliminary verdict: <span class="pill ${pillClass(
        data.verdict
      )}">${esc(data.verdict || "unverified")}</span></p>
      ${
        data.ai && !data.ai._error
          ? `
        ${
          Array.isArray(data.ai.checks)
            ? `<p><b>Verification steps</b></p><ol>${data.ai.checks
                .map(
                  (c) =>
                    `<li><b>${esc(c.step)}</b> — <small class="mono">${esc(
                      c.why
                    )}</small></li>`
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
          : aiMsg(data.ai)
      }
    `);
  } catch (err) {
    show(`<span class="pill bad">Error</span> ${esc(err.message)}`);
  } finally {
    btn.disabled = false;
  }
});
