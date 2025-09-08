import express from "express";
import morgan from "morgan";
import cors from "cors";
import fetch from "node-fetch";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import exifr from "exifr";
import "dotenv/config";

/* -------------------- app + middleware -------------------- */
const app = express();
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: "2mb" }));
app.use(morgan("tiny"));
app.use("/public", express.static("public"));

app.use(
  rateLimit({
    windowMs: 60_000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

/* -------------------- utils -------------------- */
const normalizeUrl = (u) => {
  try {
    const x = new URL(u);
    if (!["http:", "https:"].includes(x.protocol)) return null;
    return x.toString();
  } catch {
    return null;
  }
};
const isLikelyImageUrl = (u) =>
  /\.(png|jpe?g|gif|webp|bmp|tiff?)(\?|#|$)/i.test(u);
const isLikelyVideoUrl = (u) =>
  /(youtube\.com|youtu\.be|vimeo\.com|\.mp4(\?|#|$))/i.test(u);

function ytId(u) {
  try {
    const url = new URL(u);
    if (url.hostname.includes("youtube.com")) return url.searchParams.get("v");
    if (url.hostname === "youtu.be") return url.pathname.slice(1);
  } catch {}
  return null;
}
const ytThumb = (id) =>
  id ? `https://img.youtube.com/vi/${id}/hqdefault.jpg` : null;

const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 5 * 1024 * 1024 },
});

const DEFAULT_TIMEOUT = 10_000;
async function safeFetch(url, opts = {}) {
  const controller = new AbortController();
  const id = setTimeout(
    () => controller.abort(),
    opts.timeout ?? DEFAULT_TIMEOUT
  );
  try {
    const res = await fetch(url, {
      headers: {
        "User-Agent": "TrueOrScamBot/2.0 (+https://example.com)",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      redirect: "follow",
      ...opts,
      signal: controller.signal,
    });
    return res;
  } finally {
    clearTimeout(id);
  }
}

const cache = new Map();
const setCache = (k, d, ttl = 10 * 60_000) =>
  cache.set(k, { d, t: Date.now() + ttl });
const getCache = (k) => {
  const v = cache.get(k);
  if (!v) return null;
  if (Date.now() > v.t) {
    cache.delete(k);
    return null;
  }
  return v.d;
};

function sha1(buf) {
  return crypto.createHash("sha1").update(buf).digest("hex");
}

/* -------------------- validation -------------------- */
const DetectBody = z.object({
  input: z.string().optional(),
  context: z.string().max(4000).optional(),
});

/* -------------------- Safe Browsing -------------------- */
async function checkSafeBrowsing(url) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key) return { flagged: false, raw: { disabled: true } };
  const resp = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "trueorscam", clientVersion: "2.0.0" },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    }
  );
  let data;
  try {
    data = await resp.json();
  } catch {
    data = { error: "non-JSON response" };
  }
  if (!resp.ok)
    return { flagged: false, raw: { error: data, status: resp.status } };
  const flagged = Array.isArray(data?.matches) && data.matches.length > 0;
  return { flagged, raw: data };
}

/* -------------------- Page heuristics -------------------- */
function basicUrlSignals(u) {
  try {
    const url = new URL(u);
    const host = url.hostname;
    const labels = host.split(".");
    const tld = labels.at(-1);
    const suspiciousTlds = new Set([
      "zip",
      "mov",
      "info",
      "top",
      "gq",
      "cf",
      "ml",
    ]);
    return {
      scheme: url.protocol.replace(":", ""),
      host,
      tld,
      pathLen: url.pathname.length,
      hasAt: url.href.includes("@"),
      hasIpHost: /^\d{1,3}(\.\d{1,3}){3}$/.test(host),
      manyDashes: host.split("-").length > 3,
      suspiciousTld: suspiciousTlds.has(tld),
    };
  } catch {
    return {};
  }
}

function htmlRedFlags(html = "") {
  const flags = [];
  if (/onload\s*=|onclick\s*=|eval\(/i.test(html))
    flags.push("Inline handlers or eval");
  if (/bitcoin|crypto\s*wallet|seed\s*phrase/i.test(html))
    flags.push("Crypto wallet bait");
  if (/giveaway/i.test(html)) flags.push("Giveaway bait");
  if (/login/i.test(html) && /verify/i.test(html))
    flags.push("Login + verification combo");
  if (/blur\(|filter:.*blur/i.test(html)) flags.push("CSS blur trick");
  return flags;
}

async function inspectPage(url) {
  try {
    let r = await safeFetch(url, { method: "HEAD" });
    const finalUrl = r.url || url;
    const headers = Object.fromEntries([...r.headers.entries()]);
    const contentType = headers["content-type"] || "";
    const isHtml = contentType.includes("text/html") || contentType === "";

    let html = "";
    if (isHtml) {
      r = await safeFetch(finalUrl, { method: "GET" });
      const buf = Buffer.from(await r.arrayBuffer());
      html = buf.toString("utf8").slice(0, 250_000);
    }

    let faviconHash = null;
    try {
      const origin = new URL(finalUrl).origin;
      const fav = await safeFetch(origin + "/favicon.ico", { timeout: 5000 });
      if (fav.ok) {
        const b = Buffer.from(await fav.arrayBuffer());
        faviconHash = sha1(b);
      }
    } catch {}

    return {
      finalUrl,
      status: r.status,
      contentType,
      htmlSnippet: html.slice(0, 5000),
      faviconHash,
    };
  } catch (e) {
    return { error: String(e) };
  }
}

/* -------------------- EXIF -------------------- */
async function parseExifFromDataUrl(dataUrl) {
  try {
    const b64 = dataUrl.split(",")[1] || "";
    const buf = Buffer.from(b64, "base64");
    const exif = await exifr.parse(buf).catch(() => null);
    if (!exif) return { hasExif: false };
    const keep = (({
      Make,
      Model,
      Software,
      ModifyDate,
      CreateDate,
      Orientation,
      LensModel,
    }) => ({
      Make,
      Model,
      Software,
      ModifyDate,
      CreateDate,
      Orientation,
      LensModel,
    }))(exif);
    return { hasExif: true, meta: keep };
  } catch {
    return { hasExif: false };
  }
}

/* -------------------- Gemini with retry + mock fallback -------------------- */
const GEMINI_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-1.5-flash";

function mockFromPrompt(prompt) {
  const p = (prompt || "").toLowerCase();
  if (p.includes("verify this claim") || p.includes("headline")) {
    return {
      verdict: "unverified",
      checks: [
        {
          step: "Find primary source",
          why: "Confirm original speaker/publication",
        },
        {
          step: "Check date/location",
          why: "Spot recycled or out-of-context claims",
        },
      ],
      what_to_collect: ["source URL", "publication date", "speaker identity"],
      advice: "Cross-check with at least two reputable outlets.",
    };
  }
  if (p.includes("video url")) {
    return {
      risk: "suspicious",
      signals: ["Clickbait title pattern", "Unknown channel"],
      advice: "Verify channel history and corroborating sources.",
    };
  }
  if (p.includes("image")) {
    return {
      verdict: "uncertain",
      indicators: ["No EXIF metadata", "Slight edge artifacts"],
      advice: "Seek original upload; reverse image search.",
    };
  }
  return {
    risk: "suspicious",
    signals: ["Obscure domain TLD"],
    advice: "Avoid entering credentials or payment details.",
  };
}

async function geminiCallJSON({ parts }, { retries = 3 } = {}) {
  // Mock mode or no key -> immediate mock
  if (!GEMINI_KEY || GEMINI_KEY === "MOCK") {
    const text = parts?.map((p) => p.text).join("\n") || "";
    return { ...mockFromPrompt(text), _mock: true };
  }

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_KEY}`;

  for (let i = 0; i < retries; i++) {
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ contents: [{ parts }] }),
      });

      const bodyText = await resp.text();
      let data;
      try {
        data = JSON.parse(bodyText);
      } catch {
        data = {};
      }

      // If overloaded -> exponential backoff, then final fallback to mock
      if (resp.status === 503) {
        if (i < retries - 1) {
          const wait = (i + 1) * 1000;
          await new Promise((r) => setTimeout(r, wait));
          continue;
        }
        const text = parts?.map((p) => p.text).join("\n") || "";
        return { ...mockFromPrompt(text), _fallback: "gemini_503" };
      }

      if (!resp.ok) {
        const msg = data?.error?.message || bodyText || "unknown";
        return { _error: `Gemini error ${resp.status}: ${msg}` };
      }

      const text = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
      const m = text.match(/\{[\s\S]*\}/);
      if (m) {
        try {
          return JSON.parse(m[0]);
        } catch {}
      }
      // If model returned prose, degrade gracefully
      return { _error: "Bad/empty JSON from Gemini", raw: text };
    } catch (e) {
      // Network errors -> retry, then mock at the end
      if (i < retries - 1) {
        await new Promise((r) => setTimeout(r, 500));
        continue;
      }
      const text = parts?.map((p) => p.text).join("\n") || "";
      return { ...mockFromPrompt(text), _fallback: "network_error" };
    }
  }
  // Shouldn't reach here
  const text = parts?.map((p) => p.text).join("\n") || "";
  return { ...mockFromPrompt(text), _fallback: "unknown" };
}

// Text-only wrapper
async function geminiText(prompt) {
  return geminiCallJSON({ parts: [{ text: prompt }] });
}

// Vision wrapper (expects data URL; converts to inlineData)
async function geminiVision({ prompt, imageDataUrl }) {
  if (!GEMINI_KEY || GEMINI_KEY === "MOCK") {
    return { ...mockFromPrompt("image " + prompt), _mock: true };
  }
  const base64 = imageDataUrl.split(",")[1] || "";
  const mime =
    (imageDataUrl.match(/^data:(.*?);base64,/) || [])[1] || "image/jpeg";
  return geminiCallJSON({
    parts: [{ text: prompt }, { inlineData: { mimeType: mime, data: base64 } }],
  });
}

/* -------------------- core detection -------------------- */
async function detectByUrl(url, context) {
  if (isLikelyImageUrl(url)) {
    // Text-only prompt about an image URL (Gemini vision prefers inline data)
    const ai = await geminiText(
      `
Analyze this image URL for manipulation/deepfake/fraud:
${url}
Return JSON: {"verdict":"authentic|edited|uncertain","indicators":["..."],"advice":"..."}
Context: ${context || "(none)"}.
`.trim()
    );
    return {
      type: "image_url",
      verdict: ai?.verdict || "unverified",
      safeBrowsing: "n/a",
      ai,
    };
  }

  if (isLikelyVideoUrl(url)) {
    const id = ytId(url);
    const thumb = ytThumb(id);
    const ai = await geminiText(
      `
Analyze this video URL for scam/deepfake risk:
${url}
Thumbnail: ${thumb || "none"}
Return JSON: {"risk":"safe|suspicious|likely scam","signals":["..."],"advice":"..."}
Context: ${context || "(none)"}.
`.trim()
    );
    return {
      type: "video_url",
      verdict: ai?.risk || "unverified",
      thumbnailUrl: thumb || null,
      ai,
    };
  }

  // generic link with heuristics
  const sb = await checkSafeBrowsing(url);
  const urlSignals = basicUrlSignals(url);
  const page = await inspectPage(url);
  const redFlags = htmlRedFlags(page.htmlSnippet || "");

  const prompt = `
You are a fraud-risk assistant. Given structured signals + optional HTML snippet,
classify the URL: "safe" | "suspicious" | "likely scam". Return JSON:
{"risk":"...","signals":["..."],"advice":"..."}

URL: ${url}
SafeBrowsingFlagged: ${sb.flagged}
URLSignals: ${JSON.stringify(urlSignals)}
PageMeta: ${JSON.stringify({
    status: page.status,
    contentType: page.contentType,
    faviconHash: page.faviconHash,
  })}
HeuristicFlags: ${JSON.stringify(redFlags)}
HTML (snippet): ${page.htmlSnippet || "(none)"}
Context: ${context || "(none)"}.
`.trim();

  const ai = await geminiText(prompt);

  return {
    type: "link",
    verdict: sb.flagged ? "likely scam" : ai?.risk || "clear",
    safeBrowsing: sb?.raw?.disabled
      ? "disabled"
      : sb.flagged
      ? "flagged"
      : "clear",
    signals: {
      urlSignals,
      redFlags,
      page: { status: page.status, contentType: page.contentType },
    },
    ai,
  };
}

/* -------------------- routes -------------------- */
app.get("/health", (_req, res) =>
  res.json({ ok: true, time: new Date().toISOString() })
);

const uploadSingle = upload.single("file");
app.post("/api/detect", (req, res) =>
  uploadSingle(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });

    try {
      if (!req.file) {
        const parsed = DetectBody.safeParse(req.body || {});
        if (!parsed.success)
          return res.status(400).json({ error: "Bad request" });
      }

      const { input, context } = req.body || {};
      const trimmed = (input || "").trim();

      // File upload → vision + EXIF
      if (req.file) {
        const b = fs.readFileSync(req.file.path);
        const dataUrl =
          `data:${req.file.mimetype};base64,` + b.toString("base64");
        const exif = await parseExifFromDataUrl(dataUrl);
        const ai = await geminiVision({
          prompt: `
Analyze image for manipulation/deepfake. Return JSON:
{"verdict":"authentic|edited|uncertain","indicators":["..."],"advice":"..."}
Consider EXIF: ${JSON.stringify(exif)}.
Context: ${context || "(none)"}.
`.trim(),
          imageDataUrl: dataUrl,
        });
        fs.unlink(req.file.path, () => {});
        return res.json({
          mode: "file",
          detected: "image_upload",
          verdict: ai?.verdict || "unverified",
          exif,
          ai,
        });
      }

      // URL path
      const url = normalizeUrl(trimmed);
      if (url) {
        const cached = getCache(`url:${url}:${context || ""}`);
        if (cached) return res.json({ cached: true, ...cached });
        const out = await detectByUrl(url, context);
        setCache(`url:${url}:${context || ""}`, out);
        return res.json({ mode: "url", url, ...out });
      }

      // Plain text claim
      if (!trimmed)
        return res
          .status(400)
          .json({ error: "Provide URL, text, or image file." });
      const ai = await geminiText(
        `
Verify this claim/headline: "${trimmed}"
Return JSON: {"verdict":"unverified|likely true|likely false|misleading","checks":[{"step":"...","why":"..."}],"what_to_collect":["..."],"advice":"..."}
Context: ${context || "(none)"}.
`.trim()
      );
      return res.json({
        mode: "text",
        detected: "claim",
        verdict: ai?.verdict || "unverified",
        ai,
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "Internal error" });
    }
  })
);

app.get("/", (_req, res) => res.sendFile(path.resolve("index.html")));

const port = process.env.PORT || 3000;
app.listen(port, () =>
  console.log(`✓ TrueOrScam v2 (Gemini+Retry/Mock) http://localhost:${port}`)
);
