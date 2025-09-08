import express from "express";
import morgan from "morgan";
import cors from "cors";
import fetch from "node-fetch";
import "dotenv/config";

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));
app.use(cors());

// ---- rate limiter ----
function rateLimit({ windowMs = 60_000, max = 60 } = {}) {
  const hits = new Map();
  return (req, res, next) => {
    const ip =
      req.ip ||
      req.headers["x-forwarded-for"] ||
      req.connection?.remoteAddress ||
      "unknown";
    const now = Date.now();
    const entry = hits.get(ip) || { count: 0, start: now };
    if (now - entry.start > windowMs) {
      entry.count = 0;
      entry.start = now;
    }
    entry.count += 1;
    hits.set(ip, entry);
    if (entry.count > max)
      return res.status(429).json({ error: "Too many requests, slow down." });
    next();
  };
}
app.use(rateLimit());

// ---- cache ----
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

const normalizeUrl = (u) => {
  try {
    const x = new URL(u);
    if (!["http:", "https:"].includes(x.protocol)) return null;
    return x.toString();
  } catch {
    return null;
  }
};

async function checkSafeBrowsing(url) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key) throw new Error("Missing GOOGLE_SAFE_BROWSING_KEY");
  const resp = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "trueorscam", clientVersion: "1.0.0" },
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
  const data = await resp.json();
  const flagged = Array.isArray(data?.matches) && data.matches.length > 0;
  return { flagged, raw: data };
}

async function aiAssess({ url, safeBrowsingFlagged, context }) {
  const key = process.env.OPENAI_API_KEY;
  if (!key) return null; // optional
  const prompt = `
You are a security assistant. Classify the risk of this URL as "safe", "suspicious", or "likely scam". Be concise.
Return ONLY JSON: {"risk":"...","rationale":"..."}.

URL: ${url}
SafeBrowsingFlagged: ${safeBrowsingFlagged}
UserContext: ${context || "(none)"}
`.trim();

  const resp = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${key}`,
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0,
    }),
  });
  const json = await resp.json();
  let content = json?.choices?.[0]?.message?.content || "{}";
  const m = content.match(/\{[\s\S]*\}/);
  if (m) content = m[0];
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}

app.get("/health", (_req, res) =>
  res.json({ ok: true, time: new Date().toISOString() })
);

app.post("/api/check", async (req, res) => {
  try {
    const { url: raw, context } = req.body || {};
    const url = normalizeUrl(raw);
    if (!url)
      return res
        .status(400)
        .json({ error: "Invalid or missing URL (http/https only)." });

    const cached = getCache(url);
    if (cached) return res.json({ cached: true, ...cached });

    const sb = await checkSafeBrowsing(url);
    const ai = await aiAssess({
      url,
      safeBrowsingFlagged: sb.flagged,
      context,
    });
    const verdict = sb.flagged ? "likely scam" : ai?.risk || "clear";

    const result = {
      url,
      verdict,
      safeBrowsing: sb.flagged ? "flagged" : "clear",
      ai: ai || undefined,
    };
    setCache(url, result);
    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal error" });
  }
});

app.post("/api/explain", async (req, res) => {
  try {
    const key = process.env.OPENAI_API_KEY;
    if (!key) return res.status(400).json({ error: "OPENAI_API_KEY not set." });
    const { text, html, url } = req.body || {};
    const content = text || html || "";
    if (!content && !url)
      return res.status(400).json({ error: "Provide text/html and/or url." });

    const prompt = `
Analyze this content for scam indicators. Output JSON:
{"verdict":"safe|suspicious|likely scam","indicators":["...","..."],"advice":"..."}
URL(optional): ${url || "(none)"}
CONTENT START
${content.slice(0, 6000)}
CONTENT END
`.trim();

    const resp = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${key}`,
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
        temperature: 0,
      }),
    });
    const json = await resp.json();
    let contentOut = json?.choices?.[0]?.message?.content || "{}";
    const m = contentOut.match(/\{[\s\S]*\}/);
    if (m) contentOut = m[0];
    const parsed = JSON.parse(contentOut);
    res.json(parsed);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal error" });
  }
});

app.use(express.static("."));
const port = process.env.PORT || 3000;
app.listen(port, () =>
  console.log(`✓ TrueOrScam listening on http://localhost:${port}`)
);
