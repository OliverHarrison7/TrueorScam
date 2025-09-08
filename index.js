import express from "express";
import morgan from "morgan";
import cors from "cors";
import fetch from "node-fetch";
import multer from "multer";
import path from "path";
import fs from "fs";
import "dotenv/config";

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(morgan("dev"));
app.use(cors());
app.use("/public", express.static("public"));

/* -------- utils -------- */
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

/* -------- Google Safe Browsing -------- */
async function checkSafeBrowsing(url) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key) return { flagged: false, raw: { disabled: true } };
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

/* -------- Gemini Helpers -------- */
const GEMINI_KEY = process.env.GEMINI_API_KEY;

// For text-only prompts
async function geminiText(prompt) {
  try {
    const resp = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
        }),
      }
    );
    const data = await resp.json();
    if (!resp.ok)
      return {
        _error: `Gemini error ${resp.status}: ${
          data.error?.message || "unknown"
        }`,
      };

    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
    const m = text.match(/\{[\s\S]*\}/);
    if (m) {
      try {
        return JSON.parse(m[0]);
      } catch {}
    }
    return { _error: "Bad/empty JSON from Gemini", raw: text };
  } catch (e) {
    return { _error: "Gemini request failed: " + e.message };
  }
}

// For image+text
async function geminiVision({ prompt, imageUrl }) {
  try {
    const resp = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                { text: prompt },
                {
                  inlineData: {
                    mimeType: "image/jpeg",
                    data: imageUrl.split(",")[1] || "",
                  },
                },
              ],
            },
          ],
        }),
      }
    );
    const data = await resp.json();
    if (!resp.ok)
      return {
        _error: `Gemini error ${resp.status}: ${
          data.error?.message || "unknown"
        }`,
      };

    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
    const m = text.match(/\{[\s\S]*\}/);
    if (m) {
      try {
        return JSON.parse(m[0]);
      } catch {}
    }
    return { _error: "Bad/empty JSON from Gemini", raw: text };
  } catch (e) {
    return { _error: "Gemini request failed: " + e.message };
  }
}

/* -------- Detector Endpoint -------- */
const uploadSingle = upload.single("file");
app.post("/api/detect", (req, res) =>
  uploadSingle(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });

    try {
      const { input, context } = req.body || {};
      const trimmed = (input || "").trim();

      // File upload (image)
      if (req.file) {
        const b = fs.readFileSync(req.file.path);
        const dataUrl =
          `data:${req.file.mimetype};base64,` + b.toString("base64");
        const ai = await geminiVision({
          prompt: `
Analyze this image for manipulation/deepfake/fraud.
Return JSON: {"verdict":"authentic|edited|uncertain","indicators":["..."],"advice":"..."}
Context: ${context || "(none)"}.
`.trim(),
          imageUrl: dataUrl,
        });
        fs.unlink(req.file.path, () => {});
        return res.json({
          mode: "file",
          detected: "image_upload",
          verdict: ai?.verdict || "unverified",
          ai,
        });
      }

      // URL input
      const url = normalizeUrl(trimmed);
      if (url) {
        if (isLikelyImageUrl(url)) {
          const ai = await geminiText(`
Analyze this image URL for manipulation/deepfake/fraud:
${url}
Return JSON: {"verdict":"authentic|edited|uncertain","indicators":["..."],"advice":"..."}
Context: ${context || "(none)"}.
        `);
          return res.json({
            mode: "url",
            type: "image_url",
            url,
            verdict: ai?.verdict || "unverified",
            ai,
          });
        }

        if (isLikelyVideoUrl(url)) {
          const id = ytId(url);
          const thumb = ytThumb(id);
          const ai = await geminiText(`
Analyze this video URL for scam/deepfake risk:
${url}
Thumbnail: ${thumb || "none"}
Return JSON: {"risk":"safe|suspicious|likely scam","signals":["..."],"advice":"..."}
Context: ${context || "(none)"}.
        `);
          return res.json({
            mode: "url",
            type: "video_url",
            url,
            thumbnailUrl: thumb,
            verdict: ai?.risk || "unverified",
            ai,
          });
        }

        const sb = await checkSafeBrowsing(url);
        const ai = await geminiText(`
Classify this URL as safe/suspicious/likely scam:
${url}
SafeBrowsingFlagged: ${sb.flagged}
Return JSON: {"risk":"safe|suspicious|likely scam","signals":["..."],"advice":"..."}
Context: ${context || "(none)"}.
      `);
        return res.json({
          mode: "url",
          type: "link",
          url,
          verdict: sb.flagged ? "likely scam" : ai?.risk || "clear",
          safeBrowsing: sb.flagged ? "flagged" : "clear",
          ai,
        });
      }

      // Claim / Text
      if (!trimmed)
        return res
          .status(400)
          .json({ error: "Provide URL, text, or image file." });
      const ai = await geminiText(`
Verify this claim/headline: "${trimmed}"
Return JSON: {"verdict":"unverified|likely true|likely false|misleading","checks":[{"step":"...","why":"..."}],"what_to_collect":["..."],"advice":"..."}
Context: ${context || "(none)"}.
    `);
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

/* Serve frontend */
app.get("/", (_req, res) => res.sendFile(path.resolve("index.html")));

app.listen(process.env.PORT || 3000, () => {
  console.log(
    `✓ TrueOrScam (Gemini edition) listening on http://localhost:${
      process.env.PORT || 3000
    }`
  );
});
