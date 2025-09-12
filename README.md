# TrueOrScam — AI fraud & misinformation detector

Verify **links, images, video, and text claims** with one input.  
Backed by **Google Gemini**, **Safe Browsing**, and **lightweight heuristics** (HTML/URL checks, EXIF) — wrapped in a clean, modern UX.

> Goal: close the fraud-detection gap for everyday users in the age of AI media.

---

## ✨ Highlights

- **One box, many signals** — paste a URL/claim or drop an image; the app routes to the right checks.
- **Gemini analysis** — text & vision (with **retry + backoff** and **automatic mock fallback** when the model is busy).
- **Safety signals** — Google **Safe Browsing**, page fetch with HTML heuristics, favicon hash, URL red flags.
- **Image forensics** — **EXIF** metadata read (camera, software, dates).
- **Solid backend** — Node/Express with **Helmet**, **rate limiting**, **Zod** validation, **timeouts**.
- **Modern UI** — polished dark/light theme, drag-and-drop, instant verdict pills.

---

## 🧭 How it works (quick flow)

1. Input (URL/claim) or image upload.
2. If URL → Safe Browsing + page fetch (HEAD/GET, small cap) → heuristics (HTML flags, URL shape, favicon hash).
3. If image → EXIF parse; if video → thumbnail inspection and meta checks.
4. Signals are summarized and sent to **Gemini** for a structured JSON verdict.
5. UI shows **verdict + signals + advice** (with graceful mock output if the model is overloaded).

---

## 🛠 Tech

- **Backend:** Node.js (Express), `helmet`, `express-rate-limit`, `zod`, `node-fetch`, `multer`
- **Signals:** Google Safe Browsing v4, `exifr` (EXIF)
- **AI:** Google **Gemini 1.5** (`flash` by default; can switch to `pro`)
- **Frontend:** Vanilla HTML/CSS/JS (no heavy framework), drag-and-drop, dark/light theme

---

## 🚀 Quickstart

```bash
git clone https://github.com/OliverHarrison7/TrueorScam.git
cd TrueorScam
npm install
cp .env.example .env
# edit .env with your keys (see below)
npm run dev
# open http://localhost:3000
