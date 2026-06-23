# GhostFilter AI

GhostFilter AI is a scam and phishing safety tool built for the **Youth Code x AI** hackathon. It helps a normal person answer one urgent question:

> “Can I trust this message, link, email, or file?”

Instead of only saying “spam” or “not spam,” GhostFilter explains the risk in plain English, highlights the evidence, and gives the user a safer next step before they click, reply, pay, or share a code.

## What judges should know

GhostFilter is designed as a public-facing protection layer for everyday scams:

- Paste suspicious SMS, WhatsApp/Telegram/Discord/Instagram-style messages, emails, or links.
- Upload screenshots, PDFs, `.eml` emails, and text files.
- Connect read-only sources like Gmail, Google Drive, and GitHub notifications.
- Get a clear verdict: **Looks safe**, **Be careful**, or **Likely scam**.
- See why: suspicious phrases, unsafe links, sender/header forensics, risk signals, and safe page previews.
- Take action: safety checklist, copy/share/download report, rescan, delete history, and submit correction feedback.

## Live vs roadmap

| Area | Status | What it does |
|---|---:|---|
| Manual message scanner | Live | Paste SMS, chat messages, emails, or links. |
| File scanner | Live | Reads screenshots/images, PDFs, `.eml`, and text files before analysis. |
| Gmail | Live | Read-only OAuth scan of recent inbox messages. |
| Google Drive | Live | Read-only scan of recent Drive files/metadata. |
| GitHub | Live | Read-only scan of notification-style security/social-engineering messages. |
| VirusTotal | Live when key is set | Checks domain reputation for links. |
| urlscan.io | Live when key is set | Creates a sandboxed page preview for suspicious links. |
| WhatsApp / Telegram / Discord / SMS lanes | Manual paste | Browsers cannot read private chats automatically, so GhostFilter supports them as paste lanes. |
| Outlook / Slack | Roadmap UI | Shown as next integration lanes for the product direction. |

## Demo flow

1. Open the landing page.
2. Click **Open scanner**.
3. Paste a suspicious message, for example:

   ```text
   send 150 rupees, im real shah rukh khan
   ```

4. Review:
   - risk score
   - plain-English explanation
   - pattern spotted
   - safety checklist
   - highlighted message evidence
5. Try the file tab with a screenshot/PDF, or connect Gmail/GitHub if credentials are configured.

## How it works

GhostFilter combines deterministic security checks, a local ML classifier, and selective AI review.

```text
User input / connected source
        ↓
Text + file extraction
        ↓
Local classifier + heuristics
        ↓
Link intelligence + email forensics
        ↓
Gemini review only when needed
        ↓
Verdict + explanation + safe action plan
```

### Analysis layers

1. **Local classifier**
   - `lib/ml-classifier.ts`
   - Logistic regression trained from scratch without ML libraries.
   - Uses `lib/ml-weights.json`.
   - Fast triage runs on every scan.

2. **Deterministic security heuristics**
   - `lib/heuristics.ts` checks links, shortened URLs, redirects, and lookalike domains.
   - `lib/socialEngineering.ts` catches impersonation + payment patterns.
   - `lib/promptInjection.ts` detects manipulation attempts.
   - `lib/emailHeaders.ts` parses sender/authentication/header mismatches.

3. **External threat intelligence**
   - `lib/virustotal.ts` checks domain reputation.
   - `lib/urlscan.ts` creates a sandboxed preview of linked pages.

4. **AI review**
   - `lib/gemini.ts` gives structured verdicts, confidence, flagged phrases, and recommendations.
   - Gemini is called only when the classifier or deterministic checks find enough risk, which keeps the system cheaper and faster.

5. **File extraction**
   - `lib/fileExtraction.ts`
   - Uses Gemini multimodal extraction for screenshots/images and PDFs.

## Product features

- Sleek landing page with splash screen.
- Dark/light mode.
- Main scanner with message, email, link, and file modes.
- 3D risk card and tactile UI surfaces.
- Collapsible scan history sidebar.
- Search, filter, and sort scan history.
- Human-friendly result panel.
- Technical details hidden behind disclosure panels.
- Copy/download/share scan reports.
- Correction feedback for wrong results.
- Read-only connected source scanning.
- Clear distinction between live integrations and roadmap lanes.

## Tech stack

- **Next.js 16** app router
- **React 19**
- **Convex** backend, database, queries, mutations, and actions
- **Gemini** for structured review and file extraction
- **Framer Motion** for tactile UI motion
- **Tailwind CSS v4**
- **VirusTotal** and **urlscan.io** integrations

## Project structure

```text
app/
  LandingPage.tsx              Public landing page
  dashboard/page.tsx           Main scanner UI
  profile/page.tsx             History/analytics view
  api/auth/google/             Google OAuth routes
  api/auth/github/             GitHub OAuth routes

convex/
  pipeline.ts                  Shared analysis pipeline
  gmail.ts                     Gmail scanner
  drive.ts                     Google Drive scanner
  github.ts                    GitHub notification scanner
  scanResults.ts               Scan storage, feedback, deletion
  schema.ts                    Convex database schema

lib/
  ml-classifier.ts             Local classifier
  socialEngineering.ts         Impersonation/payment detection
  heuristics.ts                Link/domain heuristics
  emailHeaders.ts              Email forensic checks
  gemini.ts                    AI reviewer
  fileExtraction.ts            Image/PDF text extraction
  virustotal.ts                Domain reputation
  urlscan.ts                   Sandboxed page preview

scripts/
  train-classifier.ts          Offline classifier training
  download-corpus.sh           Optional public corpus download
```

## Setup

Install dependencies:

```bash
npm install
```

Run Convex in one terminal:

```bash
npx convex dev
```

Run Next.js in another terminal:

```bash
npm run dev
```

Open:

- Landing page: [http://localhost:3000](http://localhost:3000)
- Scanner: [http://localhost:3000/dashboard](http://localhost:3000/dashboard)

## Environment variables

Create `.env.local`.

| Variable | Required? | Purpose |
|---|---:|---|
| `NEXT_PUBLIC_CONVEX_URL` | Yes | Convex client URL. Created by `npx convex dev`. |
| `CONVEX_DEPLOYMENT` | Yes | Convex deployment identifier. |
| `NEXT_PUBLIC_CONVEX_SITE_URL` | Usually | Convex site URL. |
| `NEXT_PUBLIC_APP_URL` | Optional | Defaults to `http://localhost:3000`; set in production. |
| `GEMINI_API_KEY` | Yes for AI/file review | Gemini structured verdicts and file extraction. Also set in Convex with `npx convex env set GEMINI_API_KEY <key>`. |
| `GOOGLE_CLIENT_ID` | For Gmail/Drive | Google OAuth client ID. Also set in Convex. |
| `GOOGLE_CLIENT_SECRET` | For Gmail/Drive | Google OAuth secret. Also set in Convex. |
| `GITHUB_CLIENT_ID` | For GitHub | GitHub OAuth client ID. |
| `GITHUB_CLIENT_SECRET` | For GitHub | GitHub OAuth secret. |
| `VIRUSTOTAL_API_KEY` | Optional | Domain reputation checks. Set in Convex for actions. |
| `URLSCAN_API_KEY` | Optional | Sandboxed link previews. Set in Convex for actions. |

Google OAuth redirect URI for local development:

```text
http://localhost:3000/api/auth/google/callback
```

GitHub OAuth callback URL for local development:

```text
http://localhost:3000/api/auth/github/callback
```

## Retrain the classifier

```bash
scripts/download-corpus.sh
npm run train-classifier
```

The classifier can train on:

- `scripts/data/sms-spam.csv`
- optional SpamAssassin email corpus downloaded by the script

Only the trained weights are committed. The raw corpus is re-downloadable and ignored by git.

## Privacy and safety

- Connected Google/GitHub access is read-only.
- GhostFilter cannot send messages, edit files, delete emails, or act on behalf of the user.
- OAuth tokens are stored server-side in Convex, not exposed to the browser.
- Results are guidance, not a guarantee.
- For private chat apps, GhostFilter uses manual paste lanes instead of pretending it can read encrypted personal messages.

## Why this can win a hackathon

GhostFilter is not just a classifier demo. It is a full product loop:

- input from real user channels
- local ML + deterministic security checks
- AI reasoning only when useful
- threat-intelligence integrations
- file/image/PDF support
- readable guidance for non-technical users
- report/export/share workflow
- correction feedback loop
- polished landing page and dashboard UI

It aims to make scam detection understandable and actionable for the public, not only for security experts.
