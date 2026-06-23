# GhostFilter AI

A scam and phishing message analyzer. Paste a suspicious text, email, or DM
and get a real verdict — or connect a Gmail account and scan the inbox
directly. Built for the **Youth Code x AI** hackathon.

Two layers do the actual work:

1. **A hand-trained classifier** (`lib/ml-classifier.ts`) triages every
   message instantly and for free — logistic regression trained from
   scratch (no ML libraries) on the public SMS Spam Collection dataset,
   ~98% test accuracy. See `scripts/train-classifier.ts`.
2. **Gemini** (`lib/gemini.ts`) only gets called when the classifier or a
   deterministic heuristic (lookalike-domain detection, SSRF-guarded
   shortened-link expansion — `lib/heuristics.ts`) flags something, where it
   returns a structured verdict, confidence, flagged phrases, and a
   recommendation.

Everything is tied together in `convex/pipeline.ts` and used by both the
no-login paste-box analyzer and the Gmail scanner (`convex/gmail.ts`).
Convex (`convex/`) stores scan results and OAuth connections and pushes
updates to the dashboard live — no page refresh.

## Setup

```bash
npm install
```

### Environment variables (`.env.local`)

| Variable | Where to get it |
|---|---|
| `CONVEX_DEPLOYMENT`, `NEXT_PUBLIC_CONVEX_URL`, `NEXT_PUBLIC_CONVEX_SITE_URL` | Auto-created the first time you run `npx convex dev` — no login required, it provisions a local backend. |
| `GEMINI_API_KEY` | [Google AI Studio](https://aistudio.google.com/apikey). Also mirror it into Convex: `npx convex env set GEMINI_API_KEY <key>` (Convex actions run in their own process and don't read `.env.local`). |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Needed for the Gmail "Connect" flow. Create an OAuth client in [Google Cloud Console](https://console.cloud.google.com): enable the Gmail API, configure the OAuth consent screen (scopes `gmail.readonly`, `openid`, `email`; keep it in **Testing** mode and add your test Gmail accounts), then create a Web application OAuth client with redirect URI `http://localhost:3000/api/auth/google/callback`. Set these in both `.env.local` (for the Next.js route handlers) and Convex (`npx convex env set GOOGLE_CLIENT_ID <id>` / `GOOGLE_CLIENT_SECRET <secret>`, for token refresh in `convex/gmail.ts`). |
| `NEXT_PUBLIC_APP_URL` | Optional, defaults to `http://localhost:3000`. Set this to your deployed URL in production and update the OAuth redirect URI to match. |

### Run

```bash
npx convex dev   # keep running in its own terminal — watches convex/ and pushes changes
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) for the public landing page,
then enter the scanner at [http://localhost:3000/dashboard](http://localhost:3000/dashboard).

### Retrain the classifier

```bash
scripts/download-corpus.sh   # fetches the SpamAssassin email corpus (gitignored, ~42MB)
npm run train-classifier     # regenerates lib/ml-weights.json
```

The classifier trains on a combined corpus so it generalizes beyond SMS:
- `scripts/data/sms-spam.csv` — the SMS Spam Collection (short text messages).
- `scripts/data/spamassassin/` — the SpamAssassin public corpus of real emails, including
  `hard_ham` (legitimate-but-promotional newsletters/marketing). That class is what teaches
  the model not to flag legitimate newsletters (e.g. daily.dev) as spam.

Only the trained weights (`lib/ml-weights.json`) are committed; the raw corpus is gitignored
and re-downloadable via `scripts/download-corpus.sh`.

## Project structure

- `app/page.tsx` and `app/LandingPage.tsx` — the public landing page and branded splash experience.
- `app/dashboard/page.tsx` — the scanner workspace (connected accounts, paste-box analyzer, reactive scan history, verdict/signal breakdown).
- `app/api/auth/google/` — Gmail OAuth connect + callback routes.
- `convex/` — schema, the shared analysis pipeline, the Gmail scan action, and the connections/scanResults tables.
- `lib/` — heuristics, the ML classifier, the Gemini wrapper, and shared helpers used by both the manual analyzer and the Gmail scanner.
- `scripts/train-classifier.ts` — offline training script (no ML dependencies).

## Privacy

Gmail access is read-only (`gmail.readonly`) and only used to scan for
scams — GhostFilter never sends, deletes, or modifies anything in a
connected account. OAuth tokens are stored server-side in Convex and are
never sent to the browser. Disconnecting clears the stored tokens.
