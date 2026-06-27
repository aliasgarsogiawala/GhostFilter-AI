# Ghosti Guard Browser Extension

This is a lightweight Chrome/Edge extension demo for hackathon judging.

It scans selected text or the visible page through the local GhostFilter API:

```text
Selected webpage / full page / DM / tool output
        ↓
POST /api/ghostgpt/firewall
        ↓
pass / isolate / block + Ghosti advice + safe GhostGPT context
```

## Run locally

1. Start GhostFilter:

   ```bash
   npm run dev
   ```

2. Open Chrome or Edge:
   - Go to `chrome://extensions`
   - Enable Developer Mode
   - Click **Load unpacked**
   - Select this `browser-extension` folder

3. Highlight suspicious text on a webpage, or open a page you want to scan.
4. Click the GhostFilter extension.
5. Click **Scan selected text** or **Scan whole page**.

## What the popup shows

- Verdict: pass / isolate / block
- Risk score
- Ghosti's plain-English advice
- Safe GhostGPT context wrapper
- Copy safe context button
- Open dashboard button

## Configure API URL

The popup defaults to:

```text
http://localhost:3000
```

Change the field in the popup when testing against a deployed app.
Chrome will ask for access only to that deployed API origin. If the deployment uses
`GHOSTFILTER_API_KEY`, enter the same value in the popup's firewall API key field.
Configuration is stored in local extension storage and is not synced between browsers.
