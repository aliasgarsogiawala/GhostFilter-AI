# GhostFilter Browser Extension Starter

This is a lightweight Chrome/Edge extension demo for hackathon judging.

It scans selected webpage text through the local GhostFilter API:

```text
Selected webpage / DM / tool output
        ↓
POST /api/ghostgpt/firewall
        ↓
pass / isolate / block + safe GhostGPT context
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

3. Highlight suspicious text on a webpage.
4. Click the GhostFilter extension.
5. Click **Scan selected text**.

## Configure API URL

The popup defaults to:

```text
http://localhost:3000
```

Change the field in the popup when testing against a deployed app.
