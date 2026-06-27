// urlscan.io submission + retrieval. Scans are submitted as "unlisted" (not
// published to urlscan's public search) since the URLs we scan come from a
// user's private messages. The screenshot is rendered safely on urlscan's
// own sandboxed infrastructure, never in our process.

const URLSCAN_BASE = "https://urlscan.io";

function getApiKey(): string {
  const key = process.env.URLSCAN_API_KEY;
  if (!key) throw new Error("URLSCAN_API_KEY is not set");
  return key;
}

export interface UrlscanResult {
  url: string;
  uuid: string;
  resultUrl: string;
  screenshotUrl: string;
  ready: boolean;
}

/** Submits a URL for sandboxed scanning and polls briefly for the screenshot to be ready. */
export async function scanAndCapture(url: string, maxWaitMs = 20000): Promise<UrlscanResult | null> {
  let uuid: string;
  try {
    const submitRes = await fetch(`${URLSCAN_BASE}/api/v1/scan/`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "API-Key": getApiKey() },
      body: JSON.stringify({ url, visibility: "unlisted" }),
    });
    if (!submitRes.ok) return null;
    const submitJson = await submitRes.json();
    if (!submitJson.uuid) return null;
    uuid = submitJson.uuid;
  } catch {
    return null;
  }

  const resultUrl = `${URLSCAN_BASE}/result/${uuid}/`;
  const screenshotUrl = `${URLSCAN_BASE}/screenshots/${uuid}.png`;
  const apiResultUrl = `${URLSCAN_BASE}/api/v1/result/${uuid}/`;

  // urlscan recommends waiting ~10s before the first poll.
  await new Promise((r) => setTimeout(r, 9000));
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    try {
      const check = await fetch(apiResultUrl, {
        headers: { "API-Key": getApiKey() },
      });
      if (check.ok) return { url, uuid, resultUrl, screenshotUrl, ready: true };
    } catch {
      // keep polling until the time budget runs out
    }
    await new Promise((r) => setTimeout(r, 4000));
  }
  // Still processing — return the links anyway, the screenshot will resolve shortly after.
  return { url, uuid, resultUrl, screenshotUrl, ready: false };
}
