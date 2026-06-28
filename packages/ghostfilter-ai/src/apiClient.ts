// Optional remote mode. If GHOSTFILTER_API_URL is set, agent-firewall checks call the
// deployed GhostFilter app's /api/ghostgpt/firewall endpoint instead of running locally.
// Any failure (no env var, network error, timeout, bad response) returns null and the
// caller silently falls back to the local heuristics in agentFirewall.ts, so the package
// always works without an API key.
export interface ApiConfig {
  baseUrl: string;
  apiKey?: string;
}

export function getApiConfig(): ApiConfig | null {
  const baseUrl = process.env.GHOSTFILTER_API_URL?.trim();
  if (!baseUrl) return null;
  return { baseUrl: baseUrl.replace(/\/$/, ""), apiKey: process.env.GHOSTFILTER_API_KEY?.trim() };
}

interface RemoteFirewallResponse {
  verdict: "pass" | "isolate" | "block";
  score: number;
  summary: string;
  recommendation: string;
  findings: { label: string; detail: string }[];
  sanitizedContext: string;
}

/** Calls the main app's agent-firewall endpoint. Returns null on failure so the
 * caller can fall back to the local checker. */
export async function callAgentFirewallApi(content: string): Promise<RemoteFirewallResponse | null> {
  const config = getApiConfig();
  if (!config) return null;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(`${config.baseUrl}/api/ghostgpt/firewall`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {}),
      },
      body: JSON.stringify({ content }),
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { ok?: boolean; firewall?: RemoteFirewallResponse };
    return data.ok && data.firewall ? data.firewall : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}
