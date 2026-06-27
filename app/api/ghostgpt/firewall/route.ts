import { analyzeAgentFirewall } from "@/lib/agentFirewall";
import { rateLimit, rateLimitKey, retryAfterSeconds } from "@/lib/rateLimit";

export async function POST(request: Request) {
  try {
    const apiKey = process.env.GHOSTFILTER_API_KEY;
    if (apiKey && request.headers.get("authorization") !== `Bearer ${apiKey}`) {
      return Response.json(
        { error: "Unauthorized firewall request." },
        { status: 401 }
      );
    }

    const limit = rateLimit(rateLimitKey(request, "ghostgpt-firewall"), 30, 60_000);
    if (!limit.ok) {
      return Response.json(
        { error: "Too many firewall checks. Try again shortly." },
        {
          status: 429,
          headers: { "Retry-After": String(retryAfterSeconds(limit.resetAt)) },
        }
      );
    }

    const contentLength = Number(request.headers.get("content-length") ?? 0);
    if (contentLength > 25_000) {
      return Response.json({ error: "Request body is too large." }, { status: 413 });
    }
    const body = (await request.json()) as { content?: unknown };
    const content = typeof body.content === "string" ? body.content : "";

    if (!content.trim()) {
      return Response.json(
        { error: "Send JSON with a non-empty `content` string." },
        { status: 400 }
      );
    }

    return Response.json({
      ok: true,
      firewall: analyzeAgentFirewall(content.slice(0, 20_000)),
    });
  } catch {
    return Response.json(
      { error: "Invalid JSON body. Expected: { \"content\": \"...\" }" },
      { status: 400 }
    );
  }
}
