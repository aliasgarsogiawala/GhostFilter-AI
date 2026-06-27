import { chatWithGhosti, type GhostiChatMessage } from "@/lib/ghosti";
import { rateLimit, rateLimitKey, retryAfterSeconds } from "@/lib/rateLimit";

export const runtime = "nodejs";

export async function POST(request: Request) {
  try {
    const limit = rateLimit(rateLimitKey(request, "ghosti-chat"), 20, 60_000);
    if (!limit.ok) {
      return Response.json(
        { error: "Too many Ghosti messages. Try again shortly." },
        {
          status: 429,
          headers: { "Retry-After": String(retryAfterSeconds(limit.resetAt)) },
        }
      );
    }

    const contentLength = Number(request.headers.get("content-length") ?? 0);
    if (contentLength > 40_000) {
      return Response.json({ error: "Request body is too large." }, { status: 413 });
    }
    const body = (await request.json()) as { messages?: unknown };
    const messages = Array.isArray(body.messages)
      ? body.messages
          .map((message): GhostiChatMessage | null => {
            if (!message || typeof message !== "object") return null;
            const candidate = message as { role?: unknown; content?: unknown };
            if (
              (candidate.role !== "user" && candidate.role !== "assistant") ||
              typeof candidate.content !== "string"
            ) {
              return null;
            }
            return { role: candidate.role, content: candidate.content };
          })
          .filter((message): message is GhostiChatMessage => message !== null)
      : [];

    if (!messages.length) {
      return Response.json(
        { error: "Send JSON with a non-empty `messages` array." },
        { status: 400 }
      );
    }

    return Response.json({
      ok: true,
      ghosti: await chatWithGhosti(messages),
    });
  } catch {
    return Response.json(
      { error: "Invalid JSON body. Expected: { \"messages\": [{ \"role\": \"user\", \"content\": \"...\" }] }" },
      { status: 400 }
    );
  }
}
