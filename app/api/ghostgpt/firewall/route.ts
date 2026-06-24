import { analyzeAgentFirewall } from "@/lib/agentFirewall";

export async function POST(request: Request) {
  try {
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
