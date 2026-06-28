import { ConvexHttpClient } from "convex/browser";
import { api } from "@/convex/_generated/api";
import { rateLimit, rateLimitKey, retryAfterSeconds } from "@/lib/rateLimit";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const limit = await rateLimit(rateLimitKey(request, "account-register"), 5, 60 * 60 * 1000);
  if (!limit.ok) {
    return Response.json(
      { error: "Too many signup attempts. Try again later." },
      { status: 429, headers: { "Retry-After": String(retryAfterSeconds(limit.resetAt)) } }
    );
  }

  try {
    const contentLength = Number(request.headers.get("content-length") ?? 0);
    if (contentLength > 10_000) {
      return Response.json({ error: "Request body is too large." }, { status: 413 });
    }
    const body = (await request.json()) as { email?: unknown; name?: unknown; password?: unknown };
    if (
      typeof body.email !== "string" ||
      typeof body.name !== "string" ||
      typeof body.password !== "string"
    ) {
      return Response.json({ error: "Name, email, and password are required." }, { status: 400 });
    }
    const serviceSecret = process.env.AUTH_SERVICE_SECRET;
    if (!serviceSecret) throw new Error("Authentication service is not configured.");
    const convex = new ConvexHttpClient(process.env.NEXT_PUBLIC_CONVEX_URL!);
    await convex.action(api.auth.register, {
      serviceSecret,
      email: body.email,
      name: body.name,
      password: body.password,
    });
    return Response.json({ ok: true }, { status: 201 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Signup failed.";
    if (message.includes("already exists")) {
      return Response.json({ error: "An account with this email already exists." }, { status: 409 });
    }
    if (message.includes("valid email") || message.includes("Password") || message.includes("Enter your name")) {
      return Response.json({ error: message }, { status: 400 });
    }
    console.error("Account registration failed:", error);
    return Response.json({ error: "Signup failed. Try again." }, { status: 500 });
  }
}
