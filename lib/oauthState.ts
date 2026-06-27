import { createHmac, timingSafeEqual } from "node:crypto";

export type ConnectedProvider = "google" | "github" | "slack";

interface OAuthStatePayload {
  ownerId: string;
  provider: ConnectedProvider;
  exp: number;
}

function secret() {
  const value = process.env.OAUTH_STATE_SECRET ?? process.env.NEXTAUTH_SECRET ?? process.env.AUTH_SECRET;
  if (!value) throw new Error("Set NEXTAUTH_SECRET or OAUTH_STATE_SECRET for OAuth state signing.");
  return value;
}

function encode(value: string) {
  return Buffer.from(value).toString("base64url");
}

function sign(data: string) {
  return createHmac("sha256", secret()).update(data).digest("base64url");
}

export function createOAuthState(ownerId: string, provider: ConnectedProvider) {
  const payload: OAuthStatePayload = {
    ownerId,
    provider,
    exp: Date.now() + 10 * 60 * 1000,
  };
  const body = encode(JSON.stringify(payload));
  return `${body}.${sign(body)}`;
}

export function verifyOAuthState(state: string | null, provider: ConnectedProvider): OAuthStatePayload | null {
  if (!state) return null;
  const [body, signature] = state.split(".");
  if (!body || !signature) return null;
  const expected = sign(body);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;

  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf-8")) as OAuthStatePayload;
    if (payload.provider !== provider || payload.exp < Date.now() || !payload.ownerId) return null;
    return payload;
  } catch {
    return null;
  }
}
