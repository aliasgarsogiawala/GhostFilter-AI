const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 14;

function tokenSecret() {
  const secret = process.env.OWNER_TOKEN_SECRET ?? process.env.NEXTAUTH_SECRET ?? process.env.AUTH_SECRET;
  if (!secret) throw new Error("Set NEXTAUTH_SECRET or OWNER_TOKEN_SECRET for owner token signing.");
  return secret;
}

function hex(buffer: ArrayBuffer) {
  return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmac(data: string) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(tokenSecret()),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return hex(await crypto.subtle.sign("HMAC", key, encoder.encode(data)));
}

export async function createOwnerToken(ownerId: string) {
  const exp = Date.now() + TOKEN_TTL_MS;
  const body = `${ownerId}.${exp}`;
  return `${body}.${await hmac(body)}`;
}

export async function verifyOwnerToken(ownerId: string, token: string) {
  const [tokenOwnerId, exp, sig] = token.split(".");
  if (!tokenOwnerId || !exp || !sig || tokenOwnerId !== ownerId) return false;
  if (Number(exp) < Date.now()) return false;
  const body = `${tokenOwnerId}.${exp}`;
  return (await hmac(body)) === sig;
}

export async function assertOwnerToken(ownerId: string, ownerToken: string) {
  if (!(await verifyOwnerToken(ownerId, ownerToken))) {
    throw new Error("Unauthorized owner token.");
  }
}
