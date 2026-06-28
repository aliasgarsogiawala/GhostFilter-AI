import { loadEnvConfig } from "@next/env";

loadEnvConfig(process.cwd());

const required = [
  "NEXT_PUBLIC_CONVEX_URL",
  "CONVEX_DEPLOYMENT",
  "NEXT_PUBLIC_APP_URL",
  "NEXTAUTH_SECRET",
  "NEXTAUTH_URL",
  "AUTH_SERVICE_SECRET",
] as const;

const recommended = [
  "OWNER_TOKEN_SECRET",
  "OAUTH_STATE_SECRET",
  "OAUTH_TOKEN_ENCRYPTION_KEY",
] as const;

const missing = required.filter((name) => !process.env[name]?.trim());
const weak = ["NEXTAUTH_SECRET", "AUTH_SERVICE_SECRET"].filter(
  (name) => process.env[name] && process.env[name]!.length < 24
);
const localUrls = ["NEXT_PUBLIC_APP_URL", "NEXTAUTH_URL"].filter((name) =>
  /localhost|127\.0\.0\.1/i.test(process.env[name] ?? "")
);
const developmentConvex = /^(dev:|[a-z-]+$)/i.test(process.env.CONVEX_DEPLOYMENT ?? "");

for (const name of missing) console.error(`MISSING ${name}`);
for (const name of weak) console.error(`WEAK ${name}: use at least 24 characters`);
for (const name of localUrls) console.error(`LOCAL ${name}: set the public HTTPS deployment URL`);
if (developmentConvex) console.error("DEVELOPMENT CONVEX_DEPLOYMENT: use a production Convex deployment");
for (const name of recommended) {
  if (!process.env[name]?.trim()) console.warn(`FALLBACK ${name}: NEXTAUTH_SECRET will be used`);
}
if (!process.env.GHOSTFILTER_API_KEY?.trim()) {
  console.warn("OPEN GHOSTFILTER_API_KEY: firewall API will rely on rate limiting only");
}
if (!process.env.UPSTASH_REDIS_REST_URL?.trim() || !process.env.UPSTASH_REDIS_REST_TOKEN?.trim()) {
  console.warn("LOCAL RATE LIMIT: configure Upstash REST credentials for multi-instance enforcement");
}
if (!process.env.GOOGLE_CLIENT_ID?.trim() && !process.env.GITHUB_CLIENT_ID?.trim()) {
  console.warn("ACCESS-CODE AUTH ONLY: configure Google or GitHub for verified user identity");
}
if (/localhost|127\.0\.0\.1/i.test(process.env.OLLAMA_BASE_URL ?? "")) {
  console.warn("LOCAL OLLAMA: production Ghosti will use deterministic fallback unless Ollama is hosted");
}

if (missing.length || weak.length || localUrls.length || developmentConvex) {
  console.error("\nProduction environment check failed.");
  process.exitCode = 1;
} else {
  console.log("Production environment check passed.");
}
