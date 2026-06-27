import { loadEnvConfig } from "@next/env";

loadEnvConfig(process.cwd());

const required = [
  "NEXT_PUBLIC_CONVEX_URL",
  "CONVEX_DEPLOYMENT",
  "NEXT_PUBLIC_APP_URL",
  "NEXTAUTH_SECRET",
  "NEXTAUTH_URL",
  "DEMO_AUTH_PASSWORD",
] as const;

const recommended = [
  "OWNER_TOKEN_SECRET",
  "OAUTH_STATE_SECRET",
  "OAUTH_TOKEN_ENCRYPTION_KEY",
] as const;

const missing = required.filter((name) => !process.env[name]?.trim());
const weak = ["NEXTAUTH_SECRET", "DEMO_AUTH_PASSWORD"].filter(
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

if (missing.length || weak.length || localUrls.length || developmentConvex) {
  console.error("\nProduction environment check failed.");
  process.exitCode = 1;
} else {
  console.log("Production environment check passed.");
}
