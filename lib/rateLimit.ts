interface Entry {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, Entry>();
const MAX_BUCKETS = 10_000;

function prune(now: number) {
  for (const [key, entry] of buckets) {
    if (entry.resetAt <= now) buckets.delete(key);
  }
  if (buckets.size >= MAX_BUCKETS) {
    const oldest = [...buckets.entries()]
      .sort(([, a], [, b]) => a.resetAt - b.resetAt)
      .slice(0, Math.ceil(MAX_BUCKETS / 10));
    for (const [key] of oldest) buckets.delete(key);
  }
}

function memoryRateLimit(key: string, limit: number, windowMs: number) {
  const now = Date.now();
  if (buckets.size >= MAX_BUCKETS) prune(now);
  const entry = buckets.get(key);
  if (!entry || entry.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return { ok: true, remaining: limit - 1, resetAt: now + windowMs };
  }
  if (entry.count >= limit) {
    return { ok: false, remaining: 0, resetAt: entry.resetAt };
  }
  entry.count += 1;
  return { ok: true, remaining: limit - entry.count, resetAt: entry.resetAt };
}

export async function rateLimit(key: string, limit: number, windowMs: number) {
  const url = process.env.UPSTASH_REDIS_REST_URL?.replace(/\/$/, "");
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return memoryRateLimit(key, limit, windowMs);

  const script =
    "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end; return {n,redis.call('PTTL',KEYS[1])}";
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(["EVAL", script, 1, key, windowMs]),
      cache: "no-store",
    });
    if (!response.ok) return memoryRateLimit(key, limit, windowMs);
    const payload = (await response.json()) as { result?: [number, number] };
    const count = Number(payload.result?.[0] ?? 1);
    const ttl = Math.max(1, Number(payload.result?.[1] ?? windowMs));
    return {
      ok: count <= limit,
      remaining: Math.max(0, limit - count),
      resetAt: Date.now() + ttl,
    };
  } catch {
    return memoryRateLimit(key, limit, windowMs);
  }
}

export function rateLimitKey(request: Request, scope: string) {
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const ip = forwarded || request.headers.get("x-real-ip") || "local";
  return `${scope}:${ip}`;
}

export function retryAfterSeconds(resetAt: number) {
  return Math.max(1, Math.ceil((resetAt - Date.now()) / 1000));
}
