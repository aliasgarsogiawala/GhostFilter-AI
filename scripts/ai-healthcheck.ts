import { loadEnvConfig } from "@next/env";

loadEnvConfig(process.cwd());

type Status = "working" | "degraded" | "missing" | "failed";
interface Check {
  component: string;
  status: Status;
  detail: string;
}

const checks: Check[] = [];

function record(component: string, status: Status, detail: string) {
  checks.push({ component, status, detail });
}

async function run() {
  const { evaluationSummary } = await import("../lib/evaluationCases");
  const { extractTextFromUpload } = await import("../lib/fileExtraction");
  const { getGeminiClientForKey, getGeminiKeys } = await import("../lib/geminiKeys");
  const { checkDomainReputation } = await import("../lib/virustotal");
  const { chatWithGhosti } = await import("../lib/ghosti");

  const evaluation = evaluationSummary();
  record(
    "Local ML + deterministic firewall",
    evaluation.passed === evaluation.total ? "working" : "failed",
    `${evaluation.passed}/${evaluation.total} curated regression cases passed`
  );

  const extracted = await extractTextFromUpload({
    filename: "healthcheck.txt",
    mimeType: "text/plain",
    base64: Buffer.from("Verify this local file extraction path.").toString("base64"),
  });
  record(
    "Local TXT/EML extraction",
    extracted.includes("local file extraction") ? "working" : "failed",
    "Runs locally without an external model"
  );

  const geminiKeys = getGeminiKeys();
  if (!geminiKeys.length) {
    record("Gemini structured review", "missing", "No Gemini key is configured");
  } else {
    for (const entry of geminiKeys) {
      try {
        const response = await getGeminiClientForKey(entry).models.generateContent({
          model: "gemini-2.5-flash-lite",
          contents: "Reply with exactly GHOSTFILTER_HEALTH_OK",
          config: { temperature: 0 },
        });
        const ok = response.text?.includes("GHOSTFILTER_HEALTH_OK") ?? false;
        record(
          `Gemini (${entry.name})`,
          ok ? "working" : "failed",
          ok ? "Authenticated generation succeeded" : "Unexpected model response"
        );
      } catch (error) {
        record(`Gemini (${entry.name})`, "failed", conciseError(error));
      }
    }
  }

  if (!process.env.VIRUSTOTAL_API_KEY) {
    record("VirusTotal", "missing", "VIRUSTOTAL_API_KEY is not configured");
  } else {
    const reputation = await checkDomainReputation("google.com");
    record(
      "VirusTotal",
      reputation ? "working" : "failed",
      reputation ? "Authenticated domain lookup succeeded" : "Lookup failed or key was rejected"
    );
  }

  if (!process.env.URLSCAN_API_KEY) {
    record("urlscan.io", "missing", "URLSCAN_API_KEY is not configured");
  } else {
    try {
      const response = await fetch("https://urlscan.io/user/quotas/", {
        headers: {
          "Content-Type": "application/json",
          "API-Key": process.env.URLSCAN_API_KEY,
        },
      });
      record(
        "urlscan.io",
        response.ok ? "working" : "failed",
        response.ok ? "Authenticated quota lookup succeeded" : `Quota endpoint returned HTTP ${response.status}`
      );
    } catch (error) {
      record("urlscan.io", "failed", conciseError(error));
    }
  }

  const ollamaBase = (process.env.OLLAMA_BASE_URL ?? "http://127.0.0.1:11434").replace(/\/$/, "");
  const ollamaModel = process.env.GHOSTI_OLLAMA_MODEL ?? "qwen2.5:3b-instruct";
  try {
    const response = await fetch(`${ollamaBase}/api/tags`, {
      signal: AbortSignal.timeout(3_000),
    });
    if (!response.ok) {
      record("Ghosti open model", "failed", `Ollama returned HTTP ${response.status}`);
    } else {
      const body = (await response.json()) as { models?: Array<{ name?: string }> };
      const available = body.models?.some(
        ({ name }) => name === ollamaModel || name?.startsWith(`${ollamaModel}:`)
      );
      if (!available) {
        record("Ghosti open model", "degraded", `Ollama is running but ${ollamaModel} is not installed`);
      } else {
        const result = await chatWithGhosti([
          { role: "user", content: "Someone asked me to send my OTP. Is that safe?" },
        ]);
        record(
          "Ghosti open model",
          result.provider === "ollama" ? "working" : "degraded",
          result.provider === "ollama"
            ? `Ollama generation succeeded with ${result.model}`
            : "Ollama was reachable but Ghosti used its deterministic fallback"
        );
      }
    }
  } catch {
    const fallback = await chatWithGhosti([
      { role: "user", content: "Someone asked me to send my OTP. Is that safe?" },
    ]);
    record(
      "Ghosti open model",
      fallback.provider === "fallback" ? "degraded" : "working",
      fallback.provider === "fallback"
        ? "Ollama is unavailable; deterministic safety fallback is working"
        : `Generation succeeded with ${fallback.model}`
    );
  }

  console.table(checks);

  const hardFailures = checks.filter(({ status }) => status === "failed");
  if (hardFailures.length) process.exitCode = 1;
}

function conciseError(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").slice(0, 180);
}

run().catch((error) => {
  console.error(`AI health check crashed: ${conciseError(error)}`);
  process.exitCode = 1;
});
