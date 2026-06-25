// Orchestrates protect(): picks local vs. API for the agent-firewall check, always runs
// the scam check locally (no public REST scam endpoint exists yet — see README), and
// merges both into one result for mode "full".
import { checkScam } from "./scam.js";
import { checkAgentInjection } from "./agentFirewall.js";
import { callAgentFirewallApi } from "./apiClient.js";
import type { ProtectMode, ProtectOptions, ProtectResult, Verdict } from "./types.js";

const VERDICT_RANK: Record<Verdict, number> = { safe: 0, suspicious: 1, dangerous: 2 };

function slug(label: string) {
  return label.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

function mapRemoteFirewall(remote: NonNullable<Awaited<ReturnType<typeof callAgentFirewallApi>>>): ProtectResult {
  const verdict: Verdict = remote.verdict === "block" ? "dangerous" : remote.verdict === "isolate" ? "suspicious" : "safe";
  return {
    verdict,
    score: remote.score,
    mode: "agent",
    reasons: remote.findings.length ? remote.findings.map((f) => `${f.label}: ${f.detail}`) : [remote.summary],
    categories: remote.findings.map((f) => slug(f.label)),
    safeContext: remote.sanitizedContext,
    recommendedAction: remote.recommendation,
    raw: remote,
  };
}

async function runAgentCheck(input: string): Promise<ProtectResult> {
  const remote = await callAgentFirewallApi(input);
  return remote ? mapRemoteFirewall(remote) : checkAgentInjection(input);
}

function mergeResults(scam: ProtectResult, agent: ProtectResult): ProtectResult {
  const verdict = VERDICT_RANK[scam.verdict] >= VERDICT_RANK[agent.verdict] ? scam.verdict : agent.verdict;
  return {
    verdict,
    score: Math.max(scam.score, agent.score),
    mode: "full",
    reasons: [...new Set([...scam.reasons, ...agent.reasons])],
    categories: [...new Set([...scam.categories, ...agent.categories])],
    safeContext: agent.safeContext,
    recommendedAction: verdict === scam.verdict && scam.verdict !== "safe" ? scam.recommendedAction : agent.recommendedAction,
    raw: { scam: scam.raw, agent: agent.raw },
  };
}

export async function protect({ input, mode = "full" }: ProtectOptions): Promise<ProtectResult> {
  if (!input || !input.trim()) {
    return {
      verdict: "safe",
      score: 0,
      mode: mode as ProtectMode,
      reasons: ["Empty input — nothing to check."],
      categories: [],
      recommendedAction: "Provide text to check.",
    };
  }

  if (mode === "scam") return checkScam(input);
  if (mode === "agent") return runAgentCheck(input);

  const [scam, agent] = await Promise.all([Promise.resolve(checkScam(input)), runAgentCheck(input)]);
  return mergeResults(scam, agent);
}
