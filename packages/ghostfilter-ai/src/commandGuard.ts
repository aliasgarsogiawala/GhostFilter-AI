// Terminal command risk checker. It operates only on the exact string you
// pass in (a CLI arg or piped line). It never reads shell history, dotfiles, or the
// filesystem on its own; protection is explicit and opt-in by design.
import type { ProtectResult } from "./types.js";

type Severity = "critical" | "high" | "medium";

const COMMAND_RULES: Array<{ label: string; detail: string; severity: Severity; pattern: RegExp }> = [
  {
    label: "Root or home wipe",
    detail: "Recursively force-deletes the root filesystem or home directory.",
    severity: "critical",
    pattern: /\brm\s+(?:-\w*[rf]\w*\s+)+(?:\/|~)(?:[\s/*]|$)/i,
  },
  {
    label: "Fork bomb",
    detail: "Classic fork bomb that spawns processes until the system runs out of resources.",
    severity: "critical",
    pattern: /:\(\)\s*\{\s*:\s*\|\s*:&?\s*\}\s*;\s*:/,
  },
  {
    label: "Raw disk overwrite",
    detail: "Writes directly to a disk device, which can destroy partitions or data irrecoverably.",
    severity: "critical",
    pattern: /\bdd\s+if=.*\bof=\/dev\/(sd|nvme|disk|hd)|\bmkfs(?:\.\w+)?\s+\/dev\/|>\s*\/dev\/(sd|nvme|disk|hd)/i,
  },
  {
    label: "Remote script piped to a shell",
    detail: "Downloads a script and executes it immediately without letting you review it first.",
    severity: "critical",
    pattern: /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node)\b/i,
  },
  {
    label: "Recursive permission change on root",
    detail: "Recursively changes permissions or ownership starting at the filesystem root.",
    severity: "critical",
    pattern: /\bchmod\s+-R\s+777\s+\/(?:\s|$)|\bchown\s+-R\b.*\s+\/(?:\s|$)/i,
  },
  {
    label: "Credential exfiltration",
    detail: "Reads a secrets/key file and pipes it to a network tool.",
    severity: "critical",
    pattern: /\b(cat|printenv|env)\b[^\n|]*\b(\.env|id_rsa|\.pem|secrets?)\b[^\n]*\|\s*(curl|nc|ncat|wget)\b/i,
  },
  {
    label: "Unset or unquoted variable in a destructive delete",
    detail: "If this variable is empty or unset, the command can expand to delete far more than intended.",
    severity: "high",
    pattern: /\brm\s+(?:-\w*[rf]\w*\s+)+["']?\$\{?\w+\}?["']?\/?\*?(?:\s|$)/i,
  },
  {
    label: "Wildcard delete in current directory",
    detail: "Recursively force-deletes everything in the current directory.",
    severity: "high",
    pattern: /\brm\s+(?:-\w*[rf]\w*\s+)+(?:\*|\.\/\*)(?:\s|$)/i,
  },
  {
    label: "Force-push to a shared branch",
    detail: "Force-pushing main/master can permanently overwrite history for everyone else.",
    severity: "high",
    pattern: /\bgit\s+push\s+(?:-f|--force)\b.*\b(?:main|master)\b/i,
  },
  {
    label: "Destructive git history rewrite",
    detail: "Discards local changes or untracked files with no way to recover them.",
    severity: "high",
    pattern: /\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-z]*f[a-z]*d/i,
  },
  {
    label: "Destructive database statement",
    detail: "Drops or truncates data with no visible backup or WHERE clause.",
    severity: "high",
    pattern: /\b(drop\s+(?:database|table)|truncate\s+table)\b|\bdelete\s+from\s+\w+\s*;/i,
  },
  {
    label: "Cloud infrastructure teardown",
    detail: "Tears down cloud infrastructure or storage, which is usually difficult to undo.",
    severity: "high",
    pattern: /\bterraform\s+destroy\b|\baws\s+s3\s+rm\b.*--recursive|\bkubectl\s+delete\s+(?:namespace|pv|pvc)\b/i,
  },
  {
    label: "Kill a critical process",
    detail: "Force-killing init (PID 1) or broadly matched processes can crash the system.",
    severity: "high",
    pattern: /\bkill\s+-9\s+1\b|\bpkill\s+-9\s+-f\s+\.\*/i,
  },
  {
    label: "Elevated remote download",
    detail: "Runs a network download with elevated (sudo) privileges.",
    severity: "medium",
    pattern: /\bsudo\b.*\b(curl|wget)\b/i,
  },
  {
    label: "Package publish",
    detail: "Publishes a package publicly. Double-check the version and contents first.",
    severity: "medium",
    pattern: /\bnpm\s+publish\b/i,
  },
  {
    label: "World-writable permissions",
    detail: "Grants read/write/execute to everyone, which is rarely intended.",
    severity: "medium",
    pattern: /\bchmod\s+777\b/i,
  },
  {
    label: "Force push",
    detail: "Force-pushing can overwrite remote history; confirm the target branch.",
    severity: "medium",
    pattern: /\bgit\s+push\s+(?:-f|--force)\b/i,
  },
];

const SEVERITY_SCORE: Record<Severity, number> = { critical: 95, high: 65, medium: 35 };

/** Local, deterministic terminal-command risk check. Only inspects the string you pass in. */
export function checkCommand(input: string): ProtectResult {
  const command = input.trim();
  const matches: { label: string; detail: string; severity: Severity; evidence: string }[] = [];

  for (const rule of COMMAND_RULES) {
    const match = command.match(rule.pattern);
    if (match) {
      matches.push({ label: rule.label, detail: rule.detail, severity: rule.severity, evidence: match[0].trim() });
      // A force-push/rm-rf match at a higher severity already covers the lower-severity
      // generic version of the same rule family, so stop at the first (highest-priority) hit.
      if (rule.severity === "critical") break;
    }
  }

  const score = Math.min(100, matches.reduce((sum, m) => sum + SEVERITY_SCORE[m.severity] * 0.6, 0));
  const hasCritical = matches.some((m) => m.severity === "critical");
  const hasHigh = matches.some((m) => m.severity === "high");

  const verdict: ProtectResult["verdict"] = hasCritical || score >= 70 ? "dangerous" : hasHigh || matches.length ? "suspicious" : "safe";

  const recommendedAction =
    verdict === "dangerous"
      ? "Do not run this command. Review it manually and confirm the exact target before proceeding."
      : verdict === "suspicious"
        ? "Review what this command targets before running it. Confirm the path, branch, or variable is what you expect."
        : "No high-risk command patterns were found.";

  return {
    verdict,
    score: Math.round(score),
    mode: "command",
    reasons: matches.length ? matches.map((m) => `${m.label}: ${m.detail} (matched "${m.evidence}")`) : ["No risky command patterns were found."],
    categories: matches.map((m) => m.label.toLowerCase().replace(/[^a-z0-9]+/g, "-")),
    recommendedAction,
    raw: { command, matches },
  };
}
