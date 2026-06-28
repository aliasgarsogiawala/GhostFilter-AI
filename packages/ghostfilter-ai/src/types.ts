/** The kind of protection to run. "full" runs both the scam and agent-firewall checks. */
export type ProtectMode = "scam" | "agent" | "full";

/** mode tag attached to a result. Includes "command" for checkCommand(), which isn't
 *  reachable through protect() but reuses the same result shape for consistent CLI output. */
export type ResultMode = ProtectMode | "command";

export type Verdict = "safe" | "suspicious" | "dangerous";

export interface ProtectOptions {
  input: string;
  mode?: ProtectMode;
}

export interface ProtectResult {
  verdict: Verdict;
  /** 0-100, higher means riskier. */
  score: number;
  mode: ResultMode;
  reasons: string[];
  categories: string[];
  /** Present when the input should be wrapped before being handed to an AI agent. */
  safeContext?: string;
  recommendedAction: string;
  /** Underlying engine output, kept for advanced consumers/debugging. */
  raw?: unknown;
}
