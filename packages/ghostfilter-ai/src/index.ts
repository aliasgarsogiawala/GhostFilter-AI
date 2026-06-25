import { checkScam } from "./scam.js";
import { checkAgentInjection, sanitizeForAgent } from "./agentFirewall.js";
import { checkCommand } from "./commandGuard.js";
import { protect } from "./localProtect.js";

export const ghostfilter = {
  protect,
  checkScam,
  checkAgentInjection,
  sanitizeForAgent,
  checkCommand,
};

export { protect, checkScam, checkAgentInjection, sanitizeForAgent, checkCommand };
export type { ProtectMode, ProtectOptions, ProtectResult, ResultMode, Verdict } from "./types.js";
