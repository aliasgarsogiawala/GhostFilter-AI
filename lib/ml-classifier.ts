import weightsData from "./ml-weights.json";
import { extractFeatureVector } from "./features";

interface Weights {
  vocab: string[];
  mean: number[];
  std: number[];
  weights: number[];
  bias: number;
}

const { vocab, mean, std, weights, bias } = weightsData as Weights;

function sigmoid(z: number) {
  return 1 / (1 + Math.exp(-z));
}

/** Returns a spam/scam-likelihood probability in [0, 1]. Cheap, deterministic, no network call. */
export function scoreMessage(text: string): number {
  const raw = extractFeatureVector(text, vocab);
  const standardized = raw.map((v, j) => (v - mean[j]) / (std[j] || 1));
  const z = standardized.reduce((acc, v, j) => acc + v * weights[j], bias);
  return sigmoid(z);
}

/** Above this score, the message gets escalated to a Gemini deep-review. Tuned against the
 *  combined SMS+email model: legit newsletters score ~0.15-0.20, so 0.30 leaves margin to
 *  keep them un-escalated (instant "safe", no Gemini call) while still catching borderline
 *  phishing. Messages with a hard heuristic hit (lookalike domain, flagged link, injection)
 *  escalate regardless of this score. */
export const ML_REVIEW_THRESHOLD = 0.3;
