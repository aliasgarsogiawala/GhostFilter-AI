import { evaluationSummary } from "../lib/evaluationCases";

const summary = evaluationSummary();
console.log(JSON.stringify(summary, null, 2));

if (summary.passed !== summary.total) {
  process.exitCode = 1;
}
