import Link from "next/link";
import { CheckCircle2, XCircle } from "lucide-react";
import { evaluateAgentCases, evaluateScamCases, evaluationSummary } from "@/lib/evaluationCases";

export default function EvaluationPage() {
  const scam = evaluateScamCases();
  const agent = evaluateAgentCases();
  const summary = evaluationSummary();

  return (
    <main className="min-h-screen bg-[var(--ink)] px-5 py-8 text-zinc-300">
      <div className="mx-auto max-w-6xl">
        <nav className="mb-8 flex items-center justify-between">
          <Link href="/" className="text-sm font-semibold text-zinc-200">
            GhostFilter
          </Link>
          <div className="flex gap-2">
            <Link href="/demo" className="rounded-md border border-[var(--line)] px-3 py-2 text-xs text-zinc-400 hover:text-zinc-100">
              Judge demo
            </Link>
            <Link href="/dashboard" className="rounded-md bg-[var(--accent)] px-3 py-2 text-xs font-bold text-[var(--accent-ink)]">
              Scanner
            </Link>
          </div>
        </nav>

        <section className="mb-8">
          <p className="text-xs font-bold uppercase tracking-[0.18em] text-[var(--accent)]">Model evaluation</p>
          <h1 className="mt-3 max-w-3xl text-4xl font-semibold tracking-[-0.04em] text-zinc-100">
            Batch test runner for scam + GhostGPT detection
          </h1>
          <p className="mt-4 max-w-2xl text-sm leading-7 text-zinc-500">
            These cases act as the accuracy tuning dataset. When a false positive or false negative appears, add it here and tighten the ensemble.
          </p>
        </section>

        <section className="mb-6 grid gap-3 sm:grid-cols-4">
          {[
            ["Accuracy", `${summary.accuracy}%`],
            ["Passed", `${summary.passed}/${summary.total}`],
            ["Scam precision", `${summary.scamPrecision}%`],
            ["Scam recall", `${summary.scamRecall}%`],
          ].map(([label, value]) => (
            <div key={label} className="rounded-xl border border-[var(--line)] bg-[var(--panel)] p-4">
              <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-zinc-600">{label}</p>
              <p className="mt-2 font-mono text-3xl font-black text-[var(--accent-bright)]">{value}</p>
            </div>
          ))}
        </section>

        <EvalTable title="Scam Shield tests" rows={scam} />
        <EvalTable title="GhostGPT Firewall tests" rows={agent} />
      </div>
    </main>
  );
}

function EvalTable({
  title,
  rows,
}: {
  title: string;
  rows: Array<{
    id: string;
    text: string;
    expected: string;
    actual: string;
    pass: boolean;
    note: string;
    channel?: string;
    result: { ensembleScore?: number; score?: number };
  }>;
}) {
  return (
    <section className="mb-8 rounded-xl border border-[var(--line-strong)] bg-[var(--panel)]">
      <div className="border-b border-[var(--line)] px-4 py-3">
        <h2 className="text-sm font-semibold text-zinc-100">{title}</h2>
      </div>
      <div className="divide-y divide-[var(--line)]">
        {rows.map((row) => (
          <article key={row.id} className="grid gap-3 px-4 py-4 lg:grid-cols-[120px_1fr_120px_120px_80px] lg:items-start">
            <div>
              <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-600">{row.channel ?? "Agent"}</p>
              <p className="mt-1 text-xs text-zinc-400">{row.id}</p>
            </div>
            <div>
              <p className="text-sm leading-6 text-zinc-300">{row.text}</p>
              <p className="mt-1 text-xs text-zinc-600">{row.note}</p>
            </div>
            <Badge label="Expected" value={row.expected} />
            <Badge label="Actual" value={row.actual} />
            <div className="flex items-center gap-2">
              {row.pass ? (
                <CheckCircle2 className="h-5 w-5 text-[var(--accent)]" />
              ) : (
                <XCircle className="h-5 w-5 text-[var(--danger)]" />
              )}
              <span className={row.pass ? "text-xs font-bold text-[var(--accent)]" : "text-xs font-bold text-[var(--danger)]"}>
                {row.pass ? "PASS" : "FIX"}
              </span>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function Badge({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-[var(--line)] bg-[var(--input)] p-3">
      <p className="text-[9px] font-bold uppercase tracking-[0.14em] text-zinc-600">{label}</p>
      <p className="mt-1 text-sm font-semibold capitalize text-zinc-200">{value}</p>
    </div>
  );
}
