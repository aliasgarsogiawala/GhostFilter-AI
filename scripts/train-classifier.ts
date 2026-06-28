// Offline training script for the lightweight scam/spam triage classifier.
// Run with: npm run train-classifier
//
// Trains a logistic regression (hand-rolled gradient descent, no ML deps) on a
// combined corpus so it generalizes beyond SMS:
//   - SMS Spam Collection (scripts/data/sms-spam.csv)          . Short text messages
//   - SpamAssassin public corpus (scripts/data/spamassassin/)  . Real emails, incl.
//     hard_ham = legitimate-but-promotional newsletters/marketing (the false-positive
//     class that an SMS-only model gets wrong).
// The SpamAssassin corpus is gitignored; re-download it with:
//   scripts/download-corpus.sh   (or from spamassassin.apache.org/old/publiccorpus/)
// Exports learned weights to lib/ml-weights.json for runtime inference (lib/ml-classifier.ts).

import { readFileSync, writeFileSync, readdirSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { extractFeatureVector, tokenize, HANDCRAFTED_KEYS } from "../lib/features";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SMS_PATH = join(__dirname, "data", "sms-spam.csv");
const SPAMASSASSIN_DIR = join(__dirname, "data", "spamassassin");
const OUTPUT_PATH = join(__dirname, "..", "lib", "ml-weights.json");

// SpamAssassin folders and their label (1 = spam/scam, 0 = legitimate).
const SA_FOLDERS: { dir: string; label: 0 | 1 }[] = [
  { dir: "easy_ham", label: 0 },
  { dir: "easy_ham_2", label: 0 },
  { dir: "hard_ham", label: 0 }, // legit but promotional. Teaches the model not to over-flag
  { dir: "spam", label: 1 },
  { dir: "spam_2", label: 1 },
];

const VOCAB_SIZE = 150;
const EPOCHS = 600;
const LEARNING_RATE = 0.3;
const L2 = 0.001;

interface Row {
  label: 0 | 1; // 1 = spam
  text: string;
  source: "sms" | "email";
}

function parseCsv(raw: string): Row[] {
  const rows: Row[] = [];
  const lines = raw.split(/\r?\n/);
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    // v1,v2,,, with v2 possibly quoted and containing commas
    const firstComma = line.indexOf(",");
    if (firstComma === -1) continue;
    const label = line.slice(0, firstComma).trim();
    const rest = line.slice(firstComma + 1);
    let text: string;
    if (rest.startsWith('"')) {
      // find the closing quote, accounting for "" escaped quotes
      let end = 1;
      let buf = "";
      while (end < rest.length) {
        if (rest[end] === '"') {
          if (rest[end + 1] === '"') {
            buf += '"';
            end += 2;
            continue;
          }
          break;
        }
        buf += rest[end];
        end++;
      }
      text = buf;
    } else {
      text = rest.split(",")[0];
    }
    if (label !== "ham" && label !== "spam") continue;
    rows.push({ label: label === "spam" ? 1 : 0, text, source: "sms" });
  }
  return rows;
}

/** Extracts the Subject + plain-text body from a raw RFC822 email file, mirroring how the
 *  live Gmail scanner builds "Subject: ...\n\n body" so train-time and runtime text match. */
function parseEmail(raw: string): string {
  const sepIdx = raw.search(/\r?\n\r?\n/);
  const headerBlock = sepIdx === -1 ? raw : raw.slice(0, sepIdx);
  let body = sepIdx === -1 ? "" : raw.slice(sepIdx).trim();

  const subjectMatch = headerBlock.match(/^subject:\s*(.*)$/im);
  const subject = subjectMatch ? subjectMatch[1].trim() : "";

  // Strip HTML tags if the body is HTML, collapse whitespace, and cap length so a single
  // huge email can't dominate the bag-of-words counts.
  if (/<html|<body|<div|<table|<a\s/i.test(body)) {
    body = body
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<[^>]+>/g, " ");
  }
  body = body.replace(/\s+/g, " ").trim().slice(0, 4000);
  return `Subject: ${subject}\n\n${body}`;
}

function loadEmails(): Row[] {
  if (!existsSync(SPAMASSASSIN_DIR)) {
    console.warn(
      `\n⚠ SpamAssassin corpus not found at ${SPAMASSASSIN_DIR}. Training on SMS only.\n` +
        `  Run scripts/download-corpus.sh to fetch it for a much better model.\n`
    );
    return [];
  }
  const rows: Row[] = [];
  for (const { dir, label } of SA_FOLDERS) {
    const full = join(SPAMASSASSIN_DIR, dir);
    if (!existsSync(full)) continue;
    for (const file of readdirSync(full)) {
      if (file.startsWith(".") || file === "cmds") continue;
      try {
        const raw = readFileSync(join(full, file), "latin1"); // emails are often non-UTF8
        const text = parseEmail(raw);
        if (text.replace(/^Subject:\s*/, "").trim().length > 5) {
          rows.push({ label, text, source: "email" });
        }
      } catch {
        // skip unreadable files
      }
    }
  }
  return rows;
}

function buildVocab(rows: Row[], size: number): string[] {
  const spamCounts = new Map<string, number>();
  const hamCounts = new Map<string, number>();
  let spamTotal = 0;
  let hamTotal = 0;

  for (const row of rows) {
    const words = new Set(tokenize(row.text));
    for (const w of words) {
      if (row.label === 1) {
        spamCounts.set(w, (spamCounts.get(w) ?? 0) + 1);
        spamTotal++;
      } else {
        hamCounts.set(w, (hamCounts.get(w) ?? 0) + 1);
        hamTotal++;
      }
    }
  }

  const scored: { word: string; score: number }[] = [];
  for (const [word, sc] of spamCounts) {
    if (sc < 4) continue; // ignore rare words
    const hc = hamCounts.get(word) ?? 0;
    const spamRate = sc / spamTotal;
    const hamRate = hc / Math.max(hamTotal, 1);
    const score = spamRate / (hamRate + 1e-4); // how spam-skewed this word is
    scored.push({ word, score });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, size).map((s) => s.word);
}

function standardize(X: number[][]): { Xs: number[][]; mean: number[]; std: number[] } {
  const n = X.length;
  const d = X[0].length;
  const mean = new Array(d).fill(0);
  const std = new Array(d).fill(0);
  for (const row of X) for (let j = 0; j < d; j++) mean[j] += row[j];
  for (let j = 0; j < d; j++) mean[j] /= n;
  for (const row of X)
    for (let j = 0; j < d; j++) std[j] += (row[j] - mean[j]) ** 2;
  for (let j = 0; j < d; j++) std[j] = Math.sqrt(std[j] / n) || 1;
  const Xs = X.map((row) => row.map((v, j) => (v - mean[j]) / std[j]));
  return { Xs, mean, std };
}

function sigmoid(z: number) {
  return 1 / (1 + Math.exp(-z));
}

function trainLogReg(X: number[][], y: number[], epochs: number, lr: number, l2: number) {
  const n = X.length;
  const d = X[0].length;
  const weights = new Array(d).fill(0);
  let bias = 0;

  // class weighting: spam is the minority class in this dataset
  const posCount = y.filter((v) => v === 1).length;
  const negCount = n - posCount;
  const posWeight = negCount / posCount;

  for (let epoch = 0; epoch < epochs; epoch++) {
    const gradW = new Array(d).fill(0);
    let gradB = 0;
    for (let i = 0; i < n; i++) {
      const z = X[i].reduce((acc, v, j) => acc + v * weights[j], bias);
      const pred = sigmoid(z);
      const sampleWeight = y[i] === 1 ? posWeight : 1;
      const err = (pred - y[i]) * sampleWeight;
      for (let j = 0; j < d; j++) gradW[j] += err * X[i][j];
      gradB += err;
    }
    for (let j = 0; j < d; j++) {
      weights[j] -= lr * (gradW[j] / n + l2 * weights[j]);
    }
    bias -= lr * (gradB / n);
  }

  return { weights, bias };
}

function evaluate(
  X: number[][],
  y: number[],
  weights: number[],
  bias: number,
  threshold = 0.5
) {
  let tp = 0,
    fp = 0,
    tn = 0,
    fn = 0;
  for (let i = 0; i < X.length; i++) {
    const z = X[i].reduce((acc, v, j) => acc + v * weights[j], bias);
    const pred = sigmoid(z) >= threshold ? 1 : 0;
    if (pred === 1 && y[i] === 1) tp++;
    else if (pred === 1 && y[i] === 0) fp++;
    else if (pred === 0 && y[i] === 0) tn++;
    else fn++;
  }
  const precision = tp / (tp + fp || 1);
  const recall = tp / (tp + fn || 1);
  const f1 = (2 * precision * recall) / (precision + recall || 1);
  const accuracy = (tp + tn) / X.length;
  return { tp, fp, tn, fn, precision, recall, f1, accuracy };
}

function shuffle<T>(arr: T[], seed = 42): T[] {
  const a = [...arr];
  let s = seed;
  const rand = () => {
    s = (s * 9301 + 49297) % 233280;
    return s / 233280;
  };
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function evaluateSubset(
  rows: Row[],
  predicate: (r: Row) => boolean,
  vocab: string[],
  mean: number[],
  std: number[],
  weights: number[],
  bias: number,
  label: string
) {
  const subset = rows.filter(predicate);
  if (!subset.length) return;
  const X = subset.map((r) => extractFeatureVector(r.text, vocab).map((v, j) => (v - mean[j]) / std[j]));
  const y = subset.map((r) => r.label);
  const m = evaluate(X, y, weights, bias);
  console.log(`  ${label} (n=${subset.length}):`, {
    accuracy: +m.accuracy.toFixed(4),
    precision: +m.precision.toFixed(4),
    recall: +m.recall.toFixed(4),
  });
}

function main() {
  const sms = parseCsv(readFileSync(SMS_PATH, "utf-8"));
  const emails = loadEmails();
  const rows = shuffle([...sms, ...emails]);
  const spamCount = rows.filter((r) => r.label === 1).length;
  console.log(
    `Loaded ${rows.length} labeled messages (${sms.length} SMS + ${emails.length} email); ` +
      `${spamCount} spam / ${rows.length - spamCount} legit`
  );

  const splitIdx = Math.floor(rows.length * 0.8);
  const trainRows = rows.slice(0, splitIdx);
  const testRows = rows.slice(splitIdx);

  const vocab = buildVocab(trainRows, VOCAB_SIZE);
  console.log(`Vocab (${vocab.length}):`, vocab.join(", "));

  const Xtrain = trainRows.map((r) => extractFeatureVector(r.text, vocab));
  const ytrain = trainRows.map((r) => r.label);
  const Xtest = testRows.map((r) => extractFeatureVector(r.text, vocab));
  const ytest = testRows.map((r) => r.label);

  const { Xs: XtrainStd, mean, std } = standardize(Xtrain);
  const XtestStd = Xtest.map((row) => row.map((v, j) => (v - mean[j]) / std[j]));

  const { weights, bias } = trainLogReg(XtrainStd, ytrain, EPOCHS, LEARNING_RATE, L2);

  const trainMetrics = evaluate(XtrainStd, ytrain, weights, bias);
  const testMetrics = evaluate(XtestStd, ytest, weights, bias);
  console.log("Train:", trainMetrics);
  console.log("Test:", testMetrics);

  // Per-slice test metrics. Especially the legitimate-email recall, which is what the
  // SMS-only model was failing (flagging newsletters as spam).
  console.log("Per-source test breakdown:");
  evaluateSubset(testRows, (r) => r.source === "sms", vocab, mean, std, weights, bias, "SMS");
  evaluateSubset(testRows, (r) => r.source === "email", vocab, mean, std, weights, bias, "Email");
  evaluateSubset(testRows, (r) => r.source === "email" && r.label === 0, vocab, mean, std, weights, bias, "Legit email (want high accuracy = few false positives)");

  const output = {
    vocab,
    handcraftedKeys: HANDCRAFTED_KEYS,
    mean,
    std,
    weights,
    bias,
    trainedAt: new Date().toISOString(),
    testMetrics,
  };
  writeFileSync(OUTPUT_PATH, JSON.stringify(output, null, 2));
  console.log(`Wrote weights to ${OUTPUT_PATH}`);
}

main();
