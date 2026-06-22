// Offline training script for the lightweight scam/spam triage classifier.
// Run with: npm run train-classifier
//
// Trains a logistic regression (hand-rolled gradient descent, no ML deps)
// on the public SMS Spam Collection dataset, combining handcrafted signal
// features with a small bag-of-words vocabulary, then exports the learned
// weights to lib/ml-weights.json for runtime inference (lib/ml-classifier.ts).

import { readFileSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { extractFeatureVector, tokenize, HANDCRAFTED_KEYS } from "../lib/features";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_PATH = join(__dirname, "data", "sms-spam.csv");
const OUTPUT_PATH = join(__dirname, "..", "lib", "ml-weights.json");

const VOCAB_SIZE = 40;
const EPOCHS = 600;
const LEARNING_RATE = 0.3;
const L2 = 0.001;

interface Row {
  label: 0 | 1; // 1 = spam
  text: string;
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
    rows.push({ label: label === "spam" ? 1 : 0, text });
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

function main() {
  const raw = readFileSync(DATA_PATH, "utf-8");
  const rows = shuffle(parseCsv(raw));
  console.log(`Loaded ${rows.length} labeled messages`);

  const splitIdx = Math.floor(rows.length * 0.8);
  const trainRows = rows.slice(0, splitIdx);
  const testRows = rows.slice(splitIdx);

  const vocab = buildVocab(trainRows, VOCAB_SIZE);
  console.log("Vocab:", vocab.join(", "));

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
