import fs from 'node:fs';
import path from 'node:path';
import { extractRegistrableDomain, validateAndNormalizeUrl } from '../services/urlValidator';
import {
  extractMlFeatures,
  STRUCTURAL_FEATURE_NAMES,
  type ExtractedUrlFeatures,
} from './features';
import type { EvaluationMetrics, ModelEvaluationReport } from '../../shared/types';

export interface TrainedUrlModelArtifact {
  modelVersion: string;
  algorithm: string;
  trainedAt: string;
  structuralFeatureNames: string[];
  scalerMean: number[];
  scalerStd: number[];
  structuralWeights: number[];
  vocabulary: string[];
  idf: number[];
  ngramWeights: number[];
  bias: number;
  evaluation: ModelEvaluationReport;
}

interface DatasetRow {
  url: string;
  normalizedUrl: string;
  registrableDomain: string;
  label: 0 | 1;
  features: ExtractedUrlFeatures;
}

function deterministicHash(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function sigmoid(z: number): number {
  if (z >= 35) return 1;
  if (z <= -35) return 0;
  return 1 / (1 + Math.exp(-z));
}

export function computeMetrics(yTrue: number[], yPredProb: number[], threshold = 0.5): EvaluationMetrics {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  for (let i = 0; i < yTrue.length; i++) {
    const actual = yTrue[i];
    const predicted = yPredProb[i] >= threshold ? 1 : 0;
    if (actual === 1 && predicted === 1) tp++;
    else if (actual === 0 && predicted === 1) fp++;
    else if (actual === 0 && predicted === 0) tn++;
    else fn++;
  }

  const total = Math.max(1, yTrue.length);
  const accuracy = Number(((tp + tn) / total).toFixed(4));
  const precision = tp + fp === 0 ? 0 : Number((tp / (tp + fp)).toFixed(4));
  const recall = tp + fn === 0 ? 0 : Number((tp / (tp + fn)).toFixed(4));
  const f1Score =
    precision + recall === 0
      ? 0
      : Number(((2 * precision * recall) / (precision + recall)).toFixed(4));
  const falsePositiveRate = fp + tn === 0 ? 0 : Number((fp / (fp + tn)).toFixed(4));
  const falseNegativeRate = fn + tp === 0 ? 0 : Number((fn / (fn + tp)).toFixed(4));

  return {
    accuracy,
    precision,
    recall,
    f1Score,
    falsePositiveRate,
    falseNegativeRate,
    confusionMatrix: { tp, fp, tn, fn },
    sampleCount: yTrue.length,
  };
}

export function loadAndDeduplicateDataset(csvPath: string): {
  totalRawRows: number;
  rows: DatasetRow[];
} {
  const raw = fs.readFileSync(csvPath, 'utf8');
  const lines = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length <= 1) {
    throw new Error(`Dataset at ${csvPath} is empty or missing rows.`);
  }

  const seenUrls = new Set<string>();
  const rows: DatasetRow[] = [];
  let totalRawRows = 0;

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const lastComma = line.lastIndexOf(',');
    if (lastComma === -1) continue;
    const rawUrl = line.slice(0, lastComma).trim();
    const rawLabel = line.slice(lastComma + 1).trim();
    if (rawLabel !== '0' && rawLabel !== '1') continue;
    totalRawRows++;

    const validated = validateAndNormalizeUrl(rawUrl);
    if (!validated.valid) continue;
    if (seenUrls.has(validated.normalizedUrl)) continue;
    seenUrls.add(validated.normalizedUrl);

    const features = extractMlFeatures(validated.normalizedUrl);
    if (!features) continue;

    rows.push({
      url: rawUrl,
      normalizedUrl: validated.normalizedUrl,
      registrableDomain: extractRegistrableDomain(validated.domain),
      label: rawLabel === '1' ? 1 : 0,
      features,
    });
  }

  return { totalRawRows, rows };
}

/**
 * Domain-grouped stratified split prevents the same registrable domain from
 * leaking across training, validation, and test sets.
 */
function splitByDomainGroup(rows: DatasetRow[]): {
  train: DatasetRow[];
  val: DatasetRow[];
  test: DatasetRow[];
  uniqueDomains: number;
} {
  const domainGroups = new Map<string, DatasetRow[]>();
  for (const row of rows) {
    const key = `${row.label}:${row.registrableDomain}`;
    const existing = domainGroups.get(key);
    if (existing) existing.push(row);
    else domainGroups.set(key, [row]);
  }

  const groups = Array.from(domainGroups.entries()).sort((a, b) =>
    deterministicHash(a[0]) - deterministicHash(b[0]),
  );

  const train: DatasetRow[] = [];
  const val: DatasetRow[] = [];
  const test: DatasetRow[] = [];

  let posIdx = 0;
  let negIdx = 0;
  for (const [, groupRows] of groups) {
    const label = groupRows[0].label;
    const idx = label === 1 ? posIdx++ : negIdx++;
    const bucket = idx % 20; // 14 train (70%), 3 val (15%), 3 test (15%)
    if (bucket < 14) train.push(...groupRows);
    else if (bucket < 17) val.push(...groupRows);
    else test.push(...groupRows);
  }

  return { train, val, test, uniqueDomains: domainGroups.size };
}

export function trainUrlClassifier(
  datasetCsvPath: string,
  outputModelPath: string,
): TrainedUrlModelArtifact {
  const { totalRawRows, rows } = loadAndDeduplicateDataset(datasetCsvPath);
  if (rows.length < 40) {
    throw new Error(`Insufficient valid training rows (${rows.length}) in ${datasetCsvPath}.`);
  }

  const { train, val, test, uniqueDomains } = splitByDomainGroup(rows);
  const numStruct = STRUCTURAL_FEATURE_NAMES.length;

  // 1. Fit feature standardization scaler strictly on training split
  const scalerMean = new Array<number>(numStruct).fill(0);
  const scalerStd = new Array<number>(numStruct).fill(1);
  for (const row of train) {
    for (let j = 0; j < numStruct; j++) {
      scalerMean[j] += row.features.structural[j];
    }
  }
  for (let j = 0; j < numStruct; j++) {
    scalerMean[j] /= train.length;
  }
  const variances = new Array<number>(numStruct).fill(0);
  for (const row of train) {
    for (let j = 0; j < numStruct; j++) {
      const diff = row.features.structural[j] - scalerMean[j];
      variances[j] += diff * diff;
    }
  }
  for (let j = 0; j < numStruct; j++) {
    const std = Math.sqrt(variances[j] / Math.max(1, train.length));
    scalerStd[j] = std > 1e-6 ? std : 1;
  }

  // 2. Build character n-gram TF-IDF vocabulary strictly from training split (min_df = 3, max_features = 500)
  const docFreq = new Map<string, number>();
  for (const row of train) {
    for (const gram of row.features.ngrams.keys()) {
      docFreq.set(gram, (docFreq.get(gram) ?? 0) + 1);
    }
  }

  const vocabEntries = Array.from(docFreq.entries())
    .filter(([, df]) => df >= 3 && df < train.length * 0.9)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 500);

  const vocabulary = vocabEntries.map(([gram]) => gram);
  const vocabIndex = new Map<string, number>();
  vocabulary.forEach((gram, idx) => vocabIndex.set(gram, idx));

  const idf = vocabEntries.map(([, df]) =>
    Math.log((1 + train.length) / (1 + df)) + 1,
  );

  const encodeRow = (row: DatasetRow) => {
    const xStruct = row.features.structural.map(
      (v, j) => (v - scalerMean[j]) / scalerStd[j],
    );
    const tfidfEntries: Array<[number, number]> = [];
    let normSq = 0;
    for (const [gram, tf] of row.features.ngrams.entries()) {
      const idx = vocabIndex.get(gram);
      if (idx === undefined) continue;
      const val = tf * idf[idx];
      tfidfEntries.push([idx, val]);
      normSq += val * val;
    }
    const norm = Math.sqrt(normSq);
    if (norm > 0) {
      for (let k = 0; k < tfidfEntries.length; k++) {
        tfidfEntries[k][1] /= norm;
      }
    }
    return { xStruct, tfidfEntries, label: row.label };
  };

  const trainEncoded = train.map(encodeRow);
  const valEncoded = val.map(encodeRow);
  const testEncoded = test.map(encodeRow);

  // 3. Train L2-regularized Logistic Regression with Adam optimizer
  const wStruct = new Array<number>(numStruct).fill(0);
  const wNgram = new Array<number>(vocabulary.length).fill(0);
  let bias = 0;

  const mStruct = new Array<number>(numStruct).fill(0);
  const vStruct = new Array<number>(numStruct).fill(0);
  const mNgram = new Array<number>(vocabulary.length).fill(0);
  const vNgram = new Array<number>(vocabulary.length).fill(0);
  let mBias = 0;
  let vBias = 0;

  const lr = 0.04;
  const l2 = 0.002;
  const epochs = 180;
  const beta1 = 0.9;
  const beta2 = 0.999;
  const eps = 1e-8;

  for (let epoch = 1; epoch <= epochs; epoch++) {
    const gradStruct = new Array<number>(numStruct).fill(0);
    const gradNgram = new Array<number>(vocabulary.length).fill(0);
    let gradBias = 0;

    for (const sample of trainEncoded) {
      let z = bias;
      for (let j = 0; j < numStruct; j++) {
        z += wStruct[j] * sample.xStruct[j];
      }
      for (const [idx, val] of sample.tfidfEntries) {
        z += wNgram[idx] * val;
      }
      const p = sigmoid(z);
      const err = p - sample.label;

      gradBias += err;
      for (let j = 0; j < numStruct; j++) {
        gradStruct[j] += err * sample.xStruct[j];
      }
      for (const [idx, val] of sample.tfidfEntries) {
        gradNgram[idx] += err * val;
      }
    }

    const n = trainEncoded.length;
    const b1Pow = 1 - Math.pow(beta1, epoch);
    const b2Pow = 1 - Math.pow(beta2, epoch);

    const gB = gradBias / n;
    mBias = beta1 * mBias + (1 - beta1) * gB;
    vBias = beta2 * vBias + (1 - beta2) * gB * gB;
    bias -= (lr * (mBias / b1Pow)) / (Math.sqrt(vBias / b2Pow) + eps);

    for (let j = 0; j < numStruct; j++) {
      const g = gradStruct[j] / n + l2 * wStruct[j];
      mStruct[j] = beta1 * mStruct[j] + (1 - beta1) * g;
      vStruct[j] = beta2 * vStruct[j] + (1 - beta2) * g * g;
      wStruct[j] -= (lr * (mStruct[j] / b1Pow)) / (Math.sqrt(vStruct[j] / b2Pow) + eps);
    }

    for (let idx = 0; idx < vocabulary.length; idx++) {
      const g = gradNgram[idx] / n + l2 * wNgram[idx];
      mNgram[idx] = beta1 * mNgram[idx] + (1 - beta1) * g;
      vNgram[idx] = beta2 * vNgram[idx] + (1 - beta2) * g * g;
      wNgram[idx] -= (lr * (mNgram[idx] / b1Pow)) / (Math.sqrt(vNgram[idx] / b2Pow) + eps);
    }
  }

  const predictBatch = (encoded: ReturnType<typeof encodeRow>[]) =>
    encoded.map((sample) => {
      let z = bias;
      for (let j = 0; j < numStruct; j++) z += wStruct[j] * sample.xStruct[j];
      for (const [idx, val] of sample.tfidfEntries) z += wNgram[idx] * val;
      return sigmoid(z);
    });

  const valMetrics = computeMetrics(
    valEncoded.map((r) => r.label),
    predictBatch(valEncoded),
  );
  const testMetrics = computeMetrics(
    testEncoded.map((r) => r.label),
    predictBatch(testEncoded),
  );

  const phishingCount = rows.filter((r) => r.label === 1).length;

  const namedWeights: Array<{ feature: string; weight: number; direction: 'phishing' | 'legitimate' }> = [
    ...STRUCTURAL_FEATURE_NAMES.map((name, idx) => ({
      feature: `structural:${name}`,
      weight: Number(wStruct[idx].toFixed(4)),
      direction: (wStruct[idx] >= 0 ? 'phishing' : 'legitimate') as 'phishing' | 'legitimate',
    })),
    ...vocabulary.map((gram, idx) => ({
      feature: `ngram:"${gram}"`,
      weight: Number(wNgram[idx].toFixed(4)),
      direction: (wNgram[idx] >= 0 ? 'phishing' : 'legitimate') as 'phishing' | 'legitimate',
    })),
  ]
    .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))
    .slice(0, 16);

  const artifact: TrainedUrlModelArtifact = {
    modelVersion: '1.0.0',
    algorithm: 'L2-Regularized Logistic Regression (Structural Features + Char 3-4 Gram TF-IDF)',
    trainedAt: new Date().toISOString(),
    structuralFeatureNames: [...STRUCTURAL_FEATURE_NAMES],
    scalerMean: scalerMean.map((n) => Number(n.toFixed(6))),
    scalerStd: scalerStd.map((n) => Number(n.toFixed(6))),
    structuralWeights: wStruct.map((n) => Number(n.toFixed(6))),
    vocabulary,
    idf: idf.map((n) => Number(n.toFixed(6))),
    ngramWeights: wNgram.map((n) => Number(n.toFixed(6))),
    bias: Number(bias.toFixed(6)),
    evaluation: {
      modelVersion: '1.0.0',
      algorithm: 'L2-Regularized Logistic Regression (Structural + Char N-Gram TF-IDF)',
      trainedAt: new Date().toISOString(),
      datasetStats: {
        totalRawRows,
        deduplicatedRows: rows.length,
        trainCount: train.length,
        validationCount: val.length,
        testCount: test.length,
        phishingRatio: Number((phishingCount / rows.length).toFixed(4)),
        uniqueDomains,
      },
      validationMetrics: valMetrics,
      testMetrics,
      featureCount: numStruct + vocabulary.length,
      topLearnedWeights: namedWeights,
    },
  };

  fs.mkdirSync(path.dirname(outputModelPath), { recursive: true });
  fs.writeFileSync(outputModelPath, JSON.stringify(artifact, null, 2), 'utf8');
  return artifact;
}
