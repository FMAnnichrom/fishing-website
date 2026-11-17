import fs from 'node:fs';
import path from 'node:path';
import { extractMlFeatures, STRUCTURAL_FEATURE_NAMES } from './features';
import type { TrainedUrlModelArtifact } from './trainer';
import type {
  MlFeatureContribution,
  MlPredictionResult,
  ModelEvaluationReport,
} from '../../shared/types';

let cachedModel: TrainedUrlModelArtifact | null = null;
let vocabIndexCache: Map<string, number> | null = null;

const DEFAULT_MODEL_PATH = path.resolve(
  process.cwd(),
  'ml-service/models/url_classifier_model.json',
);

export function loadTrainedModel(modelPath = DEFAULT_MODEL_PATH): TrainedUrlModelArtifact | null {
  if (cachedModel) return cachedModel;
  if (!fs.existsSync(modelPath)) return null;
  try {
    const raw = fs.readFileSync(modelPath, 'utf8');
    const parsed = JSON.parse(raw) as TrainedUrlModelArtifact;
    cachedModel = parsed;
    vocabIndexCache = new Map<string, number>();
    parsed.vocabulary.forEach((gram, idx) => vocabIndexCache!.set(gram, idx));
    return cachedModel;
  } catch {
    return null;
  }
}

export function getModelEvaluation(): ModelEvaluationReport | null {
  const model = loadTrainedModel();
  return model ? model.evaluation : null;
}

function sigmoid(z: number): number {
  if (z >= 35) return 1;
  if (z <= -35) return 0;
  return 1 / (1 + Math.exp(-z));
}

function formatStructuralValue(name: string, rawVal: number): string {
  if (name.startsWith('has_') || name.startsWith('is_')) {
    return rawVal > 0 ? 'Yes' : 'No';
  }
  if (name === 'url_length') return `${Math.round(rawVal * 100)} chars`;
  if (name === 'domain_length') return `${Math.round(rawVal * 30)} chars`;
  if (name === 'path_length') return `${Math.round(rawVal * 50)} chars`;
  if (name === 'digit_ratio') return `${(rawVal * 10).toFixed(1)}%`;
  return Number(rawVal.toFixed(2)).toString();
}

export async function predictUrlWithMl(normalizedUrl: string): Promise<MlPredictionResult> {
  // If external Python FastAPI ML service is explicitly configured, attempt it first with strict timeout
  const externalMlUrl = process.env.ML_SERVICE_URL?.trim();
  if (externalMlUrl) {
    const timeoutMs = Number(process.env.ML_SERVICE_TIMEOUT_MS || 4000);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(`${externalMlUrl.replace(/\/$/, '')}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: normalizedUrl }),
        signal: controller.signal,
      });
      if (resp.ok) {
        const data = (await resp.json()) as MlPredictionResult;
        clearTimeout(timer);
        return data;
      }
    } catch {
      // Fall through cleanly to local trained model artifact if external ML service is unavailable
    } finally {
      clearTimeout(timer);
    }
  }

  const model = loadTrainedModel();
  if (!model || !vocabIndexCache) {
    return {
      label: 'unavailable',
      probability: 0.5,
      confidence: 0,
      engine: 'ML model not loaded (run training script)',
      modelVersion: 'none',
      topFeatures: [],
    };
  }

  const extracted = extractMlFeatures(normalizedUrl);
  if (!extracted) {
    return {
      label: 'unavailable',
      probability: 0.5,
      confidence: 0,
      engine: model.algorithm,
      modelVersion: model.modelVersion,
      topFeatures: [],
    };
  }

  let z = model.bias;
  const contributions: MlFeatureContribution[] = [];

  for (let j = 0; j < STRUCTURAL_FEATURE_NAMES.length; j++) {
    const name = STRUCTURAL_FEATURE_NAMES[j];
    const scaled = (extracted.structural[j] - model.scalerMean[j]) / model.scalerStd[j];
    const contrib = scaled * model.structuralWeights[j];
    z += contrib;
    contributions.push({
      name: name.replace(/_/g, ' '),
      value: formatStructuralValue(name, extracted.structural[j]),
      contribution: Number(contrib.toFixed(4)),
    });
  }

  const tfidfEntries: Array<[number, number, string]> = [];
  let normSq = 0;
  for (const [gram, tf] of extracted.ngrams.entries()) {
    const idx = vocabIndexCache.get(gram);
    if (idx === undefined) continue;
    const val = tf * model.idf[idx];
    tfidfEntries.push([idx, val, gram]);
    normSq += val * val;
  }
  const norm = Math.sqrt(normSq);
  if (norm > 0) {
    for (const [idx, rawVal, gram] of tfidfEntries) {
      const normalizedVal = rawVal / norm;
      const contrib = normalizedVal * model.ngramWeights[idx];
      z += contrib;
      if (Math.abs(contrib) >= 0.05) {
        contributions.push({
          name: `URL pattern "${gram}"`,
          value: `TF-IDF ${(normalizedVal).toFixed(2)}`,
          contribution: Number(contrib.toFixed(4)),
        });
      }
    }
  }

  const probability = Number(sigmoid(z).toFixed(4));
  const label = probability >= 0.5 ? 'phishing' : 'legitimate';
  // Model confidence reflects distance from decision boundary (50% -> 0%, 100%/0% -> 100%)
  const confidence = Math.round(Math.abs(probability - 0.5) * 200);

  contributions.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));

  return {
    label,
    probability,
    confidence,
    engine: model.algorithm,
    modelVersion: model.modelVersion,
    topFeatures: contributions.slice(0, 6),
  };
}
