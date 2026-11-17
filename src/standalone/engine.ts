import { extractMlFeatures, STRUCTURAL_FEATURE_NAMES } from '../../backend/ml/features';
import { safeBoundedDecode } from '../../backend/services/advancedUrlAnalyzer';
import { computeCombinedRiskAssessment } from '../../backend/services/riskScorer';
import { validateAndNormalizeUrl } from '../../backend/services/urlValidator';
import { SEED_KEYWORDS, SEED_TEST_INDICATORS } from '../../shared/defaultCatalog';
import modelArtifactJson from '../../ml-service/models/url_classifier_model.json';
import type {
  AnalysisReport,
  KeywordMatch,
  KeywordRecord,
  MlFeatureContribution,
  MlPredictionResult,
  ModelEvaluationReport,
  ProviderCheckResult,
  RecentScanItem,
  StatsSummary,
  ThreatIndicatorRecord,
  UserReportRecord,
} from '../../shared/types';

interface ModelArtifact {
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

const MODEL = modelArtifactJson as ModelArtifact;
const VOCAB_INDEX = new Map<string, number>();
MODEL.vocabulary.forEach((gram, idx) => VOCAB_INDEX.set(gram, idx));

const STORAGE_KEYS = {
  analyses: 'phish_detector_standalone_analyses_v1',
  reports: 'phish_detector_standalone_reports_v1',
};

const memoryFallbackStore: {
  analyses: AnalysisReport[];
  reports: UserReportRecord[];
} = {
  analyses: [],
  reports: [],
};

function canUseLocalStorage(): boolean {
  try {
    return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined';
  } catch {
    return false;
  }
}

function readStoredAnalyses(): AnalysisReport[] {
  if (!canUseLocalStorage()) return memoryFallbackStore.analyses;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEYS.analyses);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as AnalysisReport[]) : [];
  } catch {
    return [];
  }
}

function writeStoredAnalyses(items: AnalysisReport[]): void {
  const bounded = items.slice(0, 50);
  if (!canUseLocalStorage()) {
    memoryFallbackStore.analyses = bounded;
    return;
  }
  try {
    window.localStorage.setItem(STORAGE_KEYS.analyses, JSON.stringify(bounded));
  } catch {
    memoryFallbackStore.analyses = bounded;
  }
}

function readStoredReports(): UserReportRecord[] {
  if (!canUseLocalStorage()) return memoryFallbackStore.reports;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEYS.reports);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as UserReportRecord[]) : [];
  } catch {
    return [];
  }
}

function writeStoredReports(items: UserReportRecord[]): void {
  const bounded = items.slice(0, 50);
  if (!canUseLocalStorage()) {
    memoryFallbackStore.reports = bounded;
    return;
  }
  try {
    window.localStorage.setItem(STORAGE_KEYS.reports, JSON.stringify(bounded));
  } catch {
    memoryFallbackStore.reports = bounded;
  }
}

function generateId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `scan-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function sigmoid(z: number): number {
  if (z >= 35) return 1;
  if (z <= -35) return 0;
  return 1 / (1 + Math.exp(-z));
}

const BOOLEAN_FEATURES = new Set([
  'has_ip_address',
  'has_at_symbol',
  'is_https',
  'is_punycode',
  'unicode_confusable_detected',
  'has_suspicious_tld',
  'is_url_shortener',
  'has_suspicious_extension',
  'has_word_number_anomaly',
  'suspicious_brand_in_subdomain',
  'brand_domain_mismatch',
  'brand_in_path',
  'encoded_keyword_detected',
  'nested_url_detected',
  'external_redirect_detected',
  'unusual_port',
  'suspicious_authentication_path',
  'hostname_case_normalized',
]);

function formatStructuralValue(name: string, rawVal: number): string {
  if (BOOLEAN_FEATURES.has(name) || name.startsWith('has_') || name.startsWith('is_')) {
    return rawVal > 0 ? 'Yes' : 'No';
  }
  if (name === 'url_length') return `${Math.round(rawVal * 100)} chars`;
  if (name === 'domain_length') return `${Math.round(rawVal * 30)} chars`;
  if (name === 'path_length') return `${Math.round(rawVal * 50)} chars`;
  if (name === 'maximum_subdomain_length') return `${Math.round(rawVal * 20)} chars`;
  if (name === 'digit_ratio') return `${(rawVal * 10).toFixed(1)}%`;
  if (name === 'encoded_character_ratio' || name === 'brand_similarity_score') {
    return `${Math.round(rawVal * 100)}%`;
  }
  return Number(rawVal.toFixed(2)).toString();
}

export function predictInBrowser(rawOrNormalizedUrl: string): MlPredictionResult {
  const extracted = extractMlFeatures(rawOrNormalizedUrl);
  if (!extracted) {
    return {
      label: 'unavailable',
      probability: 0.5,
      confidence: 0,
      engine: `${MODEL.algorithm} (Browser Runtime)`,
      modelVersion: MODEL.modelVersion,
      topFeatures: [],
    };
  }

  let z = MODEL.bias;
  const contributions: MlFeatureContribution[] = [];

  const featureCount = Math.min(STRUCTURAL_FEATURE_NAMES.length, MODEL.structuralWeights.length);
  for (let j = 0; j < featureCount; j++) {
    const name = STRUCTURAL_FEATURE_NAMES[j];
    const scaled = (extracted.structural[j] - MODEL.scalerMean[j]) / MODEL.scalerStd[j];
    const contrib = scaled * MODEL.structuralWeights[j];
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
    const idx = VOCAB_INDEX.get(gram);
    if (idx === undefined) continue;
    const val = tf * MODEL.idf[idx];
    tfidfEntries.push([idx, val, gram]);
    normSq += val * val;
  }
  const norm = Math.sqrt(normSq);
  if (norm > 0) {
    for (const [idx, rawVal, gram] of tfidfEntries) {
      const normalizedVal = rawVal / norm;
      const contrib = normalizedVal * MODEL.ngramWeights[idx];
      z += contrib;
      if (Math.abs(contrib) >= 0.05) {
        contributions.push({
          name: `URL pattern "${gram}"`,
          value: `TF-IDF ${normalizedVal.toFixed(2)}`,
          contribution: Number(contrib.toFixed(4)),
        });
      }
    }
  }

  const probability = Number(sigmoid(z).toFixed(4));
  const label = probability >= 0.5 ? 'phishing' : 'legitimate';
  const confidence = Math.round(Math.abs(probability - 0.5) * 200);
  contributions.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));

  return {
    label,
    probability,
    confidence,
    engine: `${MODEL.algorithm} (In-Browser)`,
    modelVersion: MODEL.modelVersion,
    topFeatures: contributions.slice(0, 6),
  };
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function detectKeywordsInBrowser(normalizedUrl: string): KeywordMatch[] {
  let urlSurface = normalizedUrl.toLowerCase();
  let decodedSurface = urlSurface;
  try {
    const parsed = new URL(normalizedUrl);
    urlSurface = `${parsed.hostname}${parsed.pathname}${parsed.search}`.toLowerCase();
    const decodedPath = safeBoundedDecode(parsed.pathname).decoded;
    const decodedSearch = safeBoundedDecode(parsed.search).decoded;
    decodedSurface = `${parsed.hostname}${decodedPath}${decodedSearch}`.toLowerCase();
  } catch {
    // Keep full normalized string
  }

  const matches: KeywordMatch[] = [];
  for (const kw of SEED_KEYWORDS) {
    const escaped = escapeRegex(kw.keyword.toLowerCase());
    const regex = new RegExp(`(?:^|[^a-z0-9])${escaped}(?:$|[^a-z0-9])`, 'i');
    const compact = kw.keyword.toLowerCase().replace(/-/g, '');
    if (
      regex.test(urlSurface) ||
      regex.test(decodedSurface) ||
      (compact.length >= 6 && (urlSurface.includes(compact) || decodedSurface.includes(compact)))
    ) {
      matches.push({
        keyword: kw.keyword,
        category: kw.category,
        location: 'URL',
        rationale: kw.rationale,
        weight: kw.weight,
      });
    }
  }
  return matches.sort((a, b) => b.weight - a.weight || a.keyword.localeCompare(b.keyword));
}

function checkThreatIntelInBrowser(normalizedUrl: string): ProviderCheckResult[] {
  const started = performance.now ? performance.now() : Date.now();
  const localMatch = SEED_TEST_INDICATORS.find((item) => item.normalizedUrl === normalizedUrl);
  const elapsed = Math.max(1, Math.round((performance.now ? performance.now() : Date.now()) - started));

  const localResult: ProviderCheckResult = localMatch
    ? {
        provider: 'Local Threat Feed Index',
        status: 'match',
        threatCategory: localMatch.threatCategory,
        detectionStatus: localMatch.verificationStatus,
        source: localMatch.source,
        activity: 'Matched built-in standalone threat indicator index',
        message: `Matched indicator from ${localMatch.source} (${localMatch.threatCategory}).`,
        latencyMs: elapsed,
      }
    : {
        provider: 'Local Threat Feed Index',
        status: 'clean',
        message: 'No exact match found in bundled standalone threat-feed reference index.',
        latencyMs: elapsed,
      };

  const staticNotice =
    'Unavailable in static GitHub Pages mode (requires backend server proxy to keep API keys private).';

  return [
    localResult,
    {
      provider: 'Google Safe Browsing',
      status: 'not_configured',
      message: staticNotice,
      latencyMs: 0,
    },
    {
      provider: 'PhishTank',
      status: 'not_configured',
      message: staticNotice,
      latencyMs: 0,
    },
    {
      provider: 'URLhaus (abuse.ch)',
      status: 'not_configured',
      message: staticNotice,
      latencyMs: 0,
    },
  ];
}

function ensureSeededAnalyses(): AnalysisReport[] {
  const existing = readStoredAnalyses();
  if (existing.length > 0) return existing;

  const baselineUrls = [
    'https://www.wikipedia.org/wiki/Phishing',
    'http://secure-paypal-login-verify.xyz/account/update?confirm-identity=1',
    'http://testsafebrowsing.appspot.com/s/phishing.html',
  ];

  const seeded: AnalysisReport[] = [];
  for (const u of baselineUrls) {
    const report = runStandaloneAnalysis(u, { persist: false });
    seeded.unshift(report);
  }
  writeStoredAnalyses(seeded);
  return seeded;
}

export function runStandaloneAnalysis(
  rawUrl: string,
  options?: { persist?: boolean },
): AnalysisReport {
  const validated = validateAndNormalizeUrl(rawUrl);
  if (!validated.valid || !validated.signals || !validated.breakdown) {
    throw new Error(validated.error || 'Invalid URL provided.');
  }

  const mlPrediction = predictInBrowser(validated.submittedUrl);
  const threatIntelResults = checkThreatIntelInBrowser(validated.normalizedUrl);
  const keywordMatches = detectKeywordsInBrowser(validated.normalizedUrl);
  const websiteInspection = {
    enabled: false,
    status: 'disabled' as const,
    reason:
      'Isolated website inspection is disabled in standalone static mode (requires backend SSRF-protected sandbox).',
  };

  const scoring = computeCombinedRiskAssessment({
    domain: validated.domain,
    signals: validated.signals,
    breakdown: validated.breakdown,
    mlPrediction,
    threatIntelResults,
    keywordMatches,
    websiteInspection,
  });

  const report: AnalysisReport = {
    id: generateId(),
    submittedUrl: validated.submittedUrl,
    normalizedUrl: validated.normalizedUrl,
    domain: validated.domain,
    riskScore: scoring.riskScore,
    riskLevel: scoring.riskLevel,
    verdict: scoring.verdict,
    mlPrediction,
    inKnownThreatDatabase: scoring.inKnownThreatDatabase,
    keywordMatches,
    evidenceFindings: scoring.evidenceFindings,
    urlBreakdown: validated.breakdown,
    flaggedReasons: scoring.flaggedReasons,
    threatIntelResults,
    structuralSignals: validated.signals,
    websiteInspection,
    scoringBreakdown: scoring.scoringBreakdown,
    recommendedAction: scoring.recommendedAction,
    disclaimer: scoring.disclaimer,
    analyzedAt: new Date().toISOString(),
  };

  if (options?.persist !== false) {
    const current = ensureSeededAnalyses();
    writeStoredAnalyses([report, ...current]);
  }

  return report;
}

function normalizeLegacyVerdict(
  verdict: string,
  inThreatDb = false,
): AnalysisReport['verdict'] {
  if (verdict === 'Malicious / Phishing') {
    return inThreatDb ? 'Confirmed Malicious' : 'High Risk';
  }
  if (verdict === 'No Known Threat Detected') return 'No Known Threat';
  if (verdict === 'Unknown / Unable to Verify') return 'Unable to Verify';
  return verdict as AnalysisReport['verdict'];
}

export function getStandaloneAnalysisById(id: string): AnalysisReport {
  const all = ensureSeededAnalyses();
  const found = all.find((a) => a.id === id);
  if (!found) {
    throw new Error('Analysis record not found in browser storage.');
  }
  // If loaded from older cached localStorage entry without urlBreakdown, re-run analysis cleanly
  if (!found.urlBreakdown || !found.evidenceFindings) {
    return runStandaloneAnalysis(found.submittedUrl || found.normalizedUrl, { persist: false });
  }
  return {
    ...found,
    verdict: normalizeLegacyVerdict(found.verdict, found.inKnownThreatDatabase),
  };
}

export function getStandaloneStatsAndRecent(limit = 15): {
  summary: StatsSummary;
  recentScans: RecentScanItem[];
} {
  const all = ensureSeededAnalyses().map((a) => ({
    ...a,
    verdict: normalizeLegacyVerdict(a.verdict, a.inKnownThreatDatabase),
  }));
  const reports = readStoredReports();

  const summary: StatsSummary = {
    totalAnalyzed: all.length,
    maliciousDetected: all.filter(
      (a) => a.verdict === 'Confirmed Malicious' || a.verdict === 'High Risk',
    ).length,
    suspiciousDetected: all.filter((a) => a.verdict === 'Suspicious').length,
    noKnownThreat: all.filter((a) => a.verdict === 'No Known Threat').length,
    unableToVerify: all.filter((a) => a.verdict === 'Unable to Verify').length,
    threatIntelMatches: all.filter((a) => a.inKnownThreatDatabase).length,
    activeFeedIndicators: SEED_TEST_INDICATORS.length,
    pendingUserReports: reports.filter((r) => r.status === 'unverified').length,
  };

  const recentScans: RecentScanItem[] = all.slice(0, limit).map((a) => ({
    id: a.id,
    normalizedUrl: a.normalizedUrl,
    domain: a.domain,
    riskScore: a.riskScore,
    riskLevel: a.riskLevel,
    verdict: a.verdict,
    inKnownThreatDatabase: a.inKnownThreatDatabase,
    mlConfidence: a.mlPrediction.confidence,
    analyzedAt: a.analyzedAt,
  }));

  return { summary, recentScans };
}

export function submitStandaloneReport(
  rawUrl: string,
  rawReason: string,
): { message: string; report: UserReportRecord } {
  const validated = validateAndNormalizeUrl(rawUrl);
  if (!validated.valid) {
    throw new Error(validated.error || 'Invalid URL provided.');
  }

  const record: UserReportRecord = {
    id: generateId(),
    submittedUrl: validated.submittedUrl,
    normalizedUrl: validated.normalizedUrl,
    domain: validated.domain,
    reason: (rawReason.trim() || 'User reported suspicious behavior').slice(0, 400),
    status: 'unverified',
    createdAt: new Date().toISOString(),
  };

  const existing = readStoredReports();
  writeStoredReports([record, ...existing]);

  return {
    message:
      'URL report saved locally for review. Reports remain unverified until corroborated.',
    report: record,
  };
}

export function getStandaloneKeywords(): { keywords: KeywordRecord[] } {
  return {
    keywords: SEED_KEYWORDS.map((k, idx) => ({
      id: idx + 1,
      keyword: k.keyword,
      category: k.category,
      rationale: k.rationale,
      weight: k.weight,
      active: true,
    })).sort((a, b) => b.weight - a.weight || a.keyword.localeCompare(b.keyword)),
  };
}

export function getStandaloneThreatFeeds(): {
  indicators: ThreatIndicatorRecord[];
  pendingReports: UserReportRecord[];
} {
  const nowIso = new Date().toISOString();
  return {
    indicators: SEED_TEST_INDICATORS.map((item, idx) => ({
      id: idx + 1,
      normalizedUrl: item.normalizedUrl,
      domain: item.domain,
      threatCategory: item.threatCategory,
      source: item.source,
      verificationStatus: item.verificationStatus,
      firstSeen: nowIso,
      lastSeen: nowIso,
    })),
    pendingReports: readStoredReports(),
  };
}

export function getStandaloneModelEvaluation(): ModelEvaluationReport {
  return MODEL.evaluation;
}

export function getStandaloneHealth() {
  return {
    status: 'ok (standalone static mode)',
    timestamp: new Date().toISOString(),
    mlEngine: {
      loaded: true,
      version: MODEL.modelVersion,
      externalServiceConfigured: false,
    },
    websiteInspectionEnabled: false,
    threatIntelProviders: [
      {
        name: 'Local Threat Feed Index',
        configured: true,
        mode: 'Bundled Static Reference Index',
      },
      {
        name: 'Google Safe Browsing v4',
        configured: false,
        mode: 'Requires Server Proxy',
      },
      {
        name: 'PhishTank',
        configured: false,
        mode: 'Requires Server Proxy',
      },
      {
        name: 'URLhaus (abuse.ch)',
        configured: false,
        mode: 'Requires Server Proxy',
      },
    ],
  };
}
