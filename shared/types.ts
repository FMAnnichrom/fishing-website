export type DetectionVerdict =
  | 'Malicious / Phishing'
  | 'Suspicious'
  | 'No Known Threat Detected'
  | 'Unknown / Unable to Verify';

export type RiskLevel = 'Low' | 'Suspicious' | 'High' | 'Unknown';

export type ProviderStatus =
  | 'match'
  | 'clean'
  | 'not_configured'
  | 'unavailable'
  | 'error';

export interface ProviderCheckResult {
  provider: string;
  status: ProviderStatus;
  threatCategory?: string;
  detectionStatus?: string;
  firstSeen?: string;
  lastSeen?: string;
  source?: string;
  activity?: string;
  message: string;
  latencyMs: number;
}

export interface KeywordMatch {
  keyword: string;
  category: string;
  location: 'URL' | 'Website Content';
  rationale: string;
  weight: number;
}

export interface UrlStructuralSignals {
  urlLength: number;
  domainLength: number;
  pathLength: number;
  queryLength: number;
  subdomainCount: number;
  hyphenCount: number;
  dotCount: number;
  specialCharCount: number;
  digitRatio: number;
  hasIpAddress: boolean;
  hasAtSymbol: boolean;
  isHttps: boolean;
  isPunycode: boolean;
  hasMixedScript: boolean;
  hasSuspiciousTld: boolean;
  tld: string;
  isUrlShortener: boolean;
  hasSuspiciousExtension: boolean;
  hasExcessiveSubdomains: boolean;
  hasWordNumberAnomaly: boolean;
  charEntropy: number;
  impersonatedBrands: string[];
  anomalies: string[];
}

export interface MlFeatureContribution {
  name: string;
  value: string;
  contribution: number;
}

export interface MlPredictionResult {
  label: 'phishing' | 'legitimate' | 'unavailable';
  probability: number; // 0.0 to 1.0 probability of phishing
  confidence: number; // 0 to 100
  engine: string;
  modelVersion: string;
  topFeatures: MlFeatureContribution[];
}

export interface WebsiteInspectionResult {
  enabled: boolean;
  status: 'completed' | 'disabled' | 'blocked_ssrf' | 'failed';
  reason: string;
  pageTitle?: string;
  textExcerpt?: string;
  redirectChain?: string[];
  hasLoginForm?: boolean;
  hasPasswordField?: boolean;
  hasPaymentField?: boolean;
  formActionDomains?: string[];
  brandImpersonationHints?: string[];
  keywordMatches?: KeywordMatch[];
}

export interface ScoringBreakdown {
  threatIntelPoints: number;
  mlPoints: number;
  structuralPoints: number;
  keywordPoints: number;
  inspectionPoints: number;
  totalScore: number;
  classificationBasis:
    | 'confirmed_threat'
    | 'high_risk_prediction'
    | 'suspicious_signals'
    | 'no_known_threat'
    | 'unable_to_verify';
}

export interface AnalysisReport {
  id: string;
  submittedUrl: string;
  normalizedUrl: string;
  domain: string;
  riskScore: number; // 0 - 100
  riskLevel: RiskLevel;
  verdict: DetectionVerdict;
  mlPrediction: MlPredictionResult;
  inKnownThreatDatabase: boolean;
  keywordMatches: KeywordMatch[];
  flaggedReasons: string[];
  threatIntelResults: ProviderCheckResult[];
  structuralSignals: UrlStructuralSignals;
  websiteInspection: WebsiteInspectionResult;
  scoringBreakdown: ScoringBreakdown;
  recommendedAction: string;
  disclaimer: string;
  analyzedAt: string;
}

export interface RecentScanItem {
  id: string;
  normalizedUrl: string;
  domain: string;
  riskScore: number;
  riskLevel: RiskLevel;
  verdict: DetectionVerdict;
  inKnownThreatDatabase: boolean;
  mlConfidence: number;
  analyzedAt: string;
}

export interface StatsSummary {
  totalAnalyzed: number;
  maliciousDetected: number;
  suspiciousDetected: number;
  noKnownThreat: number;
  unableToVerify: number;
  threatIntelMatches: number;
  activeFeedIndicators: number;
  pendingUserReports: number;
}

export interface KeywordRecord {
  id: number;
  keyword: string;
  category: string;
  rationale: string;
  weight: number;
  active: boolean;
}

export interface ThreatIndicatorRecord {
  id: number;
  normalizedUrl: string;
  domain: string;
  threatCategory: string;
  source: string;
  verificationStatus: string;
  firstSeen: string;
  lastSeen: string;
}

export interface UserReportRecord {
  id: string;
  submittedUrl: string;
  normalizedUrl: string;
  domain: string;
  reason: string;
  status: 'unverified' | 'corroborated' | 'dismissed';
  createdAt: string;
}

export interface ConfusionMatrix {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface EvaluationMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  confusionMatrix: ConfusionMatrix;
  sampleCount: number;
}

export interface ModelEvaluationReport {
  modelVersion: string;
  algorithm: string;
  trainedAt: string;
  datasetStats: {
    totalRawRows: number;
    deduplicatedRows: number;
    trainCount: number;
    validationCount: number;
    testCount: number;
    phishingRatio: number;
    uniqueDomains: number;
  };
  validationMetrics: EvaluationMetrics;
  testMetrics: EvaluationMetrics;
  featureCount: number;
  topLearnedWeights: Array<{ feature: string; weight: number; direction: 'phishing' | 'legitimate' }>;
}
