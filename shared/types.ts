export type DetectionVerdict =
  | 'Confirmed Malicious'
  | 'High Risk'
  | 'Suspicious'
  | 'No Known Threat'
  | 'Unable to Verify';

export type RiskLevel = 'Low' | 'Suspicious' | 'High' | 'Confirmed' | 'Unknown';

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

export interface EvidenceFinding {
  id: string;
  category: string;
  pattern: string;
  matchedText: string;
  explanation: string;
  riskContribution: number;
  source:
    | 'Threat Intelligence'
    | 'Brand Impersonation'
    | 'Heuristic'
    | 'ML'
    | 'Website Inspection';
  severity: 'high' | 'medium' | 'low' | 'info';
}

export interface QueryParameterAnalysis {
  name: string;
  rawValue: string;
  decodedValue: string;
  isDuplicate: boolean;
  isRedirectParam: boolean;
  isAuthParam: boolean;
  encodingLayers: number;
  embeddedUrl?: {
    raw: string;
    hostname: string;
    registrableDomain: string;
    isRelative: boolean;
    isExternal: boolean;
    claimedBrands: string[];
  };
}

export interface BrandSimilarityResult {
  brand: string;
  officialDomains: string[];
  matchedToken: string;
  location: 'subdomain' | 'registrable_domain' | 'path' | 'query_redirect';
  matchType:
    | 'exact_impersonation'
    | 'leetspeak_substitution'
    | 'unicode_confusable'
    | 'typosquat_edit_distance'
    | 'brand_in_path'
    | 'redirect_brand_lure';
  similarityScore: number; // 0 to 1
  editDistance: number;
  details: string;
}

export interface AdvancedUrlBreakdown {
  originalUrl: string;
  normalizedUrl: string;
  protocol: string;
  hostnameRaw: string;
  hostnameNormalized: string;
  hostnameCaseMixed: boolean;
  subdomains: string[];
  registrableDomain: string;
  publicSuffix: string;
  port: string;
  isStandardPort: boolean;
  isUnusualPort: boolean;
  rawPath: string;
  decodedPath: string;
  pathEncodingLayers: number;
  encodedCharacterRatio: number;
  encodedKeywords: string[];
  fragment: string;
  queryParams: QueryParameterAnalysis[];
  queryParameterCount: number;
  duplicateParameterCount: number;
  redirectParameterCount: number;
  nestedUrlDetected: boolean;
  externalRedirectDetected: boolean;
  brandSimilarityResults: BrandSimilarityResult[];
}

export interface UrlStructuralSignals {
  urlLength: number;
  domainLength: number;
  pathLength: number;
  queryLength: number;
  subdomainCount: number;
  maxSubdomainLength: number;
  hyphenCount: number;
  dotCount: number;
  specialCharCount: number;
  digitRatio: number;
  hasIpAddress: boolean;
  hasAtSymbol: boolean;
  isHttps: boolean;
  isPunycode: boolean;
  hasMixedScript: boolean;
  unicodeConfusableDetected: boolean;
  hasSuspiciousTld: boolean;
  tld: string;
  isUrlShortener: boolean;
  hasSuspiciousExtension: boolean;
  hasExcessiveSubdomains: boolean;
  hasWordNumberAnomaly: boolean;
  charEntropy: number;
  suspiciousBrandInSubdomain: boolean;
  brandDomainMismatch: boolean;
  brandInPath: boolean;
  maxBrandSimilarityScore: number;
  encodedCharacterRatio: number;
  encodedKeywordDetected: boolean;
  nestedUrlDetected: boolean;
  externalRedirectDetected: boolean;
  redirectParameterCount: number;
  queryParameterCount: number;
  duplicateParameterCount: number;
  unusualPort: boolean;
  portNumber: number | null;
  suspiciousAuthenticationPath: boolean;
  hostnameCaseNormalized: boolean;
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
  probability: number;
  confidence: number;
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
  brandImpersonationPoints: number;
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
  riskScore: number;
  riskLevel: RiskLevel;
  verdict: DetectionVerdict;
  mlPrediction: MlPredictionResult;
  inKnownThreatDatabase: boolean;
  keywordMatches: KeywordMatch[];
  evidenceFindings: EvidenceFinding[];
  urlBreakdown: AdvancedUrlBreakdown;
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
