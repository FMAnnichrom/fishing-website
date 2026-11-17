import type {
  DetectionVerdict,
  KeywordMatch,
  MlPredictionResult,
  ProviderCheckResult,
  RiskLevel,
  ScoringBreakdown,
  UrlStructuralSignals,
  WebsiteInspectionResult,
} from '../../shared/types';

export interface ScoringInput {
  domain: string;
  signals: UrlStructuralSignals;
  mlPrediction: MlPredictionResult;
  threatIntelResults: ProviderCheckResult[];
  keywordMatches: KeywordMatch[];
  websiteInspection: WebsiteInspectionResult;
}

export interface ScoringOutput {
  riskScore: number;
  riskLevel: RiskLevel;
  verdict: DetectionVerdict;
  inKnownThreatDatabase: boolean;
  flaggedReasons: string[];
  recommendedAction: string;
  disclaimer: string;
  scoringBreakdown: ScoringBreakdown;
}

export function computeCombinedRiskAssessment(input: ScoringInput): ScoringOutput {
  const { signals, mlPrediction, threatIntelResults, keywordMatches, websiteInspection } = input;
  const flaggedReasons: string[] = [];

  // 1. Threat Intelligence Signals (strongest authoritative signal)
  const intelMatches = threatIntelResults.filter((r) => r.status === 'match');
  const inKnownThreatDatabase = intelMatches.length > 0;
  let threatIntelPoints = 0;

  if (inKnownThreatDatabase) {
    threatIntelPoints = Math.min(70, 55 + (intelMatches.length - 1) * 10);
    for (const match of intelMatches) {
      flaggedReasons.push(
        `Threat intelligence match in ${match.provider}: ${match.threatCategory ?? 'Malicious activity'} (${match.message})`,
      );
    }
  }

  // 2. Machine Learning Prediction Points (0 - 35 pts)
  let mlPoints = 0;
  if (mlPrediction.label !== 'unavailable') {
    mlPoints = Math.round(mlPrediction.probability * 35);
    if (mlPrediction.probability >= 0.7) {
      flaggedReasons.push(
        `ML classifier predicts phishing (${Math.round(mlPrediction.probability * 100)}% probability, ${mlPrediction.confidence}% model confidence).`,
      );
    } else if (mlPrediction.probability >= 0.45) {
      flaggedReasons.push(
        `ML classifier flagged borderline lexical/structural risk (${Math.round(mlPrediction.probability * 100)}% probability).`,
      );
    }
  }

  // 3. URL Structural Anomalies (0 - 34 pts)
  let structuralPoints = 0;
  if (signals.hasIpAddress) structuralPoints += 18;
  if (signals.hasAtSymbol) structuralPoints += 18;
  if (signals.impersonatedBrands.length > 0) structuralPoints += 22;
  if (signals.isPunycode || signals.hasMixedScript) structuralPoints += 14;
  if (signals.hasSuspiciousExtension) structuralPoints += 16;
  if (signals.hasSuspiciousTld) structuralPoints += 8;
  if (signals.isUrlShortener) structuralPoints += 10;
  if (signals.hasExcessiveSubdomains) structuralPoints += 8;
  if (signals.hyphenCount >= 3) structuralPoints += 6;
  if (signals.hasWordNumberAnomaly) structuralPoints += 8;
  if (signals.urlLength >= 100) structuralPoints += 5;
  if (!signals.isHttps) structuralPoints += 4;
  structuralPoints = Math.min(34, structuralPoints);

  for (const anomaly of signals.anomalies) {
    flaggedReasons.push(anomaly);
  }

  // 4. Suspicious Keyword Analysis (capped at 14 pts so keywords alone NEVER trigger Malicious!)
  const rawKeywordWeight = keywordMatches.reduce((sum, k) => sum + k.weight, 0);
  const keywordPoints = Math.min(14, Math.round(rawKeywordWeight * 0.75));
  if (keywordMatches.length > 0) {
    const categories = Array.from(new Set(keywordMatches.map((k) => k.category)));
    flaggedReasons.push(
      `Detected ${keywordMatches.length} suspicious keyword(s) (${keywordMatches
        .slice(0, 4)
        .map((k) => `"${k.keyword}"`)
        .join(', ')}) across ${categories.join(', ')}.`,
    );
  }

  // 5. Optional Isolated Website Inspection Points (0 - 20 pts)
  let inspectionPoints = 0;
  if (websiteInspection.enabled && websiteInspection.status === 'completed') {
    if (websiteInspection.hasPasswordField && signals.impersonatedBrands.length > 0) {
      inspectionPoints += 15;
      flaggedReasons.push('Isolated page inspection found a password input on a brand-impersonating domain.');
    } else if (websiteInspection.hasPaymentField && !signals.isHttps) {
      inspectionPoints += 12;
      flaggedReasons.push('Isolated page inspection detected payment fields over unencrypted HTTP.');
    }
    if (websiteInspection.brandImpersonationHints && websiteInspection.brandImpersonationHints.length > 0) {
      inspectionPoints += 10;
      flaggedReasons.push(...websiteInspection.brandImpersonationHints);
    }
    if (
      websiteInspection.formActionDomains &&
      websiteInspection.formActionDomains.some((d) => d !== input.domain && !d.endsWith(`.${input.domain}`))
    ) {
      inspectionPoints += 8;
      flaggedReasons.push('Page contains form submitting data to a different external domain.');
    }
    inspectionPoints = Math.min(20, inspectionPoints);
  } else if (websiteInspection.status === 'blocked_ssrf') {
    flaggedReasons.push(websiteInspection.reason);
  }

  let totalScore = Math.min(
    100,
    threatIntelPoints + mlPoints + structuralPoints + keywordPoints + inspectionPoints,
  );

  // Confirmed threat intelligence matches always guarantee High risk (>= 75)
  if (inKnownThreatDatabase && totalScore < 75) {
    totalScore = 75;
  }

  // Prevent keyword-only false positives on clean official URLs
  if (
    !inKnownThreatDatabase &&
    mlPrediction.probability < 0.35 &&
    structuralPoints <= 4 &&
    totalScore > 28
  ) {
    totalScore = 28;
  }

  const anyIntelAvailable = threatIntelResults.some(
    (r) => r.status === 'match' || r.status === 'clean',
  );

  let riskLevel: RiskLevel;
  let verdict: DetectionVerdict;
  let classificationBasis: ScoringBreakdown['classificationBasis'];

  if (!anyIntelAvailable && mlPrediction.label === 'unavailable') {
    riskLevel = 'Unknown';
    verdict = 'Unknown / Unable to Verify';
    classificationBasis = 'unable_to_verify';
  } else if (inKnownThreatDatabase) {
    riskLevel = 'High';
    verdict = 'Malicious / Phishing';
    classificationBasis = 'confirmed_threat';
  } else if (totalScore >= 60) {
    riskLevel = 'High';
    verdict = 'Malicious / Phishing';
    classificationBasis = 'high_risk_prediction';
  } else if (totalScore >= 30) {
    riskLevel = 'Suspicious';
    verdict = 'Suspicious';
    classificationBasis = 'suspicious_signals';
  } else {
    riskLevel = 'Low';
    verdict = 'No Known Threat Detected';
    classificationBasis = 'no_known_threat';
  }

  let recommendedAction: string;
  if (verdict === 'Malicious / Phishing') {
    recommendedAction = inKnownThreatDatabase
      ? 'Do not open this link or enter any credentials. This URL matches a confirmed threat indicator. Close the page immediately and notify your security team if you already interacted with it.'
      : 'Avoid visiting or entering sensitive data on this website. Multiple machine learning and structural risk indicators strongly resemble phishing activity.';
  } else if (verdict === 'Suspicious') {
    recommendedAction =
      'Proceed with caution. Verify the domain independently via an official bookmark or search engine before entering passwords, payment details, or personal information.';
  } else if (verdict === 'Unknown / Unable to Verify') {
    recommendedAction =
      'Verification services were unavailable during this scan. Do not trust this URL automatically—verify the destination manually before proceeding.';
  } else {
    recommendedAction =
      'No known threats were detected in available feeds or structural checks. Still verify the domain name carefully before entering sensitive credentials, as newly launched phishing sites may not yet appear in threat databases.';
  }

  if (flaggedReasons.length === 0) {
    flaggedReasons.push(
      'No known threat-feed matches, high-risk structural anomalies, or malicious keyword combinations were identified.',
    );
  }

  return {
    riskScore: totalScore,
    riskLevel,
    verdict,
    inKnownThreatDatabase,
    flaggedReasons,
    recommendedAction,
    disclaimer:
      'No automated system can guarantee a website is completely safe. Newly created phishing pages may not yet appear in threat-intelligence feeds.',
    scoringBreakdown: {
      threatIntelPoints,
      mlPoints,
      structuralPoints,
      keywordPoints,
      inspectionPoints,
      totalScore,
      classificationBasis,
    },
  };
}
