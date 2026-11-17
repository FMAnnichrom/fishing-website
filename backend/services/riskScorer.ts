import type {
  AdvancedUrlBreakdown,
  DetectionVerdict,
  EvidenceFinding,
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
  breakdown?: AdvancedUrlBreakdown;
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
  evidenceFindings: EvidenceFinding[];
  recommendedAction: string;
  disclaimer: string;
  scoringBreakdown: ScoringBreakdown;
}

const SUBDOMAIN_AUTH_TOKENS = new Set([
  'login',
  'signin',
  'auth',
  'account',
  'accounts',
  'security',
  'verify',
  'verification',
  'portal',
  'billing',
  'payment',
  'password',
  'session',
  'update',
  'wallet',
  'recover',
  'recovery',
  'confirm',
]);

const EMAIL_LURE_VALUES = new Set(['email', 'mail', 'newsletter', 'alert', 'sms', 'notification']);
const LURE_PARAM_NAMES = new Set(['source', 'utm_source', 'via', 'channel', 'ref', 'campaign']);

export function computeCombinedRiskAssessment(input: ScoringInput): ScoringOutput {
  const {
    signals,
    breakdown,
    mlPrediction,
    threatIntelResults,
    keywordMatches,
    websiteInspection,
  } = input;

  const evidenceFindings: EvidenceFinding[] = [];
  const flaggedReasons: string[] = [];

  // 1. Threat Intelligence Signals (strongest authoritative signal)
  const intelMatches = threatIntelResults.filter((r) => r.status === 'match');
  const inKnownThreatDatabase = intelMatches.length > 0;
  let threatIntelPoints = 0;

  if (inKnownThreatDatabase) {
    threatIntelPoints = Math.min(70, 55 + (intelMatches.length - 1) * 10);
    for (const match of intelMatches) {
      const explanation = `Matched confirmed threat indicator in ${match.provider}: ${match.threatCategory ?? 'Malicious activity'} (${match.message})`;
      flaggedReasons.push(explanation);
      evidenceFindings.push({
        id: `intel-${match.provider.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
        category: 'Threat Intelligence',
        pattern: match.threatCategory ?? 'Known Malicious Indicator',
        matchedText: input.domain,
        explanation,
        riskContribution: Math.round(threatIntelPoints / intelMatches.length),
        source: 'Threat Intelligence',
        severity: 'high',
      });
    }
  }

  // 2. Brand Impersonation & Lookalike Analysis (0 - 42 pts, deduplicated)
  let brandImpersonationPoints = 0;
  const brandResults = breakdown?.brandSimilarityResults ?? [];
  const recordedBrandPatterns = new Set<string>();

  for (const b of brandResults) {
    if (b.location === 'path' && !signals.suspiciousAuthenticationPath) {
      // Informational context only when brand appears in a non-auth path (e.g. news/articles)
      continue;
    }

    const dedupeKey = `${b.brand}:${b.matchType}:${b.location}`;
    if (recordedBrandPatterns.has(dedupeKey)) continue;
    recordedBrandPatterns.add(dedupeKey);

    let pts = 0;
    let patternLabel = 'Brand Impersonation';
    let severity: EvidenceFinding['severity'] = 'high';

    if (b.matchType === 'unicode_confusable') {
      pts = 38;
      patternLabel = 'Unicode Confusable Brand Impersonation';
    } else if (b.matchType === 'leetspeak_substitution') {
      pts = 42;
      patternLabel = 'Leetspeak Brand Lookalike';
    } else if (b.matchType === 'typosquat_edit_distance') {
      pts = 36;
      patternLabel = 'Typosquatting Brand Lookalike';
    } else if (b.matchType === 'redirect_brand_lure') {
      pts = 28;
      patternLabel = 'External Redirect Brand Lure';
    } else if (b.location === 'subdomain') {
      pts = 30;
      patternLabel = 'Subdomain Brand Confusion';
    } else if (b.location === 'registrable_domain') {
      pts = 30;
      patternLabel = 'Domain Brand Impersonation';
    } else if (b.location === 'path' && signals.suspiciousAuthenticationPath) {
      pts = 26;
      patternLabel = 'Brand Name in Authentication Path';
      severity = 'medium';
    }

    brandImpersonationPoints += pts;
    flaggedReasons.push(b.details);
    evidenceFindings.push({
      id: `brand-${dedupeKey.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
      category: 'Brand Impersonation',
      pattern: patternLabel,
      matchedText: b.matchedToken,
      explanation: `${b.details} Official domain(s): ${b.officialDomains.join(', ')}.`,
      riskContribution: pts,
      source: 'Brand Impersonation',
      severity,
    });
  }
  brandImpersonationPoints = Math.min(42, brandImpersonationPoints);

  // 3. Heuristic & Structural Pattern Detection (0 - 38 pts, avoiding double-counting brand matches)
  let structuralPoints = 0;
  const addHeuristicFinding = (
    id: string,
    category: string,
    pattern: string,
    matchedText: string,
    explanation: string,
    pts: number,
    severity: EvidenceFinding['severity'],
  ) => {
    structuralPoints += pts;
    flaggedReasons.push(explanation);
    evidenceFindings.push({
      id,
      category,
      pattern,
      matchedText,
      explanation,
      riskContribution: pts,
      source: 'Heuristic',
      severity,
    });
  };

  if (signals.hasIpAddress) {
    addHeuristicFinding(
      'struct-ip-literal',
      'URL Structure',
      'Raw IP Address Host',
      input.domain,
      'Uses a raw or encoded IP address instead of a registered domain name.',
      18,
      'high',
    );
  }

  if (signals.hasAtSymbol) {
    addHeuristicFinding(
      'struct-at-symbol',
      'URL Masking',
      '@ Credential Masking',
      '@',
      'Contains an "@" symbol in the authority section, which can disguise the true destination host.',
      18,
      'high',
    );
  }

  if (signals.isPunycode) {
    addHeuristicFinding(
      'struct-punycode',
      'Internationalized Domain',
      'Punycode (xn--) Domain',
      input.domain,
      'Uses Punycode (xn--) internationalized domain encoding, which can conceal homograph spoofing.',
      14,
      'medium',
    );
  } else if (signals.unicodeConfusableDetected && brandImpersonationPoints === 0) {
    addHeuristicFinding(
      'struct-unicode-confusable',
      'Homograph Detection',
      'Unicode Confusable Characters',
      breakdown?.hostnameRaw ?? input.domain,
      'Contains visually confusable Unicode homoglyph characters in the hostname.',
      20,
      'high',
    );
  }

  if (signals.hasSuspiciousExtension) {
    addHeuristicFinding(
      'struct-suspicious-ext',
      'Payload Risk',
      'Dangerous File Extension',
      breakdown?.decodedPath ?? '',
      'URL path points to a potentially dangerous executable or script file.',
      16,
      'high',
    );
  }

  // Encoding & Obfuscation
  if (signals.encodedKeywordDetected) {
    const kws = breakdown?.encodedKeywords.join(', ') || 'security keyword';
    const pct = Math.round(signals.encodedCharacterRatio * 100);
    addHeuristicFinding(
      'struct-encoded-obfuscation',
      'URL Obfuscation',
      'Hex-Encoded Security Keyword',
      breakdown?.rawPath ?? '',
      `Percent-encoding (${pct}% of path/query) conceals security-sensitive keyword(s): ${kws} (decoded path: "${breakdown?.decodedPath}").`,
      26,
      'high',
    );
  } else if (signals.encodedCharacterRatio >= 0.45) {
    addHeuristicFinding(
      'struct-heavy-encoding',
      'URL Obfuscation',
      'Heavy Percent-Encoding',
      breakdown?.rawPath ?? '',
      `High ratio (${Math.round(signals.encodedCharacterRatio * 100)}%) of percent-encoded characters in path or query.`,
      10,
      'medium',
    );
  }

  // Query parameter & redirect analysis
  const queryParams = breakdown?.queryParams ?? [];
  const hasEmailLureParam = queryParams.some(
    (q) =>
      LURE_PARAM_NAMES.has(q.name) &&
      EMAIL_LURE_VALUES.has(q.decodedValue.trim().toLowerCase()),
  );
  const hasAuthRedirectParam = queryParams.some(
    (q) =>
      (q.isRedirectParam || q.isAuthParam) &&
      /auth|login|signin|verify|password|continue|oauth/i.test(q.decodedValue),
  );

  if (signals.externalRedirectDetected) {
    const extTargets = queryParams
      .filter((q) => q.embeddedUrl && q.embeddedUrl.isExternal)
      .map((q) => `${q.name}=${q.embeddedUrl!.hostname}`)
      .join(', ');
    const hasBrandLure = brandResults.some((b) => b.matchType === 'redirect_brand_lure');
    const pts = hasBrandLure ? 10 : 16;
    addHeuristicFinding(
      'struct-external-redirect',
      'Redirect Manipulation',
      'External Redirect Parameter',
      extTargets || 'redirect parameter',
      `Query parameter embeds an external redirect destination (${extTargets || 'external domain'}) differing from "${breakdown?.registrableDomain ?? input.domain}".`,
      pts,
      'high',
    );
  } else if (signals.nestedUrlDetected && hasAuthRedirectParam) {
    const nestedTargets = queryParams
      .filter((q) => q.embeddedUrl)
      .map((q) => `${q.name}=${q.decodedValue}`)
      .join(', ');
    const isRedirectEndpoint = /\/redirect|\/redir|\/out|\/forward|\/go/i.test(
      breakdown?.decodedPath ?? '',
    );
    if (isRedirectEndpoint || !hasEmailLureParam) {
      const pts = isRedirectEndpoint ? 30 : 18;
      addHeuristicFinding(
        'struct-nested-redirect',
        'Redirect Manipulation',
        'Encoded Nested Auth Redirect',
        nestedTargets || 'encoded redirect',
        `Detected encoded nested redirect targeting an authentication path (${nestedTargets}).`,
        pts,
        'medium',
      );
    }
  }

  if (hasEmailLureParam && (hasAuthRedirectParam || signals.suspiciousAuthenticationPath)) {
    addHeuristicFinding(
      'struct-email-session-lure',
      'Query Parameter Anomaly',
      'Auth Flow with Email Campaign Lure',
      queryParams.map((q) => `${q.name}=${q.decodedValue}`).join('&'),
      'Combines authentication/session redirect parameters with an email source tracking parameter, a pattern common in credential phishing links.',
      32,
      'medium',
    );
  } else if (signals.duplicateParameterCount > 0) {
    const dupNames = Array.from(
      new Set(queryParams.filter((q) => q.isDuplicate).map((q) => q.name)),
    ).join(', ');
    addHeuristicFinding(
      'struct-duplicate-params',
      'Query Parameter Anomaly',
      'Duplicate Query Parameters',
      dupNames,
      `Contains ${signals.duplicateParameterCount} duplicate query parameter(s) (${dupNames}), which can trigger parameter pollution.`,
      14,
      'medium',
    );
  } else if (
    signals.queryParameterCount >= 4 &&
    queryParams.filter((q) => q.isRedirectParam || q.isAuthParam).length >= 2
  ) {
    addHeuristicFinding(
      'struct-multi-auth-params',
      'Query Parameter Anomaly',
      'Multiple Redirect/Auth Parameters',
      `${signals.queryParameterCount} params`,
      'Combines multiple authentication and redirect query parameters in a single request.',
      10,
      'low',
    );
  }

  // Subdomain depth & auth-stacking analysis
  if (signals.hasExcessiveSubdomains) {
    const subLabels = breakdown?.subdomains ?? [];
    const authSubMatches = subLabels.filter((lbl) => SUBDOMAIN_AUTH_TOKENS.has(lbl));
    if (authSubMatches.length >= 2) {
      addHeuristicFinding(
        'struct-deep-auth-subdomains',
        'Subdomain Structure',
        'Deep Security-Themed Subdomain Stack',
        subLabels.join('.'),
        `Stacks ${signals.subdomainCount} subdomain levels containing credential/security terms (${authSubMatches.join(', ')}) over registrable domain "${breakdown?.registrableDomain ?? input.domain}".`,
        24,
        'medium',
      );
    } else if (brandImpersonationPoints === 0) {
      addHeuristicFinding(
        'struct-deep-subdomains',
        'Subdomain Structure',
        'Multiple Subdomain Levels',
        subLabels.join('.'),
        `Uses ${signals.subdomainCount} subdomain levels (${subLabels.join('.')}) above "${breakdown?.registrableDomain ?? input.domain}".`,
        4,
        'info',
      );
    }
  }

  // Unusual port detection (contextual: 8443 is normal for alt HTTPS, only risky with auth/brand)
  if (signals.unusualPort && signals.portNumber !== null) {
    if (signals.portNumber === 8443) {
      if (signals.suspiciousAuthenticationPath || signals.brandDomainMismatch) {
        addHeuristicFinding(
          'struct-port-8443-auth',
          'Port Analysis',
          'Alternate Port 8443 on Auth Path',
          `:8443${breakdown?.decodedPath ?? ''}`,
          'Uses alternate HTTPS port :8443 combined with an authentication path, warranting verification of service legitimacy.',
          30,
          'medium',
        );
      } else {
        addHeuristicFinding(
          'struct-port-8443-info',
          'Port Analysis',
          'Alternate HTTPS Port 8443',
          ':8443',
          'Uses alternate HTTPS port :8443 (common for admin interfaces; low risk without auth or brand impersonation).',
          6,
          'info',
        );
      }
    } else {
      const pts =
        signals.suspiciousAuthenticationPath || signals.brandDomainMismatch ? 16 : 8;
      addHeuristicFinding(
        'struct-unusual-port',
        'Port Analysis',
        'Non-Standard Web Port',
        `:${signals.portNumber}`,
        `Uses non-standard web port :${signals.portNumber} instead of standard ports 80/443.`,
        pts,
        pts >= 14 ? 'medium' : 'low',
      );
    }
  }

  // Mixed-case hostname obfuscation
  if (signals.hostnameCaseNormalized) {
    const pts = brandImpersonationPoints > 0 ? 6 : 4;
    addHeuristicFinding(
      'struct-mixed-case-host',
      'URL Normalization',
      'Mixed-Case Hostname',
      breakdown?.hostnameRaw ?? input.domain,
      `Hostname "${breakdown?.hostnameRaw}" uses mixed upper/lowercase characters (normalized to "${breakdown?.hostnameNormalized}").`,
      pts,
      brandImpersonationPoints > 0 ? 'medium' : 'low',
    );
  }

  // Authentication path without official domain when brand in path wasn't triggered
  if (
    signals.suspiciousAuthenticationPath &&
    brandImpersonationPoints > 0 &&
    !recordedBrandPatterns.has(`${brandResults[0]?.brand}:brand_in_path:path`)
  ) {
    structuralPoints += 6;
  }

  if (signals.isUrlShortener) {
    addHeuristicFinding(
      'struct-url-shortener',
      'Destination Masking',
      'URL Shortener Service',
      input.domain,
      'Uses a URL shortening service that conceals the final destination domain.',
      10,
      'medium',
    );
  }

  if (signals.hasSuspiciousTld) {
    addHeuristicFinding(
      'struct-suspicious-tld',
      'Domain Reputation',
      'Frequently Abused TLD',
      `.${signals.tld}`,
      `Uses frequently abused top-level domain (.${signals.tld}).`,
      8,
      'low',
    );
  }

  const nonPunycodeHyphens = input.domain
    .split('.')
    .map((l) => (l.startsWith('xn--') ? l.slice(4) : l))
    .join('.')
    .match(/-/g)?.length ?? 0;

  if (nonPunycodeHyphens >= 3) {
    addHeuristicFinding(
      'struct-excessive-hyphens',
      'Domain Structure',
      'Multiple Hostname Hyphens',
      input.domain,
      `Hostname contains ${nonPunycodeHyphens} hyphens, often seen in deceptive lookalike domains.`,
      6,
      'low',
    );
  }

  if (
    signals.hasWordNumberAnomaly &&
    !brandResults.some((b) => b.matchType === 'leetspeak_substitution')
  ) {
    addHeuristicFinding(
      'struct-word-number-anomaly',
      'Domain Structure',
      'Digit-Letter Blending',
      input.domain,
      'Domain mixes long alphabetic words and numeric sequences in an unusual pattern.',
      8,
      'low',
    );
  }

  if (signals.urlLength >= 110) {
    addHeuristicFinding(
      'struct-long-url',
      'URL Structure',
      'Unusually Long URL',
      `${signals.urlLength} chars`,
      `Unusually long URL (${signals.urlLength} characters), which can obscure deceptive parameters.`,
      4,
      'info',
    );
  }

  if (!signals.isHttps) {
    addHeuristicFinding(
      'struct-http-unencrypted',
      'Transport Security',
      'Unencrypted HTTP',
      'http://',
      'Uses unencrypted HTTP rather than HTTPS (note: HTTPS alone does not guarantee safety).',
      4,
      'info',
    );
  }

  structuralPoints = Math.min(38, structuralPoints);

  // 4. Machine Learning Prediction Points (0 - 30 pts)
  let mlPoints = 0;
  if (mlPrediction.label !== 'unavailable') {
    mlPoints = Math.round(mlPrediction.probability * 30);
    if (mlPrediction.probability >= 0.65) {
      const explanation = `ML classifier predicts phishing (${Math.round(mlPrediction.probability * 100)}% probability, ${mlPrediction.confidence}% model confidence).`;
      flaggedReasons.push(explanation);
      evidenceFindings.push({
        id: 'ml-high-probability',
        category: 'Machine Learning',
        pattern: 'Phishing Classification',
        matchedText: `${Math.round(mlPrediction.probability * 100)}% phishing probability`,
        explanation,
        riskContribution: mlPoints,
        source: 'ML',
        severity: 'high',
      });
    } else if (mlPrediction.probability >= 0.4) {
      const explanation = `ML classifier flagged borderline lexical/structural risk (${Math.round(mlPrediction.probability * 100)}% probability, ${mlPrediction.confidence}% confidence).`;
      flaggedReasons.push(explanation);
      evidenceFindings.push({
        id: 'ml-borderline-probability',
        category: 'Machine Learning',
        pattern: 'Borderline Risk Score',
        matchedText: `${Math.round(mlPrediction.probability * 100)}% phishing probability`,
        explanation,
        riskContribution: mlPoints,
        source: 'ML',
        severity: 'medium',
      });
    }
  }

  // 5. Suspicious Keyword Analysis (capped at 12 pts, avoiding inflating clean sites or double-counting)
  const rawKeywordWeight = keywordMatches.reduce((sum, k) => sum + k.weight, 0);
  const keywordPoints = Math.min(12, Math.round(rawKeywordWeight * 0.6));
  if (keywordMatches.length > 0) {
    const categories = Array.from(new Set(keywordMatches.map((k) => k.category)));
    const kwList = keywordMatches.slice(0, 4).map((k) => k.keyword).join(', ');
    const explanation = `Detected ${keywordMatches.length} suspicious keyword(s) (${kwList}) across ${categories.join(', ')}.`;
    flaggedReasons.push(explanation);
    evidenceFindings.push({
      id: 'heuristic-keywords',
      category: 'Keyword Detection',
      pattern: 'Suspicious URL Keywords',
      matchedText: kwList,
      explanation,
      riskContribution: keywordPoints,
      source: 'Heuristic',
      severity: keywordMatches.length >= 3 ? 'medium' : 'low',
    });
  }

  // 6. Optional Isolated Website Inspection Points (0 - 20 pts)
  let inspectionPoints = 0;
  if (websiteInspection.enabled && websiteInspection.status === 'completed') {
    if (websiteInspection.hasPasswordField && signals.impersonatedBrands.length > 0) {
      inspectionPoints += 15;
      const msg = 'Isolated page inspection found a password input on a brand-impersonating domain.';
      flaggedReasons.push(msg);
      evidenceFindings.push({
        id: 'inspect-password-brand',
        category: 'Website Inspection',
        pattern: 'Credential Form on Spoofed Brand',
        matchedText: 'input[type="password"]',
        explanation: msg,
        riskContribution: 15,
        source: 'Website Inspection',
        severity: 'high',
      });
    } else if (websiteInspection.hasPaymentField && !signals.isHttps) {
      inspectionPoints += 12;
      const msg = 'Isolated page inspection detected payment fields over unencrypted HTTP.';
      flaggedReasons.push(msg);
      evidenceFindings.push({
        id: 'inspect-payment-http',
        category: 'Website Inspection',
        pattern: 'Insecure Payment Form',
        matchedText: 'payment fields over HTTP',
        explanation: msg,
        riskContribution: 12,
        source: 'Website Inspection',
        severity: 'high',
      });
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
      const msg = 'Page contains a form submitting data to a different external domain.';
      flaggedReasons.push(msg);
      evidenceFindings.push({
        id: 'inspect-external-form',
        category: 'Website Inspection',
        pattern: 'Cross-Domain Form Action',
        matchedText: websiteInspection.formActionDomains.join(', '),
        explanation: msg,
        riskContribution: 8,
        source: 'Website Inspection',
        severity: 'medium',
      });
    }
    inspectionPoints = Math.min(20, inspectionPoints);
  } else if (websiteInspection.status === 'blocked_ssrf') {
    flaggedReasons.push(websiteInspection.reason);
  }

  let totalScore = Math.min(
    100,
    threatIntelPoints +
      brandImpersonationPoints +
      mlPoints +
      structuralPoints +
      keywordPoints +
      inspectionPoints,
  );

  // Confirmed threat intelligence matches always guarantee >= 75
  if (inKnownThreatDatabase && totalScore < 75) {
    totalScore = 75;
  }

  // Prevent keyword-only false positives on clean official/benign URLs
  if (
    !inKnownThreatDatabase &&
    brandImpersonationPoints === 0 &&
    mlPrediction.probability < 0.35 &&
    structuralPoints <= 8 &&
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
    verdict = 'Unable to Verify';
    classificationBasis = 'unable_to_verify';
  } else if (inKnownThreatDatabase) {
    riskLevel = 'Confirmed';
    verdict = 'Confirmed Malicious';
    classificationBasis = 'confirmed_threat';
  } else if (totalScore >= 60) {
    riskLevel = 'High';
    verdict = 'High Risk';
    classificationBasis = 'high_risk_prediction';
  } else if (totalScore >= 30) {
    riskLevel = 'Suspicious';
    verdict = 'Suspicious';
    classificationBasis = 'suspicious_signals';
  } else {
    riskLevel = 'Low';
    verdict = 'No Known Threat';
    classificationBasis = 'no_known_threat';
  }

  let recommendedAction: string;
  if (verdict === 'Confirmed Malicious') {
    recommendedAction =
      'Do not open this link or enter any credentials. This URL matches a confirmed threat indicator. Close the page immediately and notify your security team if you already interacted with it.';
  } else if (verdict === 'High Risk') {
    recommendedAction =
      'Avoid visiting or entering sensitive data on this website. Multiple machine learning, brand impersonation, and structural indicators strongly resemble phishing activity.';
  } else if (verdict === 'Suspicious') {
    recommendedAction =
      'Proceed with caution. Verify the registrable domain independently via an official bookmark or search engine before entering passwords, payment details, or personal information.';
  } else if (verdict === 'Unable to Verify') {
    recommendedAction =
      'Verification services were unavailable during this scan. Do not trust this URL automatically—verify the destination manually before proceeding.';
  } else {
    recommendedAction =
      'No known threats were detected in available feeds or structural checks. Still verify the domain name carefully before entering sensitive credentials, as newly launched phishing sites may not yet appear in threat databases.';
  }

  if (flaggedReasons.length === 0) {
    flaggedReasons.push(
      'No known threat-feed matches, brand impersonation, or high-risk structural anomalies were identified.',
    );
  }

  // Sort evidence findings by risk contribution descending
  evidenceFindings.sort((a, b) => b.riskContribution - a.riskContribution);

  return {
    riskScore: totalScore,
    riskLevel,
    verdict,
    inKnownThreatDatabase,
    flaggedReasons,
    evidenceFindings,
    recommendedAction,
    disclaimer:
      'No automated system can guarantee a website is completely safe. Newly created phishing pages may not yet appear in threat-intelligence feeds.',
    scoringBreakdown: {
      threatIntelPoints,
      brandImpersonationPoints,
      mlPoints,
      structuralPoints,
      keywordPoints,
      inspectionPoints,
      totalScore,
      classificationBasis,
    },
  };
}
