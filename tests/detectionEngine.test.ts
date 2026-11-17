import test from 'node:test';
import assert from 'node:assert/strict';
import { getDatabase, upsertThreatIndicators } from '../backend/db/database';
import { extractMlFeatures } from '../backend/ml/features';
import { loadTrainedModel, predictUrlWithMl } from '../backend/ml/predictor';
import { analyzeSubmittedUrl } from '../backend/services/analyzeOrchestrator';
import { detectSuspiciousKeywords } from '../backend/services/keywordDetector';
import { computeCombinedRiskAssessment } from '../backend/services/riskScorer';
import { isPrivateOrReservedIp, validateOutboundTarget } from '../backend/services/ssrfGuard';
import { validateAndNormalizeUrl } from '../backend/services/urlValidator';
import {
  getStandaloneModelEvaluation,
  getStandaloneStatsAndRecent,
  runStandaloneAnalysis,
  submitStandaloneReport,
} from '../src/standalone/engine';

// Ensure DB and trained model are initialized
getDatabase(':memory:');
loadTrainedModel();

test('validates and rejects invalid, empty, and dangerous URL schemes', () => {
  assert.equal(validateAndNormalizeUrl('').valid, false);
  assert.equal(validateAndNormalizeUrl('not a url').valid, false);
  assert.equal(validateAndNormalizeUrl('javascript:alert(1)').valid, false);
  assert.equal(validateAndNormalizeUrl('data:text/html,<script>alert(1)</script>').valid, false);
  assert.equal(validateAndNormalizeUrl('file:///etc/passwd').valid, false);
});

test('rejects oversized URLs above 2048 characters', () => {
  const hugeUrl = `https://example.com/${'a'.repeat(2100)}`;
  const res = validateAndNormalizeUrl(hugeUrl);
  assert.equal(res.valid, false);
  assert.match(res.error || '', /maximum supported length/i);
});

test('flags @ credential masking, IP literals, and Punycode domains', () => {
  const atRes = validateAndNormalizeUrl('http://www.google.com@malicious-login.xyz/auth');
  assert.equal(atRes.valid, true);
  assert.equal(atRes.signals?.hasAtSymbol, true);

  const ipRes = validateAndNormalizeUrl('http://198.51.100.42/chase-bank/login/verify.php');
  assert.equal(ipRes.valid, true);
  assert.equal(ipRes.signals?.hasIpAddress, true);
  assert.ok(ipRes.signals?.impersonatedBrands.includes('Chase'));

  const punyRes = validateAndNormalizeUrl('http://xn--pple-43d.com/support/reset-password');
  assert.equal(punyRes.valid, true);
  assert.equal(punyRes.signals?.isPunycode, true);
});

test('SSRF guard blocks loopback, private RFC1918, IPv6 local, and cloud metadata IPs', async () => {
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('10.20.30.40'), true);
  assert.equal(isPrivateOrReservedIp('172.16.0.5'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.1'), true);
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('::1'), true);
  assert.equal(isPrivateOrReservedIp('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);

  const localBlocked = await validateOutboundTarget('http://localhost:3000/admin');
  assert.equal(localBlocked.allowed, false);

  const metadataBlocked = await validateOutboundTarget('http://169.254.169.254/latest/meta-data/');
  assert.equal(metadataBlocked.allowed, false);
});

test('keyword detection does not alone classify legitimate login URLs as High Risk or Confirmed Malicious', async () => {
  const kwMatches = detectSuspiciousKeywords('https://github.com/login');
  assert.ok(kwMatches.some((k) => k.keyword === 'login'));

  const analysis = await analyzeSubmittedUrl('https://github.com/login', { persist: false });
  assert.equal(analysis.ok, true);
  if (analysis.ok) {
    assert.notEqual(analysis.report.verdict, 'Confirmed Malicious');
    assert.notEqual(analysis.report.verdict, 'High Risk');
    assert.ok(analysis.report.riskScore < 60);
  }
});

test('detects known safe-test-fixture threat URL and classifies as Confirmed Malicious', async () => {
  const analysis = await analyzeSubmittedUrl(
    'http://testsafebrowsing.appspot.com/s/phishing.html',
    { persist: false },
  );
  assert.equal(analysis.ok, true);
  if (analysis.ok) {
    assert.equal(analysis.report.inKnownThreatDatabase, true);
    assert.equal(analysis.report.verdict, 'Confirmed Malicious');
    assert.ok(analysis.report.riskScore >= 75);
  }
});

test('detects multi-signal synthetic phishing URL and grades honestly when external APIs are unconfigured', async () => {
  const analysis = await analyzeSubmittedUrl(
    'http://secure-paypal-login-verify.xyz/account/update?confirm-identity=1',
    { persist: false },
  );
  assert.equal(analysis.ok, true);
  if (analysis.ok) {
    assert.equal(analysis.report.verdict, 'High Risk');
    assert.ok(analysis.report.riskScore >= 60);
    assert.ok(analysis.report.keywordMatches.length >= 3);
    const gsb = analysis.report.threatIntelResults.find((p) => p.provider === 'Google Safe Browsing');
    assert.ok(gsb);
    if (!process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
      assert.equal(gsb.status, 'not_configured');
    }
  }
});

test('legitimate reference URL returns No Known Threat with non-guarantee disclaimer', async () => {
  const analysis = await analyzeSubmittedUrl('https://www.wikipedia.org/wiki/Phishing', {
    persist: false,
  });
  assert.equal(analysis.ok, true);
  if (analysis.ok) {
    assert.equal(analysis.report.verdict, 'No Known Threat');
    assert.ok(analysis.report.riskScore < 30);
    assert.match(analysis.report.disclaimer, /No automated system can guarantee/i);
  }
});

test('deduplicates threat-feed records during batch ingestion', () => {
  const memDb = getDatabase(':memory:');
  const batch = [
    {
      normalizedUrl: 'http://dup-test.example.invalid/phish',
      domain: 'dup-test.example.invalid',
      threatCategory: 'Phishing',
      source: 'Unit Test Feed',
      verificationStatus: 'feed_reported',
    },
    {
      normalizedUrl: 'http://dup-test.example.invalid/phish',
      domain: 'dup-test.example.invalid',
      threatCategory: 'Phishing',
      source: 'Unit Test Feed',
      verificationStatus: 'feed_reported',
    },
  ];
  const res = upsertThreatIndicators(batch, memDb);
  assert.equal(res.insertedOrUpdated, 1);
  assert.equal(res.skippedDuplicates, 1);
});

test('handles unavailable ML and external providers gracefully as Unable to Verify', () => {
  const validated = validateAndNormalizeUrl('https://example.org/test');
  assert.equal(validated.valid, true);
  const scoring = computeCombinedRiskAssessment({
    domain: validated.domain,
    signals: validated.signals!,
    breakdown: validated.breakdown!,
    mlPrediction: {
      label: 'unavailable',
      probability: 0.5,
      confidence: 0,
      engine: 'none',
      modelVersion: 'none',
      topFeatures: [],
    },
    threatIntelResults: [
      {
        provider: 'Google Safe Browsing',
        status: 'not_configured',
        message: 'Not configured',
        latencyMs: 0,
      },
      {
        provider: 'Local Threat Feed Index',
        status: 'unavailable',
        message: 'Unavailable',
        latencyMs: 0,
      },
    ],
    keywordMatches: [],
    websiteInspection: {
      enabled: false,
      status: 'disabled',
      reason: 'Disabled',
    },
  });
  assert.equal(scoring.verdict, 'Unable to Verify');
});

test('trained ML predictor returns real probability and feature explanations', async () => {
  const phishPred = await predictUrlWithMl('http://198.51.100.99/paypal/verify-account.php');
  assert.equal(phishPred.label, 'phishing');
  assert.ok(phishPred.probability > 0.5);
  assert.ok(phishPred.topFeatures.length > 0);
});

// =========================================================================
// Advanced URL Pattern Detection Tests (All 10 Synthetic .test Techniques)
// =========================================================================

test('Pattern A: detects subdomain confusion and PSL registrable domain mismatch', async () => {
  const url = 'https://accounts.google.com.login.example.test/';
  const res = await analyzeSubmittedUrl(url, { persist: false });
  assert.equal(res.ok, true);
  if (res.ok) {
    const r = res.report;
    assert.equal(r.urlBreakdown.registrableDomain, 'example.test');
    assert.equal(r.structuralSignals.suspiciousBrandInSubdomain, true);
    assert.equal(r.structuralSignals.brandDomainMismatch, true);
    assert.ok(r.structuralSignals.impersonatedBrands.includes('Google'));
    assert.equal(r.verdict, 'High Risk');
    assert.ok(r.riskScore >= 60);
    assert.ok(r.evidenceFindings.some((f) => f.source === 'Brand Impersonation'));
  }
});

test('Pattern B: detects brand name inside authentication URL path on unrelated domain', async () => {
  const url = 'https://example.test/google/accounts/signin';
  const res = await analyzeSubmittedUrl(url, { persist: false });
  assert.equal(res.ok, true);
  if (res.ok) {
    const r = res.report;
    assert.equal(r.structuralSignals.brandInPath, true);
    assert.equal(r.structuralSignals.suspiciousAuthenticationPath, true);
    assert.equal(r.structuralSignals.brandDomainMismatch, true);
    assert.ok(r.riskScore >= 30);
    assert.ok(r.evidenceFindings.some((f) => f.pattern === 'Brand Name in Authentication Path'));
  }
});

test('Pattern C: detects misleading external redirect query parameter targeting a brand', async () => {
  const url = 'https://example.test/redirect?next=https://accounts.google.com';
  const res = await analyzeSubmittedUrl(url, { persist: false });
  assert.equal(res.ok, true);
  if (res.ok) {
    const r = res.report;
    assert.equal(r.structuralSignals.nestedUrlDetected, true);
    assert.equal(r.structuralSignals.externalRedirectDetected, true);
    assert.equal(r.structuralSignals.redirectParameterCount, 1);
    assert.ok(r.urlBreakdown.queryParams[0].embeddedUrl?.isExternal);
    assert.ok(r.riskScore >= 30);
    assert.ok(
      r.evidenceFindings.some((f) => f.pattern === 'External Redirect Brand Lure'),
    );
  }
});

test('Pattern D: detects URL hex encoding and obfuscation of security keywords', async () => {
  const url = 'https://example.test/%61%63%63%6F%75%6E%74/login';
  const res = await analyzeSubmittedUrl(url, { persist: false });
  assert.equal(res.ok, true);
  if (res.ok) {
    const r = res.report;
    assert.equal(r.urlBreakdown.decodedPath, '/account/login');
    assert.equal(r.structuralSignals.encodedKeywordDetected, true);
    assert.ok(r.urlBreakdown.encodedKeywords.includes('account'));
    assert.ok(r.structuralSignals.encodedCharacterRatio > 0.5);
    assert.ok(r.riskScore >= 30);
    assert.ok(r.evidenceFindings.some((f) => f.pattern === 'Hex-Encoded Security Keyword'));
  }
});

test('Pattern E: detects nested encoded redirect targeting auth path', async () => {
  const url = 'https://example.test/redirect?url=%2Fauth%2Fcontinue';
  const res = await analyzeSubmittedUrl(url, { persist: false });
  assert.equal(res.ok, true);
  if (res.ok) {
    const r = res.report;
    assert.equal(r.structuralSignals.nestedUrlDetected, true);
    assert.equal(r.structuralSignals.externalRedirectDetected, false);
    assert.equal(r.urlBreakdown.queryParams[0].decodedValue, '/auth/continue');
    assert.ok(r.riskScore >= 30);
    assert.ok(r.evidenceFindings.some((f) => f.pattern === 'Encoded Nested Auth Redirect'));
  }
});

test('Pattern F: detects long and deep security-themed subdomain hierarchy', async () => {
  const url = 'https://login.account.security.portal.example.test/';
  const res = await analyzeSubmittedUrl(url, { persist: false });
  assert.equal(res.ok, true);
  if (res.ok) {
    const r = res.report;
    assert.equal(r.urlBreakdown.registrableDomain, 'example.test');
    assert.equal(r.structuralSignals.subdomainCount, 4);
    assert.equal(r.structuralSignals.hasExcessiveSubdomains, true);
    assert.ok(r.riskScore >= 30);
    assert.ok(
      r.evidenceFindings.some((f) => f.pattern === 'Deep Security-Themed Subdomain Stack'),
    );
  }
});

test('Pattern G: detects lookalike leetspeak brand typosquatting', async () => {
  const url = 'https://g00gle.example.test/';
  const res = await analyzeSubmittedUrl(url, { persist: false });
  assert.equal(res.ok, true);
  if (res.ok) {
    const r = res.report;
    assert.ok(r.structuralSignals.impersonatedBrands.includes('Google'));
    assert.ok(r.structuralSignals.maxBrandSimilarityScore >= 0.75);
    assert.equal(r.verdict, 'High Risk');
    assert.ok(r.riskScore >= 60);
    const leetMatch = r.urlBreakdown.brandSimilarityResults.find(
      (b) => b.matchType === 'leetspeak_substitution',
    );
    assert.ok(leetMatch);
    assert.match(leetMatch.details, /o replaced with 0/i);
  }
});

test('Pattern H: evaluates port 8443 contextually when combined with auth path', async () => {
  const url = 'https://example.test:8443/auth';
  const res = await analyzeSubmittedUrl(url, { persist: false });
  assert.equal(res.ok, true);
  if (res.ok) {
    const r = res.report;
    assert.equal(r.structuralSignals.unusualPort, true);
    assert.equal(r.structuralSignals.portNumber, 8443);
    assert.equal(r.structuralSignals.suspiciousAuthenticationPath, true);
    // Contextual: should be Suspicious, not Confirmed Malicious or automatic High Risk
    assert.equal(r.verdict, 'Suspicious');
    assert.ok(r.evidenceFindings.some((f) => f.pattern === 'Alternate Port 8443 on Auth Path'));
  }
});

test('Pattern I: detects suspicious multiple query parameters and duplicate parameter names', async () => {
  const url = 'https://example.test/session?continue=%2Flogin&source=email';
  const res = await analyzeSubmittedUrl(url, { persist: false });
  assert.equal(res.ok, true);
  if (res.ok) {
    const r = res.report;
    assert.equal(r.structuralSignals.queryParameterCount, 2);
    assert.equal(r.structuralSignals.redirectParameterCount, 1);
    assert.ok(r.riskScore >= 30);
    assert.ok(
      r.evidenceFindings.some((f) => f.pattern === 'Auth Flow with Email Campaign Lure'),
    );
  }

  const dupUrl = 'https://example.test/auth?token=abc&token=def';
  const dupFeatures = extractMlFeatures(dupUrl);
  assert.equal(dupFeatures?.signals.duplicateParameterCount, 1);
});

test('Pattern J: detects mixed-case brand impersonation and preserves raw vs normalized host', async () => {
  const url = 'https://GoOgLe.example.test/Account';
  const res = await analyzeSubmittedUrl(url, { persist: false });
  assert.equal(res.ok, true);
  if (res.ok) {
    const r = res.report;
    assert.equal(r.urlBreakdown.hostnameRaw, 'GoOgLe.example.test');
    assert.equal(r.urlBreakdown.hostnameNormalized, 'google.example.test');
    assert.equal(r.urlBreakdown.hostnameCaseMixed, true);
    assert.equal(r.structuralSignals.hostnameCaseNormalized, true);
    assert.ok(r.structuralSignals.impersonatedBrands.includes('Google'));
    assert.equal(r.verdict, 'High Risk');
    assert.ok(r.riskScore >= 60);
  }
});

// =========================================================================
// Legitimate Comparison Tests (Preventing False Positives)
// =========================================================================

test('Legitimate comparison URLs do not produce false positives', async () => {
  const legitUrls = [
    'https://www.google.com/search?q=security',
    'https://example.org/news/google-workspace-announcement',
    'https://github.com/login?return_to=%2Fsettings',
    'https://app.example.org/login?next=/dashboard',
    'https://status.example.org:8443/health',
    'https://cdn.static.assets.example.org/images/logo.png',
    'https://en.wikipedia.org/wiki/Phishing%20attack',
    'https://docs.example.org/search?q=oauth&page=2&sort=asc',
  ];

  for (const url of legitUrls) {
    const res = await analyzeSubmittedUrl(url, { persist: false });
    assert.equal(res.ok, true, `Expected valid analysis for ${url}`);
    if (res.ok) {
      assert.equal(
        res.report.verdict,
        'No Known Threat',
        `Expected No Known Threat for ${url}, got ${res.report.verdict} (${res.report.riskScore})`,
      );
      assert.ok(
        res.report.riskScore < 30,
        `Expected low risk score (<30) for ${url}, got ${res.report.riskScore}`,
      );
    }
  }
});

test('standalone GitHub Pages engine runs upgraded ML, evidence findings, and URL breakdown without backend', () => {
  const phishReport = runStandaloneAnalysis(
    'https://accounts.google.com.login.example.test/',
    { persist: true },
  );
  assert.equal(phishReport.verdict, 'High Risk');
  assert.ok(phishReport.riskScore >= 60);
  assert.equal(phishReport.urlBreakdown.registrableDomain, 'example.test');
  assert.ok(phishReport.evidenceFindings.length > 0);

  const legitReport = runStandaloneAnalysis('https://github.com/login', { persist: true });
  assert.equal(legitReport.verdict, 'No Known Threat');
  assert.ok(legitReport.riskScore < 30);

  const stats = getStandaloneStatsAndRecent(10);
  assert.ok(stats.summary.totalAnalyzed >= 2);
  assert.ok(stats.recentScans.length >= 2);

  const rep = submitStandaloneReport('https://suspicious-test.example.invalid/auth', 'Test report');
  assert.equal(rep.report.status, 'unverified');

  const evalData = getStandaloneModelEvaluation();
  assert.ok(evalData.datasetStats.deduplicatedRows > 500);
});
