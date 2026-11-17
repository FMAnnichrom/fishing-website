import test from 'node:test';
import assert from 'node:assert/strict';
import { getDatabase, upsertThreatIndicators } from '../backend/db/database';
import { loadTrainedModel, predictUrlWithMl } from '../backend/ml/predictor';
import { analyzeSubmittedUrl } from '../backend/services/analyzeOrchestrator';
import { detectSuspiciousKeywords } from '../backend/services/keywordDetector';
import { computeCombinedRiskAssessment } from '../backend/services/riskScorer';
import { isPrivateOrReservedIp, validateOutboundTarget } from '../backend/services/ssrfGuard';
import { validateAndNormalizeUrl } from '../backend/services/urlValidator';

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

test('keyword detection does not alone classify legitimate login URLs as malicious', async () => {
  const kwMatches = detectSuspiciousKeywords('https://github.com/login');
  assert.ok(kwMatches.some((k) => k.keyword === 'login'));

  const analysis = await analyzeSubmittedUrl('https://github.com/login', { persist: false });
  assert.equal(analysis.ok, true);
  if (analysis.ok) {
    assert.notEqual(analysis.report.verdict, 'Malicious / Phishing');
    assert.ok(analysis.report.riskScore < 60);
  }
});

test('detects known safe-test-fixture threat URL and classifies as Malicious / Phishing', async () => {
  const analysis = await analyzeSubmittedUrl(
    'http://testsafebrowsing.appspot.com/s/phishing.html',
    { persist: false },
  );
  assert.equal(analysis.ok, true);
  if (analysis.ok) {
    assert.equal(analysis.report.inKnownThreatDatabase, true);
    assert.equal(analysis.report.verdict, 'Malicious / Phishing');
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
    assert.equal(analysis.report.verdict, 'Malicious / Phishing');
    assert.ok(analysis.report.riskScore >= 60);
    assert.ok(analysis.report.keywordMatches.length >= 3);
    // Verify unconfigured external providers honestly report not_configured rather than fake matches
    const gsb = analysis.report.threatIntelResults.find((p) => p.provider === 'Google Safe Browsing');
    assert.ok(gsb);
    if (!process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
      assert.equal(gsb.status, 'not_configured');
    }
  }
});

test('legitimate reference URL returns No Known Threat Detected with non-guarantee disclaimer', async () => {
  const analysis = await analyzeSubmittedUrl('https://www.wikipedia.org/wiki/Phishing', {
    persist: false,
  });
  assert.equal(analysis.ok, true);
  if (analysis.ok) {
    assert.equal(analysis.report.verdict, 'No Known Threat Detected');
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

test('handles unavailable ML and external providers gracefully as Unknown / Unable to Verify', () => {
  const validated = validateAndNormalizeUrl('https://example.org/test');
  assert.equal(validated.valid, true);
  const scoring = computeCombinedRiskAssessment({
    domain: validated.domain,
    signals: validated.signals!,
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
  assert.equal(scoring.verdict, 'Unknown / Unable to Verify');
});

test('trained ML predictor returns real probability and feature explanations', async () => {
  const phishPred = await predictUrlWithMl('http://198.51.100.99/paypal/verify-account.php');
  assert.equal(phishPred.label, 'phishing');
  assert.ok(phishPred.probability > 0.5);
  assert.ok(phishPred.topFeatures.length > 0);
});
