import assert from 'node:assert/strict';
import test from 'node:test';
import { runStandaloneAnalysis } from '../src/standalone/engine';
import {
  buildRecentSecurityActivity,
  computeDetectionBreakdown,
  deriveDetectionSource,
  getVerdictPresentation,
} from '../src/utils/dashboardHelpers';

test('getVerdictPresentation covers all 5 detection verdicts with consistent tone', () => {
  assert.equal(getVerdictPresentation('Confirmed Malicious').tone, 'danger');
  assert.equal(getVerdictPresentation('High Risk').tone, 'danger');
  assert.equal(getVerdictPresentation('Suspicious').tone, 'warning');
  assert.equal(getVerdictPresentation('No Known Threat').tone, 'safe');
  assert.equal(getVerdictPresentation('Unable to Verify').tone, 'neutral');
});

test('deriveDetectionSource distinguishes threat intel, brand pattern, and clean scans', () => {
  const threatReport = runStandaloneAnalysis('http://testsafebrowsing.appspot.com/s/phishing.html', {
    persist: false,
  });
  const brandReport = runStandaloneAnalysis('https://accounts.google.com.login.example.test/', {
    persist: false,
  });
  const cleanReport = runStandaloneAnalysis('https://www.wikipedia.org/wiki/Phishing', {
    persist: false,
  });

  const threatScan = {
    id: threatReport.id,
    normalizedUrl: threatReport.normalizedUrl,
    domain: threatReport.domain,
    riskScore: threatReport.riskScore,
    riskLevel: threatReport.riskLevel,
    verdict: threatReport.verdict,
    inKnownThreatDatabase: threatReport.inKnownThreatDatabase,
    mlConfidence: threatReport.mlPrediction.confidence,
    analyzedAt: threatReport.analyzedAt,
  };
  const brandScan = {
    ...threatScan,
    id: brandReport.id,
    normalizedUrl: brandReport.normalizedUrl,
    domain: brandReport.domain,
    riskScore: brandReport.riskScore,
    verdict: brandReport.verdict,
    inKnownThreatDatabase: false,
  };
  const cleanScan = {
    ...threatScan,
    id: cleanReport.id,
    normalizedUrl: cleanReport.normalizedUrl,
    domain: cleanReport.domain,
    riskScore: cleanReport.riskScore,
    verdict: cleanReport.verdict,
    inKnownThreatDatabase: false,
  };

  assert.match(deriveDetectionSource(threatScan, threatReport), /Threat Intel/);
  assert.match(deriveDetectionSource(brandScan, brandReport), /Brand Pattern/);
  assert.equal(deriveDetectionSource(cleanScan, cleanReport), 'Hybrid Engine (Clean)');
});

test('computeDetectionBreakdown aggregates real finding categories without fabrication', () => {
  const empty = computeDetectionBreakdown([]);
  assert.equal(empty.inspectedCount, 0);
  assert.equal(empty.totalFindings, 0);

  const brandReport = runStandaloneAnalysis('https://accounts.google.com.login.example.test/', {
    persist: false,
  });
  const redirectReport = runStandaloneAnalysis(
    'https://example.test/redirect?next=https://accounts.google.com',
    { persist: false },
  );

  const summary = computeDetectionBreakdown([brandReport, redirectReport]);
  assert.equal(summary.inspectedCount, 2);
  const brandBucket = summary.buckets.find((b) => b.label === 'Brand & Lookalike');
  const redirectBucket = summary.buckets.find((b) => b.label === 'Redirect Manipulation');
  assert.ok(brandBucket && brandBucket.count >= 1);
  assert.ok(redirectBucket && redirectBucket.count >= 1);
});

test('buildRecentSecurityActivity merges scans and user reports chronologically', () => {
  const report = runStandaloneAnalysis('https://accounts.google.com.login.example.test/', {
    persist: false,
  });
  const events = buildRecentSecurityActivity(
    [
      {
        id: report.id,
        normalizedUrl: report.normalizedUrl,
        domain: report.domain,
        riskScore: report.riskScore,
        riskLevel: report.riskLevel,
        verdict: report.verdict,
        inKnownThreatDatabase: report.inKnownThreatDatabase,
        mlConfidence: report.mlPrediction.confidence,
        analyzedAt: '2026-01-01T10:00:00.000Z',
      },
    ],
    [
      {
        id: 'rep-1',
        submittedUrl: 'http://example.test/login',
        normalizedUrl: 'http://example.test/login',
        domain: 'example.test',
        reason: 'SMS phishing link',
        status: 'unverified',
        createdAt: '2026-01-01T11:00:00.000Z',
      },
    ],
  );

  assert.equal(events.length, 2);
  assert.equal(events[0].id, 'report-rep-1');
  assert.equal(events[1].scanId, report.id);
});
