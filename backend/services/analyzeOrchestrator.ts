import crypto from 'node:crypto';
import { saveAnalysis } from '../db/database';
import { runAllThreatIntelChecks } from '../integrations/threatIntel';
import { predictUrlWithMl } from '../ml/predictor';
import { detectSuspiciousKeywords } from './keywordDetector';
import { computeCombinedRiskAssessment } from './riskScorer';
import { validateAndNormalizeUrl } from './urlValidator';
import { inspectWebsiteSafely } from './websiteInspector';
import type { AnalysisReport } from '../../shared/types';

export interface AnalyzeExecutionResult {
  ok: true;
  report: AnalysisReport;
}

export interface AnalyzeValidationError {
  ok: false;
  error: string;
  statusCode: number;
}

export async function analyzeSubmittedUrl(
  rawUrl: string,
  options?: { persist?: boolean },
): Promise<AnalyzeExecutionResult | AnalyzeValidationError> {
  const validated = validateAndNormalizeUrl(rawUrl);
  if (!validated.valid || !validated.signals || !validated.breakdown) {
    return {
      ok: false,
      error: validated.error || 'Invalid URL provided.',
      statusCode: 400,
    };
  }

  const [threatIntelResults, mlPrediction, websiteInspection] = await Promise.all([
    runAllThreatIntelChecks(validated.normalizedUrl, validated.domain),
    predictUrlWithMl(validated.submittedUrl),
    inspectWebsiteSafely(validated.normalizedUrl),
  ]);

  const urlKeywordMatches = detectSuspiciousKeywords(validated.normalizedUrl);
  const contentKeywordMatches = websiteInspection.keywordMatches ?? [];
  const keywordMatches = [...urlKeywordMatches, ...contentKeywordMatches];

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
    id: crypto.randomUUID(),
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
    saveAnalysis(report);
  }

  return { ok: true, report };
}
