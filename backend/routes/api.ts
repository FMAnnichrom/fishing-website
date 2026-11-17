import crypto from 'node:crypto';
import express from 'express';
import {
  getActiveKeywords,
  getAnalysisById,
  getRecentScans,
  getStatsSummary,
  listThreatIndicators,
  listUserReports,
  saveUserReport,
  upsertKeyword,
} from '../db/database';
import { syncPublicThreatFeeds } from '../integrations/threatIntel';
import {
  analyzeRateLimiter,
  generalApiRateLimiter,
  requireAdminAuth,
} from '../middleware/security';
import { getModelEvaluation, loadTrainedModel } from '../ml/predictor';
import { analyzeSubmittedUrl } from '../services/analyzeOrchestrator';
import { validateAndNormalizeUrl } from '../services/urlValidator';

export function createApiRouter(): express.Router {
  const router = express.Router();
  router.use(generalApiRateLimiter);

  // Health & service configuration overview (never leaks secrets)
  router.get('/health', (_req, res) => {
    const model = loadTrainedModel();
    const providers = [
      {
        name: 'Local Threat Feed Index',
        configured: true,
        mode: 'SQLite Persistent Feed Store',
      },
      {
        name: 'Google Safe Browsing v4',
        configured: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim()),
        mode: 'REST API v4',
      },
      {
        name: 'PhishTank',
        configured: Boolean(process.env.PHISHTANK_API_KEY?.trim()),
        mode: 'REST API',
      },
      {
        name: 'URLhaus (abuse.ch)',
        configured: Boolean(process.env.URLHAUS_AUTH_KEY?.trim()),
        mode: 'REST API v1',
      },
    ];

    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      mlEngine: {
        loaded: Boolean(model),
        version: model?.modelVersion ?? 'none',
        externalServiceConfigured: Boolean(process.env.ML_SERVICE_URL?.trim()),
      },
      websiteInspectionEnabled: process.env.ENABLE_WEBSITE_INSPECTION === 'true',
      threatIntelProviders: providers,
    });
  });

  // Analyze a URL
  router.post('/analyze', analyzeRateLimiter, async (req, res, next) => {
    try {
      const url = req.body?.url;
      if (typeof url !== 'string') {
        res.status(400).json({ error: 'Request body must include a "url" string field.' });
        return;
      }

      const result = await analyzeSubmittedUrl(url);
      if (!result.ok) {
        const errResult = result as { ok: false; error: string; statusCode: number };
        res.status(errResult.statusCode).json({ error: errResult.error });
        return;
      }

      res.json(result.report);
    } catch (err) {
      next(err);
    }
  });

  // Retrieve a previous analysis by ID
  router.get('/analyze/:id', (req, res) => {
    const id = String(req.params.id || '').trim();
    if (!/^[0-9a-f-]{8,64}$/i.test(id)) {
      res.status(400).json({ error: 'Invalid analysis ID format.' });
      return;
    }

    const report = getAnalysisById(id);
    if (!report) {
      res.status(404).json({ error: 'Analysis record not found.' });
      return;
    }
    res.json(report);
  });

  // Retrieve threat detection statistics and recent scans
  router.get('/stats', (req, res) => {
    const limitParam = Number(req.query.limit ?? 15);
    const limit = Number.isFinite(limitParam) ? Math.max(1, Math.min(50, limitParam)) : 15;
    res.json({
      summary: getStatsSummary(),
      recentScans: getRecentScans(limit),
    });
  });

  // Submit a suspicious URL report (always stored as unverified until reviewed)
  router.post('/reports', analyzeRateLimiter, (req, res) => {
    const rawUrl = req.body?.url;
    const rawReason = typeof req.body?.reason === 'string' ? req.body.reason.trim() : '';

    if (typeof rawUrl !== 'string') {
      res.status(400).json({ error: 'A valid "url" string is required.' });
      return;
    }

    const validated = validateAndNormalizeUrl(rawUrl);
    if (!validated.valid) {
      res.status(400).json({ error: validated.error || 'Invalid URL provided.' });
      return;
    }

    const cleanReason = (rawReason || 'User reported suspicious behavior').slice(0, 400);
    const record = {
      id: crypto.randomUUID(),
      submittedUrl: validated.submittedUrl,
      normalizedUrl: validated.normalizedUrl,
      domain: validated.domain,
      reason: cleanReason,
      status: 'unverified' as const,
      createdAt: new Date().toISOString(),
    };

    saveUserReport(record);
    res.status(201).json({
      message: 'URL report submitted for review. Reports remain unverified until corroborated.',
      report: record,
    });
  });

  // Public read-only transparency endpoints for UI tabs
  router.get('/keywords', (_req, res) => {
    res.json({ keywords: getActiveKeywords() });
  });

  router.get('/threat-feeds', (req, res) => {
    const limit = Number(req.query.limit ?? 40);
    res.json({
      indicators: listThreatIndicators(limit),
      pendingReports: listUserReports(20),
    });
  });

  router.get('/model/evaluation', (_req, res) => {
    const evaluation = getModelEvaluation();
    if (!evaluation) {
      res.status(404).json({ error: 'Trained ML model artifact is not loaded.' });
      return;
    }
    res.json(evaluation);
  });

  // Protected Administrative Endpoints
  router.post('/admin/feeds/sync', requireAdminAuth, async (_req, res, next) => {
    try {
      const outcome = await syncPublicThreatFeeds();
      res.json(outcome);
    } catch (err) {
      next(err);
    }
  });

  router.post('/admin/keywords', requireAdminAuth, (req, res) => {
    const { keyword, category, rationale, weight } = req.body ?? {};
    if (
      typeof keyword !== 'string' ||
      !keyword.trim() ||
      typeof category !== 'string' ||
      !category.trim() ||
      typeof rationale !== 'string' ||
      !rationale.trim()
    ) {
      res.status(400).json({ error: 'keyword, category, and rationale strings are required.' });
      return;
    }
    const created = upsertKeyword({
      keyword,
      category,
      rationale,
      weight: typeof weight === 'number' ? weight : 5,
    });
    res.status(201).json({ keyword: created });
  });

  router.get('/admin/reports', requireAdminAuth, (_req, res) => {
    res.json({ reports: listUserReports(100) });
  });

  return router;
}
