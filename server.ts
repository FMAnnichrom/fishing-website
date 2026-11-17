import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { getDatabase, getRecentScans } from './backend/db/database';
import { syncPublicThreatFeeds } from './backend/integrations/threatIntel';
import {
  corsRestrictionMiddleware,
  createSecurityHeadersMiddleware,
  safeErrorHandler,
} from './backend/middleware/security';
import { loadTrainedModel } from './backend/ml/predictor';
import { createApiRouter } from './backend/routes/api';
import { analyzeSubmittedUrl } from './backend/services/analyzeOrchestrator';

const PORT = Number(process.env.PORT || 3000);

async function seedInitialAnalysesIfEmpty(): Promise<void> {
  const existing = getRecentScans(1);
  if (existing.length > 0) return;

  // Deterministic initial baseline scans evaluated through the real detection engine
  const baselineUrls = [
    'https://www.wikipedia.org/wiki/Phishing',
    'http://secure-paypal-login-verify.xyz/account/update?confirm-identity=1',
    'http://testsafebrowsing.appspot.com/s/phishing.html',
  ];

  for (const url of baselineUrls) {
    await analyzeSubmittedUrl(url, { persist: true });
  }
}

async function startServer(): Promise<void> {
  getDatabase();
  loadTrainedModel();
  await seedInitialAnalysesIfEmpty();

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use(createSecurityHeadersMiddleware());
  app.use(corsRestrictionMiddleware);
  app.use(express.json({ limit: '16kb' }));
  app.use(express.urlencoded({ extended: false, limit: '16kb' }));

  app.use('/api', createApiRouter());

  // Error handler for API routes
  app.use('/api', safeErrorHandler);

  if (process.env.NODE_ENV === 'production') {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Phishing URL Detector running on http://0.0.0.0:${PORT}`);
  });

  if (process.env.ENABLE_PUBLIC_FEED_SYNC === 'true') {
    const intervalMinutes = Math.max(15, Number(process.env.FEED_SYNC_INTERVAL_MINUTES || 60));
    syncPublicThreatFeeds().catch((err) => {
      console.error('[Feed Sync] Initial sync failed:', err instanceof Error ? err.message : err);
    });
    setInterval(() => {
      syncPublicThreatFeeds().catch((err) => {
        console.error('[Feed Sync] Scheduled sync failed:', err instanceof Error ? err.message : err);
      });
    }, intervalMinutes * 60 * 1000).unref();
  }
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
