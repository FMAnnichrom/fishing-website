import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

export function createSecurityHeadersMiddleware() {
  const isDev = process.env.NODE_ENV !== 'production';
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: isDev ? ["'self'", "'unsafe-inline'", "'unsafe-eval'"] : ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'", 'ws:', 'wss:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'self'", 'https://*.google.com', 'https://aistudio.google.com'],
        upgradeInsecureRequests: null,
      },
    },
    crossOriginEmbedderPolicy: false,
    frameguard: false,
  });
}

export function corsRestrictionMiddleware(req: Request, res: Response, next: NextFunction): void {
  const origin = req.headers.origin;
  if (!origin) {
    next();
    return;
  }

  const allowedEnv = (process.env.CORS_ORIGIN || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const appUrl = process.env.APP_URL?.trim();
  const allowedSet = new Set([
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    ...allowedEnv,
    ...(appUrl ? [appUrl] : []),
  ]);

  // Also allow same-host origin in Cloud Run / preview environments
  const hostHeader = req.headers.host;
  const sameHostHttps = hostHeader ? `https://${hostHeader}` : '';
  const sameHostHttp = hostHeader ? `http://${hostHeader}` : '';

  if (allowedSet.has(origin) || origin === sameHostHttps || origin === sameHostHttp) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  }

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
}

export const analyzeRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many URL analysis requests. Please wait a minute and try again.',
  },
});

export const generalApiRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 240,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Rate limit exceeded. Please slow down requests.',
  },
});

export function requireAdminAuth(req: Request, res: Response, next: NextFunction): void {
  const configuredKey = process.env.ADMIN_API_KEY?.trim();
  if (!configuredKey || configuredKey === 'CHANGE_ME_TO_A_STRONG_RANDOM_SECRET') {
    res.status(503).json({
      error: 'Administrative endpoints are disabled until ADMIN_API_KEY is configured on the server.',
    });
    return;
  }

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!token) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }

  const a = Buffer.from(token);
  const b = Buffer.from(configuredKey);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    res.status(403).json({ error: 'Invalid administrative credentials.' });
    return;
  }

  next();
}

export function safeErrorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void {
  // Log concise error message without exposing request secrets or stack traces to client
  console.error('[API Error]', err.name, err.message);
  if (res.headersSent) return;
  res.status(500).json({
    error: 'An unexpected internal error occurred while processing the request.',
  });
}
