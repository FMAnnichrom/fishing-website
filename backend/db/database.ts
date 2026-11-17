import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { SEED_KEYWORDS, SEED_TEST_INDICATORS } from '../../shared/defaultCatalog';
import type {
  AnalysisReport,
  KeywordRecord,
  RecentScanItem,
  StatsSummary,
  ThreatIndicatorRecord,
  UserReportRecord,
} from '../../shared/types';

let dbInstance: DatabaseSync | null = null;

export function getDatabase(customPath?: string): DatabaseSync {
  if (dbInstance && !customPath) return dbInstance;

  const dbPath =
    customPath ||
    process.env.SQLITE_DB_PATH ||
    path.resolve(process.cwd(), 'data/phishing_detector.db');

  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  }

  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');

  db.exec(`
    CREATE TABLE IF NOT EXISTS analyses (
      id TEXT PRIMARY KEY,
      submitted_url TEXT NOT NULL,
      normalized_url TEXT NOT NULL,
      domain TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      risk_level TEXT NOT NULL,
      verdict TEXT NOT NULL,
      in_threat_db INTEGER NOT NULL,
      ml_confidence INTEGER NOT NULL,
      report_json TEXT NOT NULL,
      analyzed_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_analyses_analyzed_at ON analyses(analyzed_at DESC);
    CREATE INDEX IF NOT EXISTS idx_analyses_domain ON analyses(domain);

    CREATE TABLE IF NOT EXISTS threat_feeds (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      normalized_url TEXT NOT NULL UNIQUE,
      domain TEXT NOT NULL,
      threat_category TEXT NOT NULL,
      source TEXT NOT NULL,
      verification_status TEXT NOT NULL,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_threat_feeds_domain ON threat_feeds(domain);
    CREATE INDEX IF NOT EXISTS idx_threat_feeds_expires ON threat_feeds(expires_at);

    CREATE TABLE IF NOT EXISTS keywords (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      keyword TEXT NOT NULL UNIQUE,
      category TEXT NOT NULL,
      rationale TEXT NOT NULL,
      weight INTEGER NOT NULL DEFAULT 5,
      active INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS user_reports (
      id TEXT PRIMARY KEY,
      submitted_url TEXT NOT NULL,
      normalized_url TEXT NOT NULL,
      domain TEXT NOT NULL,
      reason TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unverified',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS feed_sync_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      status TEXT NOT NULL,
      records_ingested INTEGER NOT NULL DEFAULT 0,
      message TEXT NOT NULL,
      synced_at TEXT NOT NULL
    );
  `);

  seedInitialData(db);

  if (!customPath) {
    dbInstance = db;
  }
  return db;
}

function seedInitialData(db: DatabaseSync): void {
  const kwCountRow = db.prepare('SELECT COUNT(*) AS cnt FROM keywords').get() as { cnt: number };
  if (kwCountRow.cnt === 0) {
    const insertKw = db.prepare(
      'INSERT OR IGNORE INTO keywords (keyword, category, rationale, weight, active) VALUES (?, ?, ?, ?, 1)',
    );
    for (const kw of SEED_KEYWORDS) {
      insertKw.run(kw.keyword, kw.category, kw.rationale, kw.weight);
    }
  }

  const feedCountRow = db.prepare('SELECT COUNT(*) AS cnt FROM threat_feeds').get() as { cnt: number };
  if (feedCountRow.cnt === 0) {
    const now = new Date().toISOString();
    const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
    const insertFeed = db.prepare(
      `INSERT OR IGNORE INTO threat_feeds
       (normalized_url, domain, threat_category, source, verification_status, first_seen, last_seen, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const item of SEED_TEST_INDICATORS) {
      insertFeed.run(
        item.normalizedUrl,
        item.domain,
        item.threatCategory,
        item.source,
        item.verificationStatus,
        now,
        now,
        expires,
      );
    }
  }
}

export function saveAnalysis(report: AnalysisReport, db = getDatabase()): void {
  const stmt = db.prepare(`
    INSERT INTO analyses (
      id, submitted_url, normalized_url, domain, risk_score, risk_level,
      verdict, in_threat_db, ml_confidence, report_json, analyzed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    report.id,
    report.submittedUrl,
    report.normalizedUrl,
    report.domain,
    report.riskScore,
    report.riskLevel,
    report.verdict,
    report.inKnownThreatDatabase ? 1 : 0,
    report.mlPrediction.confidence,
    JSON.stringify(report),
    report.analyzedAt,
  );
}

export function getAnalysisById(id: string, db = getDatabase()): AnalysisReport | null {
  const row = db
    .prepare('SELECT report_json FROM analyses WHERE id = ?')
    .get(id) as { report_json: string } | undefined;
  if (!row) return null;
  try {
    return JSON.parse(row.report_json) as AnalysisReport;
  } catch {
    return null;
  }
}

export function getRecentScans(limit = 20, db = getDatabase()): RecentScanItem[] {
  const safeLimit = Math.max(1, Math.min(100, Math.floor(limit)));
  const rows = db
    .prepare(
      `SELECT id, normalized_url, domain, risk_score, risk_level, verdict, in_threat_db, ml_confidence, analyzed_at
       FROM analyses
       ORDER BY analyzed_at DESC
       LIMIT ?`,
    )
    .all(safeLimit) as Array<{
    id: string;
    normalized_url: string;
    domain: string;
    risk_score: number;
    risk_level: RecentScanItem['riskLevel'];
    verdict: RecentScanItem['verdict'];
    in_threat_db: number;
    ml_confidence: number;
    analyzed_at: string;
  }>;

  return rows.map((r) => ({
    id: r.id,
    normalizedUrl: r.normalized_url,
    domain: r.domain,
    riskScore: r.risk_score,
    riskLevel: r.risk_level,
    verdict: r.verdict,
    inKnownThreatDatabase: r.in_threat_db === 1,
    mlConfidence: r.ml_confidence,
    analyzedAt: r.analyzed_at,
  }));
}

export function getStatsSummary(db = getDatabase()): StatsSummary {
  const counts = db
    .prepare(
      `SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN verdict = 'Malicious / Phishing' THEN 1 ELSE 0 END) AS malicious,
        SUM(CASE WHEN verdict = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious,
        SUM(CASE WHEN verdict = 'No Known Threat Detected' THEN 1 ELSE 0 END) AS clean,
        SUM(CASE WHEN verdict = 'Unknown / Unable to Verify' THEN 1 ELSE 0 END) AS unknown,
        SUM(CASE WHEN in_threat_db = 1 THEN 1 ELSE 0 END) AS intelMatches
       FROM analyses`,
    )
    .get() as {
    total: number;
    malicious: number | null;
    suspicious: number | null;
    clean: number | null;
    unknown: number | null;
    intelMatches: number | null;
  };

  const nowIso = new Date().toISOString();
  const feedRow = db
    .prepare('SELECT COUNT(*) AS cnt FROM threat_feeds WHERE expires_at > ?')
    .get(nowIso) as { cnt: number };

  const reportRow = db
    .prepare("SELECT COUNT(*) AS cnt FROM user_reports WHERE status = 'unverified'")
    .get() as { cnt: number };

  return {
    totalAnalyzed: counts.total ?? 0,
    maliciousDetected: counts.malicious ?? 0,
    suspiciousDetected: counts.suspicious ?? 0,
    noKnownThreat: counts.clean ?? 0,
    unableToVerify: counts.unknown ?? 0,
    threatIntelMatches: counts.intelMatches ?? 0,
    activeFeedIndicators: feedRow.cnt ?? 0,
    pendingUserReports: reportRow.cnt ?? 0,
  };
}

export function getActiveKeywords(db = getDatabase()): KeywordRecord[] {
  const rows = db
    .prepare('SELECT id, keyword, category, rationale, weight, active FROM keywords WHERE active = 1 ORDER BY weight DESC, keyword ASC')
    .all() as Array<{
    id: number;
    keyword: string;
    category: string;
    rationale: string;
    weight: number;
    active: number;
  }>;

  return rows.map((r) => ({
    id: r.id,
    keyword: r.keyword,
    category: r.category,
    rationale: r.rationale,
    weight: r.weight,
    active: r.active === 1,
  }));
}

export function upsertKeyword(
  payload: { keyword: string; category: string; rationale: string; weight: number },
  db = getDatabase(),
): KeywordRecord {
  const cleanKw = payload.keyword.trim().toLowerCase();
  const cleanCat = payload.category.trim();
  const cleanRat = payload.rationale.trim();
  const safeWeight = Math.max(1, Math.min(10, Math.round(payload.weight)));

  db.prepare(
    `INSERT INTO keywords (keyword, category, rationale, weight, active)
     VALUES (?, ?, ?, ?, 1)
     ON CONFLICT(keyword) DO UPDATE SET
       category = excluded.category,
       rationale = excluded.rationale,
       weight = excluded.weight,
       active = 1`,
  ).run(cleanKw, cleanCat, cleanRat, safeWeight);

  const row = db
    .prepare('SELECT id, keyword, category, rationale, weight, active FROM keywords WHERE keyword = ?')
    .get(cleanKw) as {
    id: number;
    keyword: string;
    category: string;
    rationale: string;
    weight: number;
    active: number;
  };

  return {
    id: row.id,
    keyword: row.keyword,
    category: row.category,
    rationale: row.rationale,
    weight: row.weight,
    active: row.active === 1,
  };
}

export function lookupLocalThreatIndicator(
  normalizedUrl: string,
  domain: string,
  db = getDatabase(),
): ThreatIndicatorRecord | null {
  const nowIso = new Date().toISOString();
  const exact = db
    .prepare(
      `SELECT id, normalized_url, domain, threat_category, source, verification_status, first_seen, last_seen
       FROM threat_feeds
       WHERE normalized_url = ? AND expires_at > ?
       LIMIT 1`,
    )
    .get(normalizedUrl, nowIso) as
    | {
        id: number;
        normalized_url: string;
        domain: string;
        threat_category: string;
        source: string;
        verification_status: string;
        first_seen: string;
        last_seen: string;
      }
    | undefined;

  if (exact) {
    return {
      id: exact.id,
      normalizedUrl: exact.normalized_url,
      domain: exact.domain,
      threatCategory: exact.threat_category,
      source: exact.source,
      verificationStatus: exact.verification_status,
      firstSeen: exact.first_seen,
      lastSeen: exact.last_seen,
    };
  }

  return null;
}

export function listThreatIndicators(limit = 50, db = getDatabase()): ThreatIndicatorRecord[] {
  const nowIso = new Date().toISOString();
  const safeLimit = Math.max(1, Math.min(200, Math.floor(limit)));
  const rows = db
    .prepare(
      `SELECT id, normalized_url, domain, threat_category, source, verification_status, first_seen, last_seen
       FROM threat_feeds
       WHERE expires_at > ?
       ORDER BY last_seen DESC
       LIMIT ?`,
    )
    .all(nowIso, safeLimit) as Array<{
    id: number;
    normalized_url: string;
    domain: string;
    threat_category: string;
    source: string;
    verification_status: string;
    first_seen: string;
    last_seen: string;
  }>;

  return rows.map((r) => ({
    id: r.id,
    normalizedUrl: r.normalized_url,
    domain: r.domain,
    threatCategory: r.threat_category,
    source: r.source,
    verificationStatus: r.verification_status,
    firstSeen: r.first_seen,
    lastSeen: r.last_seen,
  }));
}

export function upsertThreatIndicators(
  records: Array<{
    normalizedUrl: string;
    domain: string;
    threatCategory: string;
    source: string;
    verificationStatus: string;
    ttlDays?: number;
  }>,
  db = getDatabase(),
): { insertedOrUpdated: number; skippedDuplicates: number } {
  const now = new Date();
  const nowIso = now.toISOString();
  let insertedOrUpdated = 0;
  let skippedDuplicates = 0;

  const seenInBatch = new Set<string>();
  const stmt = db.prepare(`
    INSERT INTO threat_feeds (
      normalized_url, domain, threat_category, source, verification_status, first_seen, last_seen, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(normalized_url) DO UPDATE SET
      last_seen = excluded.last_seen,
      expires_at = excluded.expires_at,
      threat_category = excluded.threat_category
  `);

  for (const rec of records) {
    if (seenInBatch.has(rec.normalizedUrl)) {
      skippedDuplicates++;
      continue;
    }
    seenInBatch.add(rec.normalizedUrl);
    const ttlDays = rec.ttlDays ?? 30;
    const expiresIso = new Date(now.getTime() + ttlDays * 24 * 60 * 60 * 1000).toISOString();
    stmt.run(
      rec.normalizedUrl,
      rec.domain,
      rec.threatCategory,
      rec.source,
      rec.verificationStatus,
      nowIso,
      nowIso,
      expiresIso,
    );
    insertedOrUpdated++;
  }

  return { insertedOrUpdated, skippedDuplicates };
}

export function purgeExpiredIndicators(db = getDatabase()): number {
  const nowIso = new Date().toISOString();
  const res = db.prepare('DELETE FROM threat_feeds WHERE expires_at <= ?').run(nowIso);
  return Number(res.changes ?? 0);
}

export function saveUserReport(report: UserReportRecord, db = getDatabase()): void {
  // User-submitted reports always start as 'unverified' and never directly enter threat_feeds
  db.prepare(
    `INSERT INTO user_reports (id, submitted_url, normalized_url, domain, reason, status, created_at)
     VALUES (?, ?, ?, ?, ?, 'unverified', ?)`,
  ).run(
    report.id,
    report.submittedUrl,
    report.normalizedUrl,
    report.domain,
    report.reason,
    report.createdAt,
  );
}

export function listUserReports(limit = 30, db = getDatabase()): UserReportRecord[] {
  const safeLimit = Math.max(1, Math.min(100, Math.floor(limit)));
  const rows = db
    .prepare(
      `SELECT id, submitted_url, normalized_url, domain, reason, status, created_at
       FROM user_reports
       ORDER BY created_at DESC
       LIMIT ?`,
    )
    .all(safeLimit) as Array<{
    id: string;
    submitted_url: string;
    normalized_url: string;
    domain: string;
    reason: string;
    status: UserReportRecord['status'];
    created_at: string;
  }>;

  return rows.map((r) => ({
    id: r.id,
    submittedUrl: r.submitted_url,
    normalizedUrl: r.normalized_url,
    domain: r.domain,
    reason: r.reason,
    status: r.status,
    createdAt: r.created_at,
  }));
}

export function logFeedSync(
  source: string,
  status: string,
  recordsIngested: number,
  message: string,
  db = getDatabase(),
): void {
  db.prepare(
    `INSERT INTO feed_sync_logs (source, status, records_ingested, message, synced_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(source, status, recordsIngested, message, new Date().toISOString());
}
