import type {
  AnalysisReport,
  KeywordRecord,
  ModelEvaluationReport,
  RecentScanItem,
  StatsSummary,
  ThreatIndicatorRecord,
  UserReportRecord,
} from '../../shared/types';
import {
  getStandaloneAnalysisById,
  getStandaloneHealth,
  getStandaloneKeywords,
  getStandaloneModelEvaluation,
  getStandaloneStatsAndRecent,
  getStandaloneThreatFeeds,
  runStandaloneAnalysis,
  submitStandaloneReport,
} from '../standalone/engine';

export interface HealthResponse {
  status: string;
  timestamp: string;
  mlEngine: {
    loaded: boolean;
    version: string;
    externalServiceConfigured: boolean;
  };
  websiteInspectionEnabled: boolean;
  threatIntelProviders: Array<{
    name: string;
    configured: boolean;
    mode: string;
  }>;
}

const FORCE_STANDALONE = import.meta.env.VITE_STANDALONE_MODE === 'true';

// Memoized detection of whether a live Express /api backend is reachable
let backendAvailableCache: boolean | null = FORCE_STANDALONE ? false : null;

async function hasLiveBackend(): Promise<boolean> {
  if (FORCE_STANDALONE) return false;
  if (backendAvailableCache !== null) return backendAvailableCache;

  try {
    const resp = await fetch('./api/health', { method: 'GET' });
    const contentType = resp.headers.get('content-type') || '';
    if (resp.ok && contentType.includes('application/json')) {
      backendAvailableCache = true;
      return true;
    }
  } catch {
    // Static hosting (GitHub Pages, file server, etc.) has no /api server
  }
  backendAvailableCache = false;
  return false;
}

export async function isStandaloneStaticMode(): Promise<boolean> {
  return !(await hasLiveBackend());
}

export async function analyzeUrl(url: string): Promise<AnalysisReport> {
  if (await hasLiveBackend()) {
    const resp = await fetch('./api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Failed to analyze URL.');
    }
    return data as AnalysisReport;
  }

  return runStandaloneAnalysis(url, { persist: true });
}

export async function fetchAnalysisById(id: string): Promise<AnalysisReport> {
  if (await hasLiveBackend()) {
    const resp = await fetch(`./api/analyze/${encodeURIComponent(id)}`);
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Failed to retrieve analysis record.');
    }
    return data as AnalysisReport;
  }

  return getStandaloneAnalysisById(id);
}

export async function fetchStatsAndRecent(limit = 15): Promise<{
  summary: StatsSummary;
  recentScans: RecentScanItem[];
}> {
  if (await hasLiveBackend()) {
    const resp = await fetch(`./api/stats?limit=${limit}`);
    if (!resp.ok) {
      throw new Error('Failed to load threat statistics.');
    }
    return resp.json();
  }

  return getStandaloneStatsAndRecent(limit);
}

export async function fetchHealth(): Promise<HealthResponse> {
  if (await hasLiveBackend()) {
    const resp = await fetch('./api/health');
    if (!resp.ok) {
      throw new Error('Failed to load system health.');
    }
    return resp.json();
  }

  return getStandaloneHealth();
}

export async function submitUserReport(
  url: string,
  reason: string,
): Promise<{ message: string; report: UserReportRecord }> {
  if (await hasLiveBackend()) {
    const resp = await fetch('./api/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, reason }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Failed to submit URL report.');
    }
    return data;
  }

  return submitStandaloneReport(url, reason);
}

export async function fetchKeywords(): Promise<{ keywords: KeywordRecord[] }> {
  if (await hasLiveBackend()) {
    const resp = await fetch('./api/keywords');
    if (!resp.ok) {
      throw new Error('Failed to load keyword database.');
    }
    return resp.json();
  }

  return getStandaloneKeywords();
}

export async function fetchThreatFeeds(): Promise<{
  indicators: ThreatIndicatorRecord[];
  pendingReports: UserReportRecord[];
}> {
  if (await hasLiveBackend()) {
    const resp = await fetch('./api/threat-feeds');
    if (!resp.ok) {
      throw new Error('Failed to load threat feed records.');
    }
    return resp.json();
  }

  return getStandaloneThreatFeeds();
}

export async function fetchModelEvaluation(): Promise<ModelEvaluationReport> {
  if (await hasLiveBackend()) {
    const resp = await fetch('./api/model/evaluation');
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Failed to load model evaluation.');
    }
    return data as ModelEvaluationReport;
  }

  return getStandaloneModelEvaluation();
}
