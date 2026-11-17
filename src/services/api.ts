import type {
  AnalysisReport,
  KeywordRecord,
  ModelEvaluationReport,
  RecentScanItem,
  StatsSummary,
  ThreatIndicatorRecord,
  UserReportRecord,
} from '../../shared/types';

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

export async function analyzeUrl(url: string): Promise<AnalysisReport> {
  const resp = await fetch('/api/analyze', {
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

export async function fetchAnalysisById(id: string): Promise<AnalysisReport> {
  const resp = await fetch(`/api/analyze/${encodeURIComponent(id)}`);
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error || 'Failed to retrieve analysis record.');
  }
  return data as AnalysisReport;
}

export async function fetchStatsAndRecent(limit = 15): Promise<{
  summary: StatsSummary;
  recentScans: RecentScanItem[];
}> {
  const resp = await fetch(`/api/stats?limit=${limit}`);
  if (!resp.ok) {
    throw new Error('Failed to load threat statistics.');
  }
  return resp.json();
}

export async function fetchHealth(): Promise<HealthResponse> {
  const resp = await fetch('/api/health');
  if (!resp.ok) {
    throw new Error('Failed to load system health.');
  }
  return resp.json();
}

export async function submitUserReport(
  url: string,
  reason: string,
): Promise<{ message: string; report: UserReportRecord }> {
  const resp = await fetch('/api/reports', {
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

export async function fetchKeywords(): Promise<{ keywords: KeywordRecord[] }> {
  const resp = await fetch('/api/keywords');
  if (!resp.ok) {
    throw new Error('Failed to load keyword database.');
  }
  return resp.json();
}

export async function fetchThreatFeeds(): Promise<{
  indicators: ThreatIndicatorRecord[];
  pendingReports: UserReportRecord[];
}> {
  const resp = await fetch('/api/threat-feeds');
  if (!resp.ok) {
    throw new Error('Failed to load threat feed records.');
  }
  return resp.json();
}

export async function fetchModelEvaluation(): Promise<ModelEvaluationReport> {
  const resp = await fetch('/api/model/evaluation');
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error || 'Failed to load model evaluation.');
  }
  return data as ModelEvaluationReport;
}
