import type {
  AnalysisReport,
  DetectionVerdict,
  EvidenceFinding,
  RecentScanItem,
  UserReportRecord,
} from '../../shared/types';

export interface VerdictPresentation {
  label: string;
  shortLabel: string;
  badgeSurface: string;
  textColor: string;
  barColor: string;
  ringStroke: string;
  softPanel: string;
  tone: 'danger' | 'warning' | 'safe' | 'neutral';
}

export function getVerdictPresentation(verdict: DetectionVerdict): VerdictPresentation {
  switch (verdict) {
    case 'Confirmed Malicious':
      return {
        label: 'Confirmed Malicious',
        shortLabel: 'Malicious',
        badgeSurface: 'bg-red-50 border-red-200 text-red-800',
        textColor: 'text-red-700',
        barColor: 'bg-red-600',
        ringStroke: '#DC2626',
        softPanel: 'bg-red-50/60 border-red-200',
        tone: 'danger',
      };
    case 'High Risk':
      return {
        label: 'High Risk',
        shortLabel: 'High Risk',
        badgeSurface: 'bg-red-50 border-red-200 text-red-700',
        textColor: 'text-red-600',
        barColor: 'bg-red-500',
        ringStroke: '#EF4444',
        softPanel: 'bg-red-50/50 border-red-200',
        tone: 'danger',
      };
    case 'Suspicious':
      return {
        label: 'Suspicious',
        shortLabel: 'Suspicious',
        badgeSurface: 'bg-amber-50 border-amber-200 text-amber-800',
        textColor: 'text-amber-700',
        barColor: 'bg-amber-500',
        ringStroke: '#D97706',
        softPanel: 'bg-amber-50/60 border-amber-200',
        tone: 'warning',
      };
    case 'No Known Threat':
      return {
        label: 'No Known Threat',
        shortLabel: 'No Threat',
        badgeSurface: 'bg-emerald-50 border-emerald-200 text-emerald-800',
        textColor: 'text-emerald-700',
        barColor: 'bg-emerald-600',
        ringStroke: '#059669',
        softPanel: 'bg-emerald-50/50 border-emerald-200',
        tone: 'safe',
      };
    default:
      return {
        label: 'Unable to Verify',
        shortLabel: 'Unverified',
        badgeSurface: 'bg-slate-100 border-slate-300 text-slate-700',
        textColor: 'text-slate-600',
        barColor: 'bg-slate-500',
        ringStroke: '#64748B',
        softPanel: 'bg-slate-50 border-slate-200',
        tone: 'neutral',
      };
  }
}

export function deriveDetectionSource(
  scan: RecentScanItem,
  report?: AnalysisReport,
): string {
  if (report) {
    const sources: string[] = [];
    if (report.inKnownThreatDatabase || report.scoringBreakdown.threatIntelPoints > 0) {
      sources.push('Threat Intel');
    }
    if ((report.scoringBreakdown.brandImpersonationPoints ?? 0) > 0) {
      sources.push('Brand Pattern');
    }
    if (report.scoringBreakdown.structuralPoints > 0 || report.scoringBreakdown.keywordPoints > 0) {
      sources.push('URL Structure');
    }
    if (report.mlPrediction.label === 'phishing' && report.scoringBreakdown.mlPoints > 0) {
      sources.push('ML Model');
    }
    if (sources.length > 0) {
      return sources.slice(0, 2).join(' + ');
    }
    return 'Hybrid Engine (Clean)';
  }

  if (scan.inKnownThreatDatabase) {
    return 'Threat Intel + ML';
  }
  if (scan.verdict === 'No Known Threat') {
    return 'Hybrid Pipeline';
  }
  return 'ML + Pattern Engine';
}

export interface BreakdownBucket {
  id: string;
  label: string;
  count: number;
  sharePct: number;
  tone: 'danger' | 'warning' | 'info' | 'neutral';
}

function classifyFindingCategory(finding: EvidenceFinding): string {
  const cat = `${finding.category} ${finding.pattern}`.toLowerCase();
  if (finding.source === 'Threat Intelligence' || cat.includes('threat')) {
    return 'Threat Intel Matches';
  }
  if (
    finding.source === 'Brand Impersonation' ||
    cat.includes('brand') ||
    cat.includes('lookalike') ||
    cat.includes('homoglyph') ||
    cat.includes('punycode')
  ) {
    return 'Brand & Lookalike';
  }
  if (cat.includes('redirect') || cat.includes('nested')) {
    return 'Redirect Manipulation';
  }
  if (cat.includes('encoding') || cat.includes('obfuscation') || cat.includes('credential mask')) {
    return 'URL Obfuscation';
  }
  if (cat.includes('subdomain') || cat.includes('port') || cat.includes('domain') || cat.includes('structure')) {
    return 'Structural Anomalies';
  }
  if (cat.includes('keyword')) {
    return 'Phishing Keywords';
  }
  return 'ML Risk Signals';
}

export function computeDetectionBreakdown(reports: AnalysisReport[]): {
  buckets: BreakdownBucket[];
  inspectedCount: number;
  totalFindings: number;
} {
  const counts = new Map<string, number>([
    ['Brand & Lookalike', 0],
    ['Threat Intel Matches', 0],
    ['Redirect Manipulation', 0],
    ['URL Obfuscation', 0],
    ['Structural Anomalies', 0],
    ['Phishing Keywords', 0],
  ]);

  let totalFindings = 0;

  for (const report of reports) {
    const seenCategoriesForReport = new Set<string>();
    if (report.inKnownThreatDatabase) {
      seenCategoriesForReport.add('Threat Intel Matches');
      counts.set('Threat Intel Matches', (counts.get('Threat Intel Matches') ?? 0) + 1);
      totalFindings += 1;
    }
    for (const finding of report.evidenceFindings ?? []) {
      const bucket = classifyFindingCategory(finding);
      if (!seenCategoriesForReport.has(bucket)) {
        seenCategoriesForReport.add(bucket);
        counts.set(bucket, (counts.get(bucket) ?? 0) + 1);
        totalFindings += 1;
      }
    }
  }

  const maxCount = Math.max(1, ...Array.from(counts.values()));
  const buckets: BreakdownBucket[] = Array.from(counts.entries())
    .map(([label, count]) => ({
      id: label.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      label,
      count,
      sharePct: count > 0 ? Math.round((count / maxCount) * 100) : 0,
      tone:
        label === 'Threat Intel Matches' || label === 'Brand & Lookalike'
          ? ('danger' as const)
          : label === 'Redirect Manipulation' || label === 'URL Obfuscation'
            ? ('warning' as const)
            : ('info' as const),
    }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));

  return {
    buckets,
    inspectedCount: reports.length,
    totalFindings,
  };
}

export interface ActivityEvent {
  id: string;
  scanId?: string;
  title: string;
  detail: string;
  timestamp: string;
  tone: 'danger' | 'warning' | 'safe' | 'info';
}

export function buildRecentSecurityActivity(
  recentScans: RecentScanItem[],
  pendingReports: UserReportRecord[],
): ActivityEvent[] {
  const scanEvents: ActivityEvent[] = recentScans.slice(0, 6).map((scan) => {
    const tone: ActivityEvent['tone'] =
      scan.verdict === 'Confirmed Malicious' || scan.verdict === 'High Risk'
        ? 'danger'
        : scan.verdict === 'Suspicious'
          ? 'warning'
          : scan.verdict === 'No Known Threat'
            ? 'safe'
            : 'info';

    return {
      id: `scan-${scan.id}`,
      scanId: scan.id,
      title: `${scan.verdict} · ${scan.domain}`,
      detail: scan.inKnownThreatDatabase
        ? `Risk ${scan.riskScore}/100 · Matched threat intelligence`
        : `Risk ${scan.riskScore}/100 · ML confidence ${scan.mlConfidence}%`,
      timestamp: scan.analyzedAt,
      tone,
    };
  });

  const reportEvents: ActivityEvent[] = pendingReports.slice(0, 3).map((rep) => ({
    id: `report-${rep.id}`,
    title: `Community Report · ${rep.domain}`,
    detail: `Queued as ${rep.status}: ${rep.reason}`,
    timestamp: rep.createdAt,
    tone: 'info',
  }));

  return [...scanEvents, ...reportEvents]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 7);
}
