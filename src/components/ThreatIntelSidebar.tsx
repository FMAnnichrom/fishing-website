import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Clock,
  Database,
  HelpCircle,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { AnalysisReport, RecentScanItem, UserReportRecord } from '../../shared/types';
import type { HealthResponse } from '../services/api';
import {
  buildRecentSecurityActivity,
  computeDetectionBreakdown,
} from '../utils/dashboardHelpers';

interface ThreatIntelSidebarProps {
  health: HealthResponse | null;
  healthLoading: boolean;
  recentScans: RecentScanItem[];
  inspectedReports: AnalysisReport[];
  pendingReports: UserReportRecord[];
  onSelectScan: (id: string) => void;
  onOpenThreatIntelTab: () => void;
}

export function ThreatIntelSidebar({
  health,
  healthLoading,
  recentScans,
  inspectedReports,
  pendingReports,
  onSelectScan,
  onOpenThreatIntelTab,
}: ThreatIntelSidebarProps) {
  const breakdown = computeDetectionBreakdown(inspectedReports);
  const activity = buildRecentSecurityActivity(recentScans, pendingReports);

  return (
    <aside aria-label="Threat intelligence summary" className="space-y-6">
      {/* 1. Threat Intelligence Sources */}
      <section className="rounded-xl border border-[#E2E8F0] bg-white p-5 shadow-xs">
        <div className="flex items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-[#2563EB]" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-[#111827]">Threat Intelligence Sources</h2>
          </div>
          <button
            type="button"
            onClick={onOpenThreatIntelTab}
            className="text-xs font-medium text-[#2563EB] hover:underline whitespace-nowrap shrink-0"
          >
            View Feeds
          </button>
        </div>

        {healthLoading ? (
          <div className="mt-3 space-y-2.5" aria-hidden="true">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-10 animate-pulse rounded-lg bg-slate-100" />
            ))}
          </div>
        ) : health ? (
          <ul className="mt-3 divide-y divide-slate-100">
            {health.threatIntelProviders.map((provider) => (
              <li key={provider.name} className="py-2.5 first:pt-0 last:pb-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-[#111827] truncate">
                    {provider.name}
                  </span>
                  {provider.configured ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-700 shrink-0">
                      <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>Configured</span>
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[#64748B] shrink-0">
                      <HelpCircle className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>Not Configured</span>
                    </span>
                  )}
                </div>
                <div className="mt-0.5 text-[11px] text-[#64748B]">{provider.mode}</div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-3 text-xs text-[#64748B]">
            Provider configuration status could not be loaded.
          </p>
        )}
      </section>

      {/* 2. Detection Breakdown (Aggregated strictly from loaded real AnalysisReports) */}
      <section className="rounded-xl border border-[#E2E8F0] bg-white p-5 shadow-xs">
        <div className="flex items-center justify-between gap-2 border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-[#2563EB]" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-[#111827]">Detection Breakdown</h2>
          </div>
          <span className="font-mono text-[11px] tabular-nums text-[#64748B]">
            {breakdown.inspectedCount} report{breakdown.inspectedCount === 1 ? '' : 's'}
          </span>
        </div>

        {breakdown.inspectedCount === 0 ? (
          <p className="mt-3 text-xs leading-relaxed text-[#64748B]">
            Run a URL analysis or select a scan record to summarize real signal categories across
            inspected reports.
          </p>
        ) : (
          <div className="mt-3.5 space-y-3">
            {breakdown.buckets.map((bucket) => {
              const barColor =
                bucket.tone === 'danger'
                  ? 'bg-red-500'
                  : bucket.tone === 'warning'
                    ? 'bg-amber-500'
                    : 'bg-[#2563EB]';
              return (
                <div key={bucket.id}>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-[#111827] font-medium">{bucket.label}</span>
                    <span className="font-mono tabular-nums text-[#64748B]">
                      {bucket.count} scan{bucket.count === 1 ? '' : 's'}
                    </span>
                  </div>
                  <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
                    <div
                      className={`h-full rounded-full transition-all duration-300 ${
                        bucket.count > 0 ? barColor : 'bg-transparent'
                      }`}
                      style={{ width: bucket.count > 0 ? `${Math.max(8, bucket.sharePct)}%` : '0%' }}
                    />
                  </div>
                </div>
              );
            })}
            <p className="pt-1 text-[11px] text-[#64748B]">
              Counts reflect distinct evidence categories observed in loaded scan reports.
            </p>
          </div>
        )}
      </section>

      {/* 3. Recent Security Activity (Real scans & reports only) */}
      <section className="rounded-xl border border-[#E2E8F0] bg-white p-5 shadow-xs">
        <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
          <Clock className="h-4 w-4 text-[#2563EB]" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-[#111827]">Recent Security Activity</h2>
        </div>

        {activity.length === 0 ? (
          <p className="mt-3 text-xs text-[#64748B]">
            No scan activity recorded yet. Submit a URL above to begin monitoring.
          </p>
        ) : (
          <ul className="mt-3 space-y-3">
            {activity.map((ev) => {
              const Icon =
                ev.tone === 'danger'
                  ? ShieldAlert
                  : ev.tone === 'warning'
                    ? AlertTriangle
                    : ev.tone === 'safe'
                      ? ShieldCheck
                      : Database;
              const iconColor =
                ev.tone === 'danger'
                  ? 'text-red-600'
                  : ev.tone === 'warning'
                    ? 'text-amber-600'
                    : ev.tone === 'safe'
                      ? 'text-emerald-600'
                      : 'text-[#2563EB]';

              return (
                <li key={ev.id} className="flex items-start gap-2.5 text-xs">
                  <Icon className={`h-4 w-4 mt-0.5 shrink-0 ${iconColor}`} aria-hidden="true" />
                  <div className="min-w-0 flex-1">
                    {ev.scanId ? (
                      <button
                        type="button"
                        onClick={() => onSelectScan(ev.scanId!)}
                        className="text-left font-medium text-[#111827] hover:text-[#2563EB] hover:underline truncate block w-full"
                      >
                        {ev.title}
                      </button>
                    ) : (
                      <div className="font-medium text-[#111827] truncate">{ev.title}</div>
                    )}
                    <div className="mt-0.5 text-[11px] text-[#64748B] truncate">{ev.detail}</div>
                    <time
                      dateTime={ev.timestamp}
                      className="mt-0.5 block font-mono text-[10px] tabular-nums text-slate-400"
                    >
                      {new Date(ev.timestamp).toLocaleString()}
                    </time>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </aside>
  );
}
