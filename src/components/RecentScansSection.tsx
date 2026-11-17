import { useState } from 'react';
import { AlertTriangle, HelpCircle, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { DetectionVerdict, RecentScanItem, StatsSummary } from '../../shared/types';

interface RecentScansSectionProps {
  summary: StatsSummary | null;
  recentScans: RecentScanItem[];
  onSelectScan: (id: string) => void;
}

function getVerdictBadge(verdict: DetectionVerdict) {
  switch (verdict) {
    case 'Malicious / Phishing':
      return { icon: ShieldAlert, text: 'text-red-700', label: 'Malicious / Phishing' };
    case 'Suspicious':
      return { icon: AlertTriangle, text: 'text-amber-700', label: 'Suspicious' };
    case 'No Known Threat Detected':
      return { icon: ShieldCheck, text: 'text-emerald-700', label: 'No Known Threat' };
    default:
      return { icon: HelpCircle, text: 'text-slate-600', label: 'Unable to Verify' };
  }
}

export function RecentScansSection({
  summary,
  recentScans,
  onSelectScan,
}: RecentScansSectionProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<'all' | DetectionVerdict>('all');

  const filteredScans = recentScans.filter((item) => {
    const matchesSearch =
      !searchTerm.trim() ||
      item.normalizedUrl.toLowerCase().includes(searchTerm.trim().toLowerCase()) ||
      item.domain.toLowerCase().includes(searchTerm.trim().toLowerCase());
    const matchesVerdict = verdictFilter === 'all' || item.verdict === verdictFilter;
    return matchesSearch && matchesVerdict;
  });

  return (
    <div className="space-y-6">
      {/* Threat Statistics Strip */}
      {summary && (
        <section aria-label="Threat detection statistics" className="rounded-xl border border-slate-200 bg-white">
          <div className="grid grid-cols-2 divide-y divide-slate-200 sm:grid-cols-3 lg:grid-cols-5 sm:divide-y-0 sm:divide-x">
            <div className="px-5 py-4">
              <div className="text-xs font-medium text-slate-500">Total URLs Analyzed</div>
              <div className="mt-1 text-2xl font-bold font-mono tabular-nums text-slate-900">
                {summary.totalAnalyzed}
              </div>
            </div>
            <div className="px-5 py-4">
              <div className="text-xs font-medium text-slate-500">Malicious Detected</div>
              <div className="mt-1 text-2xl font-bold font-mono tabular-nums text-red-700">
                {summary.maliciousDetected}
              </div>
            </div>
            <div className="px-5 py-4">
              <div className="text-xs font-medium text-slate-500">Suspicious Detected</div>
              <div className="mt-1 text-2xl font-bold font-mono tabular-nums text-amber-700">
                {summary.suspiciousDetected}
              </div>
            </div>
            <div className="px-5 py-4">
              <div className="text-xs font-medium text-slate-500">No Known Threat</div>
              <div className="mt-1 text-2xl font-bold font-mono tabular-nums text-emerald-700">
                {summary.noKnownThreat}
              </div>
            </div>
            <div className="px-5 py-4 col-span-2 sm:col-span-1">
              <div className="text-xs font-medium text-slate-500">Threat Intel Matches</div>
              <div className="mt-1 text-2xl font-bold font-mono tabular-nums text-slate-900">
                {summary.threatIntelMatches}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Recent Scans Table */}
      <section aria-label="Recent URL scans" className="rounded-xl border border-slate-200 bg-white">
        <div className="flex flex-col gap-3 border-b border-slate-200 px-6 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-900">Recent Scans</h2>
            <p className="text-xs text-slate-500">
              Select any scan row to inspect its full evidence report.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400"
                aria-hidden="true"
              />
              <input
                type="search"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                aria-label="Filter recent scans by URL or domain"
                placeholder="Filter domain or URL..."
                className="w-52 rounded-lg border border-slate-300 bg-white py-1.5 pl-8 pr-3 text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none"
              />
            </div>

            <div className="flex items-center gap-1 rounded-lg bg-slate-100 p-1">
              {(
                [
                  { id: 'all', label: 'All' },
                  { id: 'Malicious / Phishing', label: 'Malicious' },
                  { id: 'Suspicious', label: 'Suspicious' },
                  { id: 'No Known Threat Detected', label: 'No Threat' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setVerdictFilter(tab.id)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                    verdictFilter === tab.id
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {filteredScans.length === 0 ? (
          <div className="px-6 py-10 text-center text-sm text-slate-500">
            No matching URL scans found. Submit a URL above to run a new analysis.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50/60 text-xs font-medium text-slate-500">
                  <th className="px-6 py-2.5">Scanned URL</th>
                  <th className="px-4 py-2.5">Verdict</th>
                  <th className="px-4 py-2.5 text-right">Risk Score</th>
                  <th className="px-4 py-2.5 text-right">ML Confidence</th>
                  <th className="px-6 py-2.5 text-right">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredScans.map((scan) => {
                  const badge = getVerdictBadge(scan.verdict);
                  const Icon = badge.icon;
                  return (
                    <tr key={scan.id} className="hover:bg-slate-50 transition-colors">
                      <td className="px-6 py-3 max-w-md">
                        <button
                          type="button"
                          onClick={() => onSelectScan(scan.id)}
                          className="text-left font-mono text-xs text-slate-900 hover:text-blue-700 hover:underline truncate block max-w-md focus-visible:outline-2 focus-visible:outline-blue-700"
                        >
                          {scan.normalizedUrl}
                        </button>
                        <span className="text-xs text-slate-500">{scan.domain}</span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${badge.text}`}>
                          <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                          <span>{badge.label}</span>
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-xs font-semibold tabular-nums text-slate-900">
                        {scan.riskScore}/100
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-xs tabular-nums text-slate-600">
                        {scan.mlConfidence}%
                      </td>
                      <td className="px-6 py-3 text-right font-mono text-xs tabular-nums text-slate-500 whitespace-nowrap">
                        {new Date(scan.analyzedAt).toLocaleString()}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
