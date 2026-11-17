import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  HelpCircle,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from 'lucide-react';
import type {
  AnalysisReport,
  DetectionVerdict,
  RecentScanItem,
} from '../../shared/types';
import {
  deriveDetectionSource,
  getVerdictPresentation,
} from '../utils/dashboardHelpers';

interface RecentScansSectionProps {
  recentScans: RecentScanItem[];
  reportsById?: Record<string, AnalysisReport>;
  selectedScanId?: string;
  onSelectScan: (id: string) => void;
  pageSize?: number;
  title?: string;
  subtitle?: string;
}

type VerdictFilterId = 'all' | 'malicious_high' | 'Suspicious' | 'No Known Threat';
type SortField = 'analyzedAt' | 'riskScore' | 'mlConfidence' | 'domain' | 'verdict';
type SortDirection = 'asc' | 'desc';

function getVerdictIcon(verdict: DetectionVerdict) {
  switch (verdict) {
    case 'Confirmed Malicious':
      return ShieldX;
    case 'High Risk':
      return ShieldAlert;
    case 'Suspicious':
      return AlertTriangle;
    case 'No Known Threat':
      return ShieldCheck;
    default:
      return HelpCircle;
  }
}

export function RecentScansSection({
  recentScans,
  reportsById = {},
  selectedScanId,
  onSelectScan,
  pageSize = 10,
  title = 'Recent URL Scans',
  subtitle = 'Click any row to open its full security investigation report.',
}: RecentScansSectionProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilterId>('all');
  const [domainFilter, setDomainFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('analyzedAt');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [currentPage, setCurrentPage] = useState(1);

  const uniqueDomains = useMemo(() => {
    const set = new Set<string>();
    for (const scan of recentScans) {
      if (scan.domain) set.add(scan.domain);
    }
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [recentScans]);

  const filteredAndSorted = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    const filtered = recentScans.filter((item) => {
      const matchesSearch =
        !q ||
        item.normalizedUrl.toLowerCase().includes(q) ||
        item.domain.toLowerCase().includes(q);
      const matchesVerdict =
        verdictFilter === 'all' ||
        (verdictFilter === 'malicious_high'
          ? item.verdict === 'Confirmed Malicious' || item.verdict === 'High Risk'
          : item.verdict === verdictFilter);
      const matchesDomain = domainFilter === 'all' || item.domain === domainFilter;
      return matchesSearch && matchesVerdict && matchesDomain;
    });

    const sorted = [...filtered].sort((a, b) => {
      let cmp = 0;
      if (sortField === 'analyzedAt') {
        cmp = new Date(a.analyzedAt).getTime() - new Date(b.analyzedAt).getTime();
      } else if (sortField === 'riskScore') {
        cmp = a.riskScore - b.riskScore;
      } else if (sortField === 'mlConfidence') {
        cmp = a.mlConfidence - b.mlConfidence;
      } else if (sortField === 'domain') {
        cmp = a.domain.localeCompare(b.domain);
      } else if (sortField === 'verdict') {
        cmp = a.verdict.localeCompare(b.verdict);
      }
      return sortDirection === 'asc' ? cmp : -cmp;
    });

    return sorted;
  }, [recentScans, searchTerm, verdictFilter, domainFilter, sortField, sortDirection]);

  const totalPages = Math.max(1, Math.ceil(filteredAndSorted.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, verdictFilter, domainFilter, pageSize]);

  const paginatedScans = filteredAndSorted.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );

  function toggleSort(field: SortField) {
    if (sortField === field) {
      setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection(field === 'domain' || field === 'verdict' ? 'asc' : 'desc');
    }
  }

  function renderSortIcon(field: SortField) {
    if (sortField !== field) {
      return <ArrowUpDown className="h-3 w-3 text-slate-400" aria-hidden="true" />;
    }
    return sortDirection === 'asc' ? (
      <ArrowUp className="h-3 w-3 text-[#2563EB]" aria-hidden="true" />
    ) : (
      <ArrowDown className="h-3 w-3 text-[#2563EB]" aria-hidden="true" />
    );
  }

  return (
    <section
      aria-label="Recent URL scans"
      className="rounded-xl border border-[#E2E8F0] bg-white shadow-xs overflow-hidden"
    >
      {/* Header + Search + Filters */}
      <div className="border-b border-[#E2E8F0] px-5 py-4 sm:px-6 space-y-3">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-base font-semibold text-[#111827]">{title}</h2>
            <p className="text-xs text-[#64748B]">{subtitle}</p>
          </div>
          <div className="font-mono text-xs tabular-nums text-[#64748B]">
            {filteredAndSorted.length} of {recentScans.length} scan
            {recentScans.length === 1 ? '' : 's'}
          </div>
        </div>

        <div className="flex flex-col gap-2.5 xl:flex-row xl:items-center xl:justify-between">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="relative flex-1 min-w-[200px] sm:flex-initial sm:w-64">
              <Search
                className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400"
                aria-hidden="true"
              />
              <input
                type="search"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                aria-label="Search scans by URL or domain"
                placeholder="Search URL or domain..."
                className="w-full rounded-lg border border-slate-300 bg-white py-1.5 pl-8 pr-3 text-xs text-[#111827] placeholder:text-slate-400 focus:border-[#2563EB] focus:outline-none"
              />
            </div>

            <label className="sr-only" htmlFor="scan-domain-filter">
              Filter by domain
            </label>
            <select
              id="scan-domain-filter"
              value={domainFilter}
              onChange={(e) => setDomainFilter(e.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-[#111827] focus:border-[#2563EB] focus:outline-none max-w-[180px]"
            >
              <option value="all">All domains ({uniqueDomains.length})</option>
              {uniqueDomains.map((dom) => (
                <option key={dom} value={dom}>
                  {dom}
                </option>
              ))}
            </select>
          </div>

          <div className="flex flex-wrap items-center gap-1 rounded-lg bg-slate-100 p-1">
            {(
              [
                { id: 'all', label: 'All' },
                { id: 'malicious_high', label: 'Malicious / High' },
                { id: 'Suspicious', label: 'Suspicious' },
                { id: 'No Known Threat', label: 'No Threat' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setVerdictFilter(tab.id)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  verdictFilter === tab.id
                    ? 'bg-white text-[#111827] shadow-xs'
                    : 'text-[#64748B] hover:text-[#111827]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Empty State */}
      {paginatedScans.length === 0 ? (
        <div className="px-6 py-12 text-center text-sm text-[#64748B]">
          No matching URL scans found. Adjust your filters or analyze a URL above.
        </div>
      ) : (
        <>
          {/* Desktop & Tablet Table */}
          <div className="hidden md:block overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-[#E2E8F0] bg-[#F8FAFC] text-[11px] font-medium text-[#64748B]">
                  <th className="pl-4 pr-2.5 py-2.5 whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => toggleSort('domain')}
                      className="inline-flex items-center gap-1 hover:text-[#111827]"
                    >
                      <span>URL / Domain</span>
                      {renderSortIcon('domain')}
                    </button>
                  </th>
                  <th className="px-2.5 py-2.5 whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => toggleSort('verdict')}
                      className="inline-flex items-center gap-1 hover:text-[#111827]"
                    >
                      <span>Verdict</span>
                      {renderSortIcon('verdict')}
                    </button>
                  </th>
                  <th className="px-2.5 py-2.5 whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => toggleSort('riskScore')}
                      className="inline-flex items-center gap-1 hover:text-[#111827]"
                    >
                      <span>Risk</span>
                      {renderSortIcon('riskScore')}
                    </button>
                  </th>
                  <th className="px-2.5 py-2.5 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => toggleSort('mlConfidence')}
                      className="inline-flex items-center gap-1 hover:text-[#111827]"
                    >
                      <span>ML</span>
                      {renderSortIcon('mlConfidence')}
                    </button>
                  </th>
                  <th className="px-2.5 py-2.5 whitespace-nowrap">Source</th>
                  <th className="px-2.5 py-2.5 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => toggleSort('analyzedAt')}
                      className="inline-flex items-center gap-1 hover:text-[#111827]"
                    >
                      <span>Time</span>
                      {renderSortIcon('analyzedAt')}
                    </button>
                  </th>
                  <th className="pl-2.5 pr-4 py-2.5 text-right whitespace-nowrap">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {paginatedScans.map((scan) => {
                  const pres = getVerdictPresentation(scan.verdict);
                  const Icon = getVerdictIcon(scan.verdict);
                  const cachedReport = reportsById[scan.id];
                  const sourceLabel = deriveDetectionSource(scan, cachedReport);
                  const isSelected = selectedScanId === scan.id;
                  const dt = new Date(scan.analyzedAt);

                  return (
                    <tr
                      key={scan.id}
                      onClick={() => onSelectScan(scan.id)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? 'bg-blue-50/50' : 'hover:bg-slate-50/80'
                      }`}
                    >
                      <td className="pl-4 pr-2.5 py-2.5 max-w-[180px] 2xl:max-w-[260px]">
                        <div
                          className="font-mono text-xs font-medium text-[#111827] truncate"
                          title={scan.normalizedUrl}
                        >
                          {scan.normalizedUrl}
                        </div>
                        <div className="mt-0.5 text-[11px] text-[#64748B] truncate">
                          {scan.domain}
                        </div>
                      </td>
                      <td className="px-2.5 py-2.5 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium ${pres.badgeSurface}`}
                        >
                          <Icon className="h-3 w-3 shrink-0" aria-hidden="true" />
                          <span>{pres.label}</span>
                        </span>
                      </td>
                      <td className="px-2.5 py-2.5 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-semibold tabular-nums text-[#111827] w-11">
                            {scan.riskScore}/100
                          </span>
                          <div className="h-1.5 w-11 overflow-hidden rounded-full bg-slate-100 hidden 2xl:block">
                            <div
                              className={`h-full rounded-full ${pres.barColor}`}
                              style={{ width: `${Math.max(4, scan.riskScore)}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="px-2.5 py-2.5 text-right font-mono text-xs tabular-nums text-[#64748B] whitespace-nowrap">
                        {scan.mlConfidence}%
                      </td>
                      <td
                        className="px-2.5 py-2.5 text-xs text-[#64748B] max-w-[115px] 2xl:max-w-[160px] truncate"
                        title={sourceLabel}
                      >
                        {sourceLabel}
                      </td>
                      <td className="px-2.5 py-2.5 text-right font-mono text-[11px] tabular-nums text-[#64748B] whitespace-nowrap">
                        <div>{dt.toLocaleDateString()}</div>
                        <div className="text-[10px] text-slate-400">
                          {dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </div>
                      </td>
                      <td className="pl-2.5 pr-4 py-2.5 text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectScan(scan.id);
                          }}
                          className="inline-flex items-center gap-1 rounded-md border border-[#E2E8F0] bg-white px-2 py-1 text-[11px] font-medium text-[#111827] hover:border-[#2563EB] hover:text-[#2563EB]"
                        >
                          <span>Inspect</span>
                          <ExternalLink className="h-3 w-3" aria-hidden="true" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Mobile Responsive Card List */}
          <ul className="divide-y divide-slate-100 md:hidden">
            {paginatedScans.map((scan) => {
              const pres = getVerdictPresentation(scan.verdict);
              const Icon = getVerdictIcon(scan.verdict);
              const sourceLabel = deriveDetectionSource(scan, reportsById[scan.id]);
              return (
                <li key={scan.id} className="p-4">
                  <button
                    type="button"
                    onClick={() => onSelectScan(scan.id)}
                    className="w-full text-left space-y-2.5"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span
                        className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium ${pres.badgeSurface}`}
                      >
                        <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        <span>{pres.label}</span>
                      </span>
                      <span className="font-mono text-xs font-semibold tabular-nums text-[#111827]">
                        Score {scan.riskScore}/100
                      </span>
                    </div>

                    <div>
                      <div className="font-mono text-xs font-medium text-[#111827] break-all line-clamp-2">
                        {scan.normalizedUrl}
                      </div>
                      <div className="mt-0.5 text-[11px] text-[#64748B]">{scan.domain}</div>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-[#64748B]">
                      <span>
                        {sourceLabel} · ML {scan.mlConfidence}%
                      </span>
                      <span className="font-mono tabular-nums">
                        {new Date(scan.analyzedAt).toLocaleString()}
                      </span>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>

          {/* Pagination Footer */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between border-t border-[#E2E8F0] bg-[#F8FAFC] px-5 py-3 text-xs text-[#64748B]">
              <span className="font-mono tabular-nums">
                Page {safePage} of {totalPages}
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={safePage <= 1}
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  className="inline-flex items-center gap-1 rounded-md border border-[#E2E8F0] bg-white px-2.5 py-1 font-medium text-[#111827] hover:bg-slate-50 disabled:opacity-40"
                >
                  <ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Previous</span>
                </button>
                <button
                  type="button"
                  disabled={safePage >= totalPages}
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  className="inline-flex items-center gap-1 rounded-md border border-[#E2E8F0] bg-white px-2.5 py-1 font-medium text-[#111827] hover:bg-slate-50 disabled:opacity-40"
                >
                  <span>Next</span>
                  <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}
