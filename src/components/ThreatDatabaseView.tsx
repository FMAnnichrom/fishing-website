import { useEffect, useState } from 'react';
import { Database, KeyRound, ShieldAlert } from 'lucide-react';
import type { KeywordRecord, ThreatIndicatorRecord, UserReportRecord } from '../../shared/types';
import {
  fetchHealth,
  fetchKeywords,
  fetchThreatFeeds,
  type HealthResponse,
} from '../services/api';

export function ThreatDatabaseView() {
  const [keywords, setKeywords] = useState<KeywordRecord[]>([]);
  const [indicators, setIndicators] = useState<ThreatIndicatorRecord[]>([]);
  const [reports, setReports] = useState<UserReportRecord[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.all([fetchKeywords(), fetchThreatFeeds(), fetchHealth()])
      .then(([kwData, feedData, healthData]) => {
        if (!active) return;
        setKeywords(kwData.keywords);
        setIndicators(feedData.indicators);
        setReports(feedData.pendingReports);
        setHealth(healthData);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : 'Failed to load threat database.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  if (loading) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-8 text-sm text-slate-500">
        Loading threat-intelligence feeds and keyword database...
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-red-200 bg-red-50 p-6 text-sm text-red-800">
        {error}
      </div>
    );
  }

  const categories = ['All', ...Array.from(new Set(keywords.map((k) => k.category)))];
  const filteredKeywords =
    selectedCategory === 'All'
      ? keywords
      : keywords.filter((k) => k.category === selectedCategory);

  return (
    <div className="space-y-6">
      {/* Provider Configuration Transparency */}
      {health && (
        <section className="rounded-xl border border-slate-200 bg-white p-6">
          <div className="flex items-start gap-3">
            <KeyRound className="h-5 w-5 text-slate-600 mt-0.5 shrink-0" aria-hidden="true" />
            <div>
              <h2 className="text-base font-semibold text-slate-900">
                Threat-Intelligence Provider Status
              </h2>
              <p className="mt-1 text-xs text-slate-600">
                External API keys are stored strictly in server environment variables. Unconfigured
                providers report their status honestly rather than returning fabricated results.
              </p>
            </div>
          </div>

          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {health.threatIntelProviders.map((p) => (
              <div key={p.name} className="rounded-lg border border-slate-200 px-4 py-3">
                <div className="text-sm font-medium text-slate-900">{p.name}</div>
                <div className="mt-1 text-xs text-slate-500">{p.mode}</div>
                <div
                  className={`mt-2 text-xs font-medium ${
                    p.configured ? 'text-emerald-700' : 'text-slate-600'
                  }`}
                >
                  {p.configured ? 'Configured & Active' : 'API Key Not Configured'}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Local Threat Feed Indicators */}
      <section className="rounded-xl border border-slate-200 bg-white">
        <div className="flex items-center justify-between gap-4 border-b border-slate-200 px-6 py-4">
          <div className="flex items-center gap-2.5 min-w-0">
            <Database className="h-4 w-4 text-slate-600 shrink-0" aria-hidden="true" />
            <div className="min-w-0">
              <h2 className="text-base font-semibold text-slate-900">
                Local Threat Feed Indicators
              </h2>
              <p className="text-xs text-slate-500">
                Deduplicated, normalized threat indicators from synced public feeds and safe test fixtures.
              </p>
            </div>
          </div>
          <span className="font-mono text-xs tabular-nums text-slate-600 whitespace-nowrap shrink-0">
            {indicators.length} active
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/60 text-xs font-medium text-slate-500">
                <th className="px-6 py-2.5">Normalized URL</th>
                <th className="px-4 py-2.5">Category</th>
                <th className="px-4 py-2.5">Source</th>
                <th className="px-6 py-2.5 text-right">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {indicators.map((ind) => (
                <tr key={ind.id}>
                  <td className="px-6 py-3 font-mono text-xs text-slate-900 break-all">
                    {ind.normalizedUrl}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-700 whitespace-nowrap">
                    {ind.threatCategory}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-600 whitespace-nowrap">
                    {ind.source}
                  </td>
                  <td className="px-6 py-3 text-right font-mono text-xs tabular-nums text-slate-500 whitespace-nowrap">
                    {new Date(ind.lastSeen).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* User-Submitted Reports Queue (Unverified until corroborated) */}
      <section className="rounded-xl border border-slate-200 bg-white">
        <div className="flex items-center justify-between gap-4 border-b border-slate-200 px-6 py-4">
          <div className="flex items-center gap-2.5 min-w-0">
            <ShieldAlert className="h-4 w-4 text-slate-600 shrink-0" aria-hidden="true" />
            <div className="min-w-0">
              <h2 className="text-base font-semibold text-slate-900">
                Community Submitted Reports
              </h2>
              <p className="text-xs text-slate-500">
                User reports remain unverified until reviewed or corroborated by trusted feeds.
              </p>
            </div>
          </div>
          <span className="font-mono text-xs tabular-nums text-slate-600 whitespace-nowrap shrink-0">
            {reports.length} submitted
          </span>
        </div>

        {reports.length === 0 ? (
          <div className="px-6 py-8 text-center text-xs text-slate-500">
            No suspicious URLs have been reported by users yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50/60 text-xs font-medium text-slate-500">
                  <th className="px-6 py-2.5">Reported URL</th>
                  <th className="px-4 py-2.5">Reason</th>
                  <th className="px-4 py-2.5">Review Status</th>
                  <th className="px-6 py-2.5 text-right">Submitted</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {reports.map((rep) => (
                  <tr key={rep.id}>
                    <td className="px-6 py-3 font-mono text-xs text-slate-900 break-all">
                      {rep.normalizedUrl}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-700">{rep.reason}</td>
                    <td className="px-4 py-3 text-xs font-medium text-amber-700 capitalize whitespace-nowrap">
                      {rep.status}
                    </td>
                    <td className="px-6 py-3 text-right font-mono text-xs tabular-nums text-slate-500 whitespace-nowrap">
                      {new Date(rep.createdAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Suspicious Keyword Database */}
      <section className="rounded-xl border border-slate-200 bg-white">
        <div className="flex flex-col gap-3 border-b border-slate-200 px-6 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-900">
              Suspicious Keyword Database
            </h2>
            <p className="text-xs text-slate-500">
              Categorized terms evaluated across URLs and safely extracted content.
            </p>
          </div>

          <label className="flex items-center gap-2 text-xs text-slate-600">
            <span>Category:</span>
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:border-blue-700 focus:outline-none"
            >
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/60 text-xs font-medium text-slate-500">
                <th className="px-6 py-2.5">Keyword</th>
                <th className="px-4 py-2.5">Category</th>
                <th className="px-4 py-2.5 text-right">Weight</th>
                <th className="px-6 py-2.5">Security Rationale</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredKeywords.map((kw) => (
                <tr key={kw.id}>
                  <td className="px-6 py-2.5 font-mono text-xs font-semibold text-slate-900 whitespace-nowrap">
                    {kw.keyword}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-slate-700 whitespace-nowrap">
                    {kw.category}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums text-slate-900">
                    {kw.weight}/10
                  </td>
                  <td className="px-6 py-2.5 text-xs text-slate-600">{kw.rationale}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
