import type { FormEvent } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Database,
  GlobeLock,
  Loader2,
  Search,
  Shield,
  Tag,
  X,
} from 'lucide-react';
import type { HealthResponse } from '../services/api';

export interface SampleUrlOption {
  label: string;
  url: string;
}

export const SAFE_TEST_EXAMPLES: SampleUrlOption[] = [
  {
    label: 'Legitimate reference',
    url: 'https://www.wikipedia.org/wiki/Phishing',
  },
  {
    label: 'Subdomain impersonation',
    url: 'https://accounts.google.com.login.example.test/',
  },
  {
    label: 'Redirect lure',
    url: 'https://example.test/redirect?next=https://accounts.google.com',
  },
  {
    label: 'Safe threat-feed fixture',
    url: 'http://testsafebrowsing.appspot.com/s/phishing.html',
  },
  {
    label: 'Punycode homograph',
    url: 'http://xn--pple-43d.com/support/reset-password?urgent-action=true',
  },
];

interface ScannerHeroProps {
  urlInput: string;
  onChangeUrl: (value: string) => void;
  onSubmit: (e: FormEvent) => void;
  onSelectSample: (url: string) => void;
  onClear: () => void;
  analyzing: boolean;
  hasReport: boolean;
  error: string | null;
  health: HealthResponse | null;
  healthLoading: boolean;
  healthError: boolean;
}

export function ScannerHero({
  urlInput,
  onChangeUrl,
  onSubmit,
  onSelectSample,
  onClear,
  analyzing,
  hasReport,
  error,
  health,
  healthLoading,
  healthError,
}: ScannerHeroProps) {
  const configuredProviders =
    health?.threatIntelProviders.filter((p) => p.configured).length ?? 0;
  const totalProviders = health?.threatIntelProviders.length ?? 0;

  const engineRows = [
    {
      id: 'ml',
      name: 'Machine Learning Engine',
      icon: Cpu,
      statusLabel: healthLoading
        ? 'Checking...'
        : healthError
          ? 'Unavailable'
          : health?.mlEngine.loaded
            ? `Operational · v${health.mlEngine.version}`
            : 'Unavailable',
      operational: Boolean(!healthLoading && !healthError && health?.mlEngine.loaded),
      detail: health?.mlEngine.externalServiceConfigured
        ? 'Hybrid external + local classifier'
        : 'In-process TF-IDF & structural model',
    },
    {
      id: 'ti',
      name: 'Threat Intelligence APIs',
      icon: Database,
      statusLabel: healthLoading
        ? 'Checking...'
        : healthError
          ? 'Unavailable'
          : `${configuredProviders} of ${totalProviders} Active`,
      operational: Boolean(!healthLoading && !healthError && configuredProviders > 0),
      detail: health?.threatIntelProviders
        .filter((p) => p.configured)
        .map((p) => p.name)
        .join(', ') || 'No configured providers',
    },
    {
      id: 'url',
      name: 'URL Analysis Engine',
      icon: Shield,
      statusLabel: healthLoading
        ? 'Checking...'
        : healthError
          ? 'Unavailable'
          : 'Operational',
      operational: Boolean(!healthLoading && !healthError && health),
      detail: 'PSL domain parser, brand & redirect checks',
    },
    {
      id: 'kw',
      name: 'Keyword Detection Engine',
      icon: Tag,
      statusLabel: healthLoading
        ? 'Checking...'
        : healthError
          ? 'Unavailable'
          : 'Operational',
      operational: Boolean(!healthLoading && !healthError && health),
      detail: 'Weighted phishing & credential-lure terms',
    },
  ];

  return (
    <section
      aria-label="URL security scanner and engine status"
      className="grid grid-cols-1 gap-6 lg:grid-cols-12"
    >
      {/* Left: Hero URL Scanner (8 columns) */}
      <div className="lg:col-span-8 rounded-xl border border-[#E2E8F0] bg-white p-6 shadow-xs sm:p-8 flex flex-col justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#111827] sm:text-3xl text-balance">
            Stay Ahead of Online Threats.
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-[#64748B] sm:text-base">
            Analyze suspicious URLs using machine learning, threat intelligence, and advanced URL
            security inspection.
          </p>

          <form onSubmit={onSubmit} className="mt-6">
            <label htmlFor="url-input" className="sr-only">
              Website URL to analyze
            </label>
            <div className="flex flex-col gap-3 sm:flex-row">
              <div className="relative flex-1">
                <Search
                  className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
                  aria-hidden="true"
                />
                <input
                  id="url-input"
                  type="text"
                  value={urlInput}
                  onChange={(e) => onChangeUrl(e.target.value)}
                  placeholder="Paste a website URL to analyze its security..."
                  autoComplete="off"
                  spellCheck={false}
                  className="w-full rounded-lg border border-slate-300 bg-white py-3.5 pl-11 pr-10 font-mono text-sm text-[#111827] placeholder:font-sans placeholder:text-slate-400 focus:border-[#2563EB] focus:outline-none focus:ring-2 focus:ring-[#2563EB]/15"
                />
                {urlInput && (
                  <button
                    type="button"
                    onClick={onClear}
                    aria-label="Clear URL input"
                    className="absolute right-3 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-[#111827]"
                  >
                    <X className="h-4 w-4" aria-hidden="true" />
                  </button>
                )}
              </div>

              <div className="flex items-center gap-2.5 shrink-0">
                <button
                  type="submit"
                  disabled={analyzing}
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-[#2563EB] px-6 py-3.5 text-sm font-semibold text-white transition-colors hover:bg-blue-700 disabled:opacity-60 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#2563EB]"
                >
                  {analyzing && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                  <span>{analyzing ? 'Analyzing...' : 'Analyze URL'}</span>
                </button>

                {(urlInput || hasReport) && (
                  <button
                    type="button"
                    onClick={onClear}
                    disabled={analyzing}
                    className="rounded-lg border border-[#E2E8F0] bg-white px-4 py-3.5 text-sm font-medium text-[#111827] transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>
          </form>

          {/* Error & Loading Feedback */}
          {error && (
            <div
              role="alert"
              className="mt-4 flex items-start gap-2.5 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800"
            >
              <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-red-700" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          {analyzing && (
            <div
              role="status"
              aria-live="polite"
              className="mt-4 flex items-center gap-3 rounded-lg border border-blue-200 bg-blue-50/60 px-4 py-3 text-sm font-medium text-[#111827]"
            >
              <Loader2 className="h-4 w-4 animate-spin text-[#2563EB] shrink-0" aria-hidden="true" />
              <span>
                Running PSL domain normalization, brand impersonation checks, ML scoring, and threat
                intelligence lookups...
              </span>
            </div>
          )}
        </div>

        {/* Bottom Helper & Safe Samples */}
        <div className="mt-6 border-t border-slate-100 pt-4 space-y-2.5">
          <div className="flex flex-wrap items-center gap-2 text-xs text-[#64748B]">
            <GlobeLock className="h-3.5 w-3.5 text-[#2563EB] shrink-0" aria-hidden="true" />
            <span>
              URLs are parsed and evaluated without navigating your browser to the target site.
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-[#64748B]">Sample test URLs:</span>
            {SAFE_TEST_EXAMPLES.map((sample) => (
              <button
                key={sample.url}
                type="button"
                disabled={analyzing}
                onClick={() => onSelectSample(sample.url)}
                className="rounded-md border border-[#E2E8F0] bg-[#F8FAFC] px-2.5 py-1 font-medium text-[#111827] transition-colors hover:border-blue-200 hover:bg-blue-50/70 hover:text-[#2563EB] disabled:opacity-50"
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Right: Security Engine Overview (4 columns) */}
      <aside
        aria-label="Security engine runtime status"
        className="lg:col-span-4 rounded-xl border border-[#E2E8F0] bg-white p-6 shadow-xs flex flex-col justify-between"
      >
        <div>
          <div className="flex items-center justify-between gap-3 border-b border-slate-100 pb-3.5">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-[#2563EB]" aria-hidden="true" />
              <h2 className="text-sm font-semibold text-[#111827]">Security Engine Overview</h2>
            </div>
            <span className="font-mono text-[11px] text-[#64748B]">
              {health?.status.includes('standalone') ? 'Static Engine' : 'Live API'}
            </span>
          </div>

          <ul className="mt-3 divide-y divide-slate-100">
            {engineRows.map((row) => {
              const Icon = row.icon;
              return (
                <li key={row.id} className="py-3 first:pt-1 last:pb-1">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <Icon className="h-4 w-4 text-[#64748B] shrink-0" aria-hidden="true" />
                      <span className="text-xs font-semibold text-[#111827] truncate">
                        {row.name}
                      </span>
                    </div>
                    <span
                      className={`inline-flex items-center gap-1 text-xs font-medium shrink-0 ${
                        healthLoading
                          ? 'text-[#64748B]'
                          : row.operational
                            ? 'text-emerald-700'
                            : 'text-amber-700'
                      }`}
                    >
                      {!healthLoading &&
                        (row.operational ? (
                          <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        ) : (
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        ))}
                      <span>{row.statusLabel}</span>
                    </span>
                  </div>
                  <p className="mt-0.5 pl-6 text-[11px] text-[#64748B] truncate">{row.detail}</p>
                </li>
              );
            })}
          </ul>
        </div>

        <div className="mt-4 rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] px-3.5 py-2.5 text-[11px] text-[#64748B] flex items-center justify-between gap-2">
          <span>Website Sandbox Inspection</span>
          <span className="font-mono font-medium text-[#111827]">
            {healthLoading
              ? 'Checking...'
              : health?.websiteInspectionEnabled
                ? 'Enabled (SSRF Guarded)'
                : health?.status.includes('standalone')
                  ? 'Disabled (Static Mode)'
                  : 'Disabled (Server Policy)'}
          </span>
        </div>
      </aside>
    </section>
  );
}
