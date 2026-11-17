import { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Cpu,
  Database,
  Flag,
  HelpCircle,
  Info,
  Layers,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  XCircle,
} from 'lucide-react';
import type { AnalysisReport, EvidenceFinding, ProviderStatus } from '../../shared/types';
import { getVerdictPresentation } from '../utils/dashboardHelpers';

interface AnalysisResultCardProps {
  report: AnalysisReport;
  onReportCurrentUrl: (url: string) => void;
  defaultDetailsExpanded?: boolean;
}

function getVerdictIcon(verdict: AnalysisReport['verdict']) {
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

function formatBasisLabel(basis: AnalysisReport['scoringBreakdown']['classificationBasis']): string {
  switch (basis) {
    case 'confirmed_threat':
      return 'Confirmed Threat Intelligence Match';
    case 'high_risk_prediction':
      return 'High-Risk Pattern, Brand & ML Detection';
    case 'suspicious_signals':
      return 'Suspicious URL Patterns Detected';
    case 'no_known_threat':
      return 'No Known Threat Found in Checked Sources';
    default:
      return 'Insufficient Verification Data';
  }
}

function getProviderStatusVisual(status: ProviderStatus) {
  switch (status) {
    case 'match':
      return {
        icon: XCircle,
        color: 'text-red-700',
        badge: 'bg-red-50 border-red-200 text-red-800',
        label: 'Threat Match',
      };
    case 'clean':
      return {
        icon: CheckCircle2,
        color: 'text-emerald-700',
        badge: 'bg-emerald-50 border-emerald-200 text-emerald-800',
        label: 'No Match',
      };
    case 'not_configured':
      return {
        icon: HelpCircle,
        color: 'text-[#64748B]',
        badge: 'bg-slate-100 border-slate-200 text-[#64748B]',
        label: 'Not Configured',
      };
    default:
      return {
        icon: AlertTriangle,
        color: 'text-amber-700',
        badge: 'bg-amber-50 border-amber-200 text-amber-800',
        label: 'Unavailable',
      };
  }
}

function getSeverityVisual(severity: EvidenceFinding['severity']) {
  switch (severity) {
    case 'high':
      return {
        icon: ShieldAlert,
        color: 'text-red-700',
        surface: 'border-red-200 bg-red-50/40',
        label: 'High',
      };
    case 'medium':
      return {
        icon: AlertTriangle,
        color: 'text-amber-700',
        surface: 'border-amber-200 bg-amber-50/40',
        label: 'Medium',
      };
    case 'low':
      return {
        icon: Info,
        color: 'text-[#2563EB]',
        surface: 'border-blue-200 bg-blue-50/30',
        label: 'Low',
      };
    default:
      return {
        icon: Info,
        color: 'text-[#64748B]',
        surface: 'border-[#E2E8F0] bg-slate-50/50',
        label: 'Info',
      };
  }
}

export function AnalysisResultCard({
  report,
  onReportCurrentUrl,
  defaultDetailsExpanded = false,
}: AnalysisResultCardProps) {
  const [detailsExpanded, setDetailsExpanded] = useState(defaultDetailsExpanded);
  const [copiedUrl, setCopiedUrl] = useState(false);

  useEffect(() => {
    setDetailsExpanded(defaultDetailsExpanded);
  }, [report.id, defaultDetailsExpanded]);

  const pres = getVerdictPresentation(report.verdict);
  const VerdictIcon = getVerdictIcon(report.verdict);
  const breakdown = report.urlBreakdown;
  const findings = report.evidenceFindings ?? [];

  // Circular risk gauge SVG math
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const clampedScore = Math.max(0, Math.min(100, report.riskScore));
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  async function handleCopyUrl() {
    try {
      await navigator.clipboard.writeText(report.normalizedUrl);
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 1800);
    } catch {
      // Clipboard may be unavailable in restricted contexts
    }
  }

  return (
    <section
      aria-label="Security investigation report"
      className="rounded-xl border border-[#E2E8F0] bg-white shadow-xs overflow-hidden"
    >
      {/* Top Investigation Report Header */}
      <div className={`border-b border-[#E2E8F0] px-6 py-6 ${pres.softPanel}`}>
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-start gap-4 min-w-0">
            {/* Circular SVG Risk Gauge */}
            <div
              className="relative flex h-24 w-24 shrink-0 items-center justify-center rounded-full bg-white border border-[#E2E8F0] shadow-xs"
              aria-label={`Overall risk score ${report.riskScore} out of 100`}
            >
              <svg className="h-22 w-22 -rotate-90" viewBox="0 0 96 96" aria-hidden="true">
                <circle
                  cx="48"
                  cy="48"
                  r={radius}
                  fill="none"
                  stroke="#E2E8F0"
                  strokeWidth="8"
                />
                <circle
                  cx="48"
                  cy="48"
                  r={radius}
                  fill="none"
                  stroke={pres.ringStroke}
                  strokeWidth="8"
                  strokeLinecap="round"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  className="transition-all duration-500"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`font-mono text-2xl font-bold tabular-nums leading-none ${pres.textColor}`}>
                  {report.riskScore}
                </span>
                <span className="mt-0.5 text-[10px] font-medium text-[#64748B]">/ 100</span>
              </div>
            </div>

            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2.5">
                <span
                  className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold ${pres.badgeSurface}`}
                >
                  <VerdictIcon className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>{report.verdict}</span>
                </span>
                <span className="text-xs font-medium text-[#64748B]">
                  {formatBasisLabel(report.scoringBreakdown.classificationBasis)}
                </span>
              </div>

              <h2 className="mt-2 font-mono text-sm sm:text-base font-semibold text-[#111827] break-all">
                {report.normalizedUrl}
              </h2>

              <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[#64748B]">
                <span>
                  Registrable Domain:{' '}
                  <strong className="font-mono font-semibold text-[#111827]">
                    {breakdown?.registrableDomain || report.domain}
                  </strong>
                </span>
                <span>
                  Transport:{' '}
                  <strong className="text-[#111827]">
                    {report.structuralSignals.isHttps ? 'HTTPS' : 'HTTP'}
                    {breakdown?.isUnusualPort ? ` (Port ${breakdown.port})` : ''}
                  </strong>
                </span>
                <time dateTime={report.analyzedAt} className="font-mono tabular-nums">
                  Analyzed {new Date(report.analyzedAt).toLocaleString()}
                </time>
              </div>
            </div>
          </div>

          {/* Right Quick Actions */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={handleCopyUrl}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#E2E8F0] bg-white px-3 py-2 text-xs font-medium text-[#111827] hover:bg-slate-50"
            >
              {copiedUrl ? (
                <Check className="h-3.5 w-3.5 text-emerald-700" aria-hidden="true" />
              ) : (
                <Copy className="h-3.5 w-3.5 text-[#64748B]" aria-hidden="true" />
              )}
              <span>{copiedUrl ? 'Copied' : 'Copy URL'}</span>
            </button>
            <button
              type="button"
              onClick={() => onReportCurrentUrl(report.normalizedUrl)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#E2E8F0] bg-white px-3 py-2 text-xs font-medium text-[#111827] hover:bg-slate-50"
            >
              <Flag className="h-3.5 w-3.5 text-[#64748B]" aria-hidden="true" />
              <span>Report URL</span>
            </button>
          </div>
        </div>
      </div>

      {/* A. Detection Summary */}
      <div className="border-b border-[#E2E8F0] px-6 py-5 bg-white">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="max-w-4xl">
            <h3 className="text-sm font-semibold text-[#111827]">A. Detection Summary</h3>
            <p className="mt-1.5 text-sm leading-relaxed text-[#111827]">
              {report.recommendedAction}
            </p>
            <p className="mt-2 text-xs leading-relaxed text-[#64748B]">{report.disclaimer}</p>
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 shrink-0 lg:w-auto">
            <div className="rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] px-3.5 py-2.5">
              <div className="text-[11px] font-medium text-[#64748B]">Evidence Findings</div>
              <div className="mt-0.5 font-mono text-base font-bold tabular-nums text-[#111827]">
                {findings.length}
              </div>
            </div>
            <div className="rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] px-3.5 py-2.5">
              <div className="text-[11px] font-medium text-[#64748B]">Threat DB Match</div>
              <div className="mt-0.5 text-sm font-semibold text-[#111827]">
                {report.inKnownThreatDatabase ? 'Match Found' : 'No Match'}
              </div>
            </div>
            <div className="rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] px-3.5 py-2.5 col-span-2 sm:col-span-1">
              <div className="text-[11px] font-medium text-[#64748B]">Suspicious Keywords</div>
              <div className="mt-0.5 font-mono text-base font-bold tabular-nums text-[#111827]">
                {report.keywordMatches.length}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* B. Detection Evidence */}
      <div className="border-b border-[#E2E8F0] px-6 py-5">
        <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="text-sm font-semibold text-[#111827]">B. Detection Evidence</h3>
            <p className="text-xs text-[#64748B]">
              Deduplicated security findings ordered by risk contribution.
            </p>
          </div>
          <span className="font-mono text-xs tabular-nums text-[#64748B]">
            {findings.length} finding{findings.length === 1 ? '' : 's'}
          </span>
        </div>

        {findings.length > 0 ? (
          <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
            {findings.map((finding) => {
              const sev = getSeverityVisual(finding.severity);
              const SevIcon = sev.icon;
              return (
                <div
                  key={finding.id}
                  className={`rounded-lg border p-4 ${sev.surface}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-2 min-w-0">
                      <SevIcon className={`h-4 w-4 mt-0.5 shrink-0 ${sev.color}`} aria-hidden="true" />
                      <div className="min-w-0">
                        <div className="text-sm font-semibold text-[#111827]">{finding.pattern}</div>
                        <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[11px] text-[#64748B]">
                          <span>{finding.category}</span>
                          <span aria-hidden="true">·</span>
                          <span>{finding.source}</span>
                          <span aria-hidden="true">·</span>
                          <span className={`font-medium ${sev.color}`}>{sev.label}</span>
                        </div>
                      </div>
                    </div>
                    <span
                      className={`font-mono text-xs font-semibold tabular-nums shrink-0 ${sev.color}`}
                    >
                      +{finding.riskContribution} pts
                    </span>
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-[#111827]">
                    {finding.explanation}
                  </p>
                  {finding.matchedText && (
                    <div className="mt-2 rounded border border-[#E2E8F0] bg-white px-2.5 py-1.5 text-[11px] text-[#64748B]">
                      Matched:{' '}
                      <code className="font-mono text-[#111827] break-all">
                        {finding.matchedText}
                      </code>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="mt-4 rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] p-4 text-xs text-[#64748B]">
            No deceptive URL patterns, brand impersonation indicators, or threat-feed matches were
            triggered for this URL.
          </div>
        )}

        {/* Specific Reasons List */}
        {report.flaggedReasons.length > 0 && (
          <div className="mt-5 border-t border-slate-100 pt-4">
            <h4 className="text-xs font-semibold text-[#111827]">Assessment Reasons & Signals</h4>
            <ul className="mt-2 grid grid-cols-1 gap-2 lg:grid-cols-2">
              {report.flaggedReasons.map((reason, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs text-[#64748B]">
                  <span
                    className="mt-1.5 h-1.5 w-1.5 rounded-full bg-slate-400 shrink-0"
                    aria-hidden="true"
                  />
                  <span className="leading-relaxed text-[#111827]">{reason}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* C. Expandable Advanced URL Breakdown */}
      <div className="border-b border-[#E2E8F0] px-6 py-4 bg-white">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <button
            type="button"
            aria-expanded={detailsExpanded}
            onClick={() => setDetailsExpanded((v) => !v)}
            className="inline-flex items-center gap-2 text-sm font-semibold text-[#2563EB] hover:text-blue-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#2563EB]"
          >
            <Layers className="h-4 w-4" aria-hidden="true" />
            <span>C. Advanced URL Breakdown & Technical Telemetry</span>
            {detailsExpanded ? (
              <ChevronUp className="h-4 w-4" aria-hidden="true" />
            ) : (
              <ChevronDown className="h-4 w-4" aria-hidden="true" />
            )}
          </button>

          <span className="font-mono text-xs text-[#64748B]">
            {breakdown?.queryParameterCount ?? 0} query param(s) ·{' '}
            {breakdown?.subdomains.length ?? 0} subdomain label(s) ·{' '}
            {report.keywordMatches.length} keyword match(es)
          </span>
        </div>

        {detailsExpanded && (
          <div className="mt-5 space-y-6 border-t border-[#E2E8F0] pt-5">
            {breakdown && (
              <div className="space-y-4">
                <dl className="grid grid-cols-1 gap-3 text-xs lg:grid-cols-2">
                  <div className="rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] p-3.5">
                    <dt className="font-medium text-[#64748B]">Original Submitted URL</dt>
                    <dd className="mt-1 font-mono text-[#111827] break-all">
                      {breakdown.originalUrl}
                    </dd>
                  </div>
                  <div className="rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] p-3.5">
                    <dt className="font-medium text-[#64748B]">Normalized URL</dt>
                    <dd className="mt-1 font-mono text-[#111827] break-all">
                      {breakdown.normalizedUrl}
                    </dd>
                  </div>
                </dl>

                <dl className="grid grid-cols-1 gap-4 rounded-lg border border-[#E2E8F0] bg-white p-4 text-xs sm:grid-cols-2 lg:grid-cols-4">
                  <div>
                    <dt className="text-[#64748B]">Protocol & Port</dt>
                    <dd className="mt-1 font-mono font-medium text-[#111827]">
                      {breakdown.protocol.toUpperCase()} · {breakdown.port}
                      {breakdown.isUnusualPort ? ' (nonstandard)' : ''}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#64748B]">Hostname (Raw / Normalized)</dt>
                    <dd className="mt-1 font-mono font-medium text-[#111827] break-all">
                      {breakdown.hostnameCaseMixed
                        ? `${breakdown.hostnameRaw} -> ${breakdown.hostnameNormalized}`
                        : breakdown.hostnameNormalized}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#64748B]">Registrable Domain (PSL)</dt>
                    <dd className="mt-1 font-mono font-semibold text-[#111827] break-all">
                      {breakdown.registrableDomain}
                      {breakdown.publicSuffix ? ` (.${breakdown.publicSuffix})` : ''}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#64748B]">Subdomains ({breakdown.subdomains.length})</dt>
                    <dd className="mt-1 font-mono text-[#111827] break-all">
                      {breakdown.subdomains.length > 0 ? breakdown.subdomains.join(' · ') : 'None'}
                    </dd>
                  </div>
                  <div className="sm:col-span-2">
                    <dt className="text-[#64748B]">
                      Path & Decoded Path ({breakdown.pathEncodingLayers} decode layer
                      {breakdown.pathEncodingLayers === 1 ? '' : 's'})
                    </dt>
                    <dd className="mt-1 font-mono text-[#111827] break-all">
                      {breakdown.decodedPath}
                      {breakdown.rawPath !== breakdown.decodedPath
                        ? ` (raw: ${breakdown.rawPath})`
                        : ''}
                    </dd>
                  </div>
                  <div className="sm:col-span-2">
                    <dt className="text-[#64748B]">Encoding & Redirect Telemetry</dt>
                    <dd className="mt-1 font-mono text-[#111827]">
                      {Math.round(breakdown.encodedCharacterRatio * 100)}% encoded ·{' '}
                      {breakdown.redirectParameterCount} redirect param(s) ·{' '}
                      {breakdown.nestedUrlDetected ? 'Nested URL detected' : 'No nested URL'}
                    </dd>
                  </div>
                </dl>

                {/* Query Parameters Table */}
                {breakdown.queryParams.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-[#111827]">
                      Query Parameters Analysis
                    </h4>
                    <div className="mt-2 overflow-x-auto rounded-lg border border-[#E2E8F0]">
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="border-b border-[#E2E8F0] bg-[#F8FAFC] text-[#64748B]">
                            <th className="px-3 py-2 font-medium">Parameter</th>
                            <th className="px-3 py-2 font-medium">Decoded Value</th>
                            <th className="px-3 py-2 font-medium">Flags</th>
                            <th className="px-3 py-2 font-medium">Embedded URL</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {breakdown.queryParams.map((q, idx) => {
                            const flags: string[] = [];
                            if (q.isRedirectParam) flags.push('Redirect');
                            if (q.isAuthParam) flags.push('Auth');
                            if (q.isDuplicate) flags.push('Duplicate');
                            if (q.encodingLayers > 0) flags.push(`Encoded (${q.encodingLayers}x)`);
                            return (
                              <tr key={`${q.name}-${idx}`}>
                                <td className="px-3 py-2 font-mono font-medium text-[#111827] whitespace-nowrap">
                                  {q.name}
                                </td>
                                <td className="px-3 py-2 font-mono text-[#64748B] break-all max-w-xs">
                                  {q.decodedValue || '—'}
                                </td>
                                <td className="px-3 py-2 text-[#111827] whitespace-nowrap">
                                  {flags.length > 0 ? flags.join(' · ') : 'Standard'}
                                </td>
                                <td className="px-3 py-2 font-mono text-[#111827] break-all">
                                  {q.embeddedUrl
                                    ? `${q.embeddedUrl.hostname}${q.embeddedUrl.isExternal ? ' (external)' : ' (internal)'}`
                                    : 'None'}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Brand Similarity Table */}
                {breakdown.brandSimilarityResults.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-[#111827]">
                      Brand Impersonation & Lookalike Analysis
                    </h4>
                    <div className="mt-2 overflow-x-auto rounded-lg border border-[#E2E8F0]">
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="border-b border-[#E2E8F0] bg-[#F8FAFC] text-[#64748B]">
                            <th className="px-3 py-2 font-medium">Brand</th>
                            <th className="px-3 py-2 font-medium">Location & Match Type</th>
                            <th className="px-3 py-2 font-medium">Matched Token</th>
                            <th className="px-3 py-2 font-medium">Similarity</th>
                            <th className="px-3 py-2 font-medium">Official Domains</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {breakdown.brandSimilarityResults.map((b, idx) => (
                            <tr key={`${b.brand}-${b.location}-${idx}`}>
                              <td className="px-3 py-2 font-medium text-[#111827] whitespace-nowrap">
                                {b.brand}
                              </td>
                              <td className="px-3 py-2 text-[#64748B] whitespace-nowrap">
                                {b.location.replace(/_/g, ' ')} · {b.matchType.replace(/_/g, ' ')}
                              </td>
                              <td className="px-3 py-2 font-mono text-[#111827] whitespace-nowrap">
                                {b.matchedToken}
                              </td>
                              <td className="px-3 py-2 font-mono tabular-nums text-[#111827] whitespace-nowrap">
                                {Math.round(b.similarityScore * 100)}% (dist {b.editDistance})
                              </td>
                              <td className="px-3 py-2 font-mono text-[#64748B]">
                                {b.officialDomains.slice(0, 3).join(', ')}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Suspicious Keywords Table */}
            {report.keywordMatches.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold text-[#111827]">
                  Detected Suspicious Keywords
                </h4>
                <div className="mt-2 overflow-x-auto rounded-lg border border-[#E2E8F0]">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-[#E2E8F0] bg-[#F8FAFC] text-[#64748B]">
                        <th className="px-3 py-2 font-medium">Keyword</th>
                        <th className="px-3 py-2 font-medium">Category</th>
                        <th className="px-3 py-2 font-medium">Location</th>
                        <th className="px-3 py-2 font-medium">Security Rationale</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {report.keywordMatches.map((kw, idx) => (
                        <tr key={`${kw.location}-${kw.keyword}-${idx}`}>
                          <td className="px-3 py-2 font-mono font-semibold text-[#111827] whitespace-nowrap">
                            {kw.keyword}
                          </td>
                          <td className="px-3 py-2 text-[#111827] whitespace-nowrap">
                            {kw.category}
                          </td>
                          <td className="px-3 py-2 text-[#64748B] whitespace-nowrap">
                            {kw.location}
                          </td>
                          <td className="px-3 py-2 text-[#64748B]">{kw.rationale}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Risk Score Breakdown & Structural Telemetry */}
            <div className="grid grid-cols-1 gap-6 border-t border-[#E2E8F0] pt-5 md:grid-cols-2">
              <div>
                <h4 className="text-xs font-semibold text-[#111827]">Risk Score Breakdown</h4>
                <dl className="mt-2.5 space-y-1.5 text-xs">
                  <div className="flex justify-between py-1 border-b border-slate-100">
                    <dt className="text-[#64748B]">Threat Intelligence Contribution</dt>
                    <dd className="font-mono tabular-nums font-medium text-[#111827]">
                      +{report.scoringBreakdown.threatIntelPoints} pts
                    </dd>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-100">
                    <dt className="text-[#64748B]">Brand Impersonation & Lookalike</dt>
                    <dd className="font-mono tabular-nums font-medium text-[#111827]">
                      +{report.scoringBreakdown.brandImpersonationPoints ?? 0} pts
                    </dd>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-100">
                    <dt className="text-[#64748B]">ML Classifier Contribution</dt>
                    <dd className="font-mono tabular-nums font-medium text-[#111827]">
                      +{report.scoringBreakdown.mlPoints} pts
                    </dd>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-100">
                    <dt className="text-[#64748B]">URL Structure & Heuristics</dt>
                    <dd className="font-mono tabular-nums font-medium text-[#111827]">
                      +{report.scoringBreakdown.structuralPoints} pts
                    </dd>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-100">
                    <dt className="text-[#64748B]">Suspicious Keywords</dt>
                    <dd className="font-mono tabular-nums font-medium text-[#111827]">
                      +{report.scoringBreakdown.keywordPoints} pts
                    </dd>
                  </div>
                  <div className="flex justify-between py-1">
                    <dt className="text-[#64748B]">Isolated Website Inspection</dt>
                    <dd className="font-mono tabular-nums font-medium text-[#111827]">
                      +{report.scoringBreakdown.inspectionPoints} pts
                    </dd>
                  </div>
                </dl>
              </div>

              <div>
                <h4 className="text-xs font-semibold text-[#111827]">
                  URL Structural Telemetry & Inspection
                </h4>
                <dl className="mt-2.5 grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                  <div>
                    <dt className="text-[#64748B]">URL / Domain Length</dt>
                    <dd className="font-mono tabular-nums text-[#111827]">
                      {report.structuralSignals.urlLength} / {report.structuralSignals.domainLength} chars
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#64748B]">Character Entropy</dt>
                    <dd className="font-mono tabular-nums text-[#111827]">
                      {report.structuralSignals.charEntropy}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#64748B]">Punycode / Confusable</dt>
                    <dd className="font-mono text-[#111827]">
                      {report.structuralSignals.isPunycode ? 'Yes' : 'No'} /{' '}
                      {report.structuralSignals.unicodeConfusableDetected ? 'Yes' : 'No'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#64748B]">Shortener / @ Mask</dt>
                    <dd className="font-mono text-[#111827]">
                      {report.structuralSignals.isUrlShortener ? 'Yes' : 'No'} /{' '}
                      {report.structuralSignals.hasAtSymbol ? 'Yes' : 'No'}
                    </dd>
                  </div>
                </dl>
                <div className="mt-3 rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] p-3 text-xs text-[#64748B]">
                  <span className="font-medium text-[#111827]">Website Inspection: </span>
                  {report.websiteInspection.reason}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* D & E Side-by-Side: Machine Learning Analysis + Threat Intelligence Results */}
      <div className="grid grid-cols-1 divide-y divide-[#E2E8F0] lg:grid-cols-12 lg:divide-y-0 lg:divide-x">
        {/* D. Machine Learning Analysis (6 cols) */}
        <div className="lg:col-span-6 px-6 py-5">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 text-[#2563EB]" aria-hidden="true" />
              <h3 className="text-sm font-semibold text-[#111827]">
                D. Machine Learning Analysis
              </h3>
            </div>
            <span className="font-mono text-[11px] text-[#64748B]">
              v{report.mlPrediction.modelVersion}
            </span>
          </div>

          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] p-3">
              <div className="text-[11px] text-[#64748B]">Model Prediction</div>
              <div className="mt-1 text-sm font-semibold text-[#111827] capitalize">
                {report.mlPrediction.label}
              </div>
            </div>
            <div className="rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] p-3">
              <div className="text-[11px] text-[#64748B]">Phishing Probability</div>
              <div className="mt-1 font-mono text-sm font-semibold tabular-nums text-[#111827]">
                {Math.round(report.mlPrediction.probability * 100)}%
              </div>
            </div>
            <div className="rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] p-3">
              <div className="text-[11px] text-[#64748B]">ML Confidence</div>
              <div className="mt-1 font-mono text-sm font-semibold tabular-nums text-[#111827]">
                {report.mlPrediction.confidence}%
              </div>
            </div>
          </div>

          <p className="mt-2.5 text-[11px] leading-relaxed text-[#64748B]">
            Engine: {report.mlPrediction.engine}. ML Confidence measures statistical model certainty
            and is distinct from the composite Overall Risk Score ({report.riskScore}/100).
          </p>

          <h4 className="mt-4 text-xs font-semibold text-[#111827]">
            Top Extracted Feature Contributions
          </h4>
          <ul className="mt-2 divide-y divide-slate-100 text-xs">
            {report.mlPrediction.topFeatures.map((feat, idx) => (
              <li
                key={idx}
                className="flex items-center justify-between gap-3 py-2 first:pt-0 last:pb-0"
              >
                <span className="text-[#111827] truncate">
                  {feat.name}{' '}
                  <span className="font-mono text-[#64748B]">({feat.value})</span>
                </span>
                <span
                  className={`font-mono tabular-nums font-semibold shrink-0 ${
                    feat.contribution >= 0 ? 'text-red-700' : 'text-emerald-700'
                  }`}
                >
                  {feat.contribution >= 0 ? `+${feat.contribution}` : feat.contribution}
                </span>
              </li>
            ))}
          </ul>
        </div>

        {/* E. Threat Intelligence Results (6 cols) */}
        <div className="lg:col-span-6 px-6 py-5">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-[#2563EB]" aria-hidden="true" />
              <h3 className="text-sm font-semibold text-[#111827]">
                E. Threat Intelligence Results
              </h3>
            </div>
            <span className="font-mono text-[11px] tabular-nums text-[#64748B]">
              {report.threatIntelResults.filter((r) => r.status === 'match' || r.status === 'clean').length}
              /{report.threatIntelResults.length} checked
            </span>
          </div>

          <ul className="mt-4 space-y-2.5">
            {report.threatIntelResults.map((provider) => {
              const visual = getProviderStatusVisual(provider.status);
              const StatusIcon = visual.icon;
              return (
                <li
                  key={provider.provider}
                  className="rounded-lg border border-[#E2E8F0] bg-[#F8FAFC]/60 p-3"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 min-w-0">
                      <StatusIcon className={`h-4 w-4 shrink-0 ${visual.color}`} aria-hidden="true" />
                      <span className="text-xs font-semibold text-[#111827] truncate">
                        {provider.provider}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span
                        className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium ${visual.badge}`}
                      >
                        {visual.label}
                      </span>
                      <span className="font-mono text-[11px] tabular-nums text-[#64748B]">
                        {provider.latencyMs}ms
                      </span>
                    </div>
                  </div>
                  <p className="mt-1.5 pl-6 text-xs text-[#64748B]">{provider.message}</p>
                  {provider.threatCategory && (
                    <div className="mt-1 pl-6 text-[11px] font-medium text-red-700">
                      Category: {provider.threatCategory}
                      {provider.source ? ` · Source: ${provider.source}` : ''}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </section>
  );
}
