import { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Database,
  Flag,
  HelpCircle,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import type { AnalysisReport, ProviderStatus } from '../../shared/types';

interface AnalysisResultCardProps {
  report: AnalysisReport;
  onReportCurrentUrl: (url: string) => void;
}

function getVerdictTheme(verdict: AnalysisReport['verdict']) {
  switch (verdict) {
    case 'Malicious / Phishing':
      return {
        surface: 'bg-red-50 border-red-200 text-red-900',
        bar: 'bg-red-600',
        scoreText: 'text-red-700',
        icon: ShieldAlert,
        iconColor: 'text-red-700',
        classificationLabel: 'High Risk Threat',
      };
    case 'Suspicious':
      return {
        surface: 'bg-amber-50 border-amber-200 text-amber-950',
        bar: 'bg-amber-600',
        scoreText: 'text-amber-700',
        icon: AlertTriangle,
        iconColor: 'text-amber-700',
        classificationLabel: 'Suspicious Characteristics',
      };
    case 'No Known Threat Detected':
      return {
        surface: 'bg-emerald-50 border-emerald-200 text-emerald-950',
        bar: 'bg-emerald-600',
        scoreText: 'text-emerald-700',
        icon: ShieldCheck,
        iconColor: 'text-emerald-700',
        classificationLabel: 'No Known Threat Detected',
      };
    default:
      return {
        surface: 'bg-slate-100 border-slate-300 text-slate-900',
        bar: 'bg-slate-500',
        scoreText: 'text-slate-700',
        icon: HelpCircle,
        iconColor: 'text-slate-600',
        classificationLabel: 'Unable to Verify',
      };
  }
}

function formatBasisLabel(basis: AnalysisReport['scoringBreakdown']['classificationBasis']): string {
  switch (basis) {
    case 'confirmed_threat':
      return 'Confirmed Threat Intelligence Match';
    case 'high_risk_prediction':
      return 'High-Risk ML & Structural Prediction';
    case 'suspicious_signals':
      return 'Suspicious Signals Detected';
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
        label: 'Threat Match',
      };
    case 'clean':
      return {
        icon: CheckCircle2,
        color: 'text-emerald-700',
        label: 'No Match',
      };
    case 'not_configured':
      return {
        icon: HelpCircle,
        color: 'text-slate-500',
        label: 'Not Configured',
      };
    default:
      return {
        icon: AlertTriangle,
        color: 'text-amber-700',
        label: 'Unavailable',
      };
  }
}

export function AnalysisResultCard({ report, onReportCurrentUrl }: AnalysisResultCardProps) {
  const [detailsExpanded, setDetailsExpanded] = useState(false);
  const theme = getVerdictTheme(report.verdict);
  const VerdictIcon = theme.icon;

  return (
    <section
      aria-label="Security analysis result"
      className="rounded-xl border border-slate-200 bg-white overflow-hidden"
    >
      {/* Top verdict banner */}
      <div className={`border-b px-6 py-5 ${theme.surface}`}>
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-start gap-3.5 min-w-0">
            <VerdictIcon className={`h-7 w-7 mt-0.5 shrink-0 ${theme.iconColor}`} aria-hidden="true" />
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs font-medium text-slate-700">
                <span>{formatBasisLabel(report.scoringBreakdown.classificationBasis)}</span>
                <span aria-hidden="true">·</span>
                <time dateTime={report.analyzedAt} className="font-mono tabular-nums">
                  {new Date(report.analyzedAt).toLocaleString()}
                </time>
              </div>
              <h2 className="mt-1 text-2xl font-bold tracking-tight text-slate-900">
                {report.verdict}
              </h2>
              <p className="mt-1 font-mono text-xs text-slate-700 break-all">
                {report.normalizedUrl}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-5 shrink-0">
            <div className="text-left md:text-right">
              <div className="text-xs font-medium text-slate-600">Overall Risk Score</div>
              <div className={`text-3xl font-bold font-mono tabular-nums ${theme.scoreText}`}>
                {report.riskScore}
                <span className="text-base font-normal text-slate-500">/100</span>
              </div>
            </div>
          </div>
        </div>

        {/* Visual score bar */}
        <div className="mt-4">
          <div className="h-2 w-full rounded-full bg-white/80 border border-slate-200/80 overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${theme.bar}`}
              style={{ width: `${Math.max(3, report.riskScore)}%` }}
            />
          </div>
        </div>
      </div>

      {/* Key assessment metrics row */}
      <div className="grid grid-cols-1 divide-y divide-slate-200 border-b border-slate-200 sm:grid-cols-2 lg:grid-cols-4 sm:divide-y-0 sm:divide-x">
        <div className="px-6 py-4">
          <div className="text-xs font-medium text-slate-500">Extracted Domain</div>
          <div className="mt-1 font-mono text-sm font-semibold text-slate-900 break-all">
            {report.domain}
          </div>
          <div className="mt-0.5 text-xs text-slate-500">
            {report.structuralSignals.isHttps ? 'HTTPS transport' : 'Unencrypted HTTP'}
          </div>
        </div>

        <div className="px-6 py-4">
          <div className="text-xs font-medium text-slate-500">ML Model Prediction</div>
          <div className="mt-1 text-sm font-semibold text-slate-900 capitalize">
            {report.mlPrediction.label === 'unavailable'
              ? 'Unavailable'
              : `${report.mlPrediction.label} (${Math.round(report.mlPrediction.probability * 100)}%)`}
          </div>
          <div className="mt-0.5 text-xs text-slate-500 font-mono tabular-nums">
            Model confidence: {report.mlPrediction.confidence}%
          </div>
        </div>

        <div className="px-6 py-4">
          <div className="text-xs font-medium text-slate-500">Known Threat Databases</div>
          <div className="mt-1 flex items-center gap-1.5 text-sm font-semibold text-slate-900">
            <Database className="h-4 w-4 text-slate-500 shrink-0" aria-hidden="true" />
            <span>{report.inKnownThreatDatabase ? 'Match Found' : 'No Match Found'}</span>
          </div>
          <div className="mt-0.5 text-xs text-slate-500">
            {report.threatIntelResults.filter((r) => r.status === 'match' || r.status === 'clean').length}{' '}
            of {report.threatIntelResults.length} sources queried
          </div>
        </div>

        <div className="px-6 py-4">
          <div className="text-xs font-medium text-slate-500">Suspicious Keywords</div>
          <div className="mt-1 text-sm font-semibold text-slate-900 font-mono tabular-nums">
            {report.keywordMatches.length} detected
          </div>
          <div className="mt-0.5 text-xs text-slate-500">
            {report.keywordMatches.length === 0
              ? 'No risky keywords matched'
              : Array.from(new Set(report.keywordMatches.map((k) => k.category))).slice(0, 2).join(', ')}
          </div>
        </div>
      </div>

      {/* Recommended action & honest safety caveat */}
      <div className="border-b border-slate-200 px-6 py-5 bg-slate-50/50">
        <h3 className="text-sm font-semibold text-slate-900">Recommended Action</h3>
        <p className="mt-1.5 text-sm leading-relaxed text-slate-700">{report.recommendedAction}</p>
        <p className="mt-2 text-xs text-slate-500">{report.disclaimer}</p>
      </div>

      {/* Flagged Reasons & Threat Intelligence Sources */}
      <div className="grid grid-cols-1 divide-y divide-slate-200 lg:grid-cols-2 lg:divide-y-0 lg:divide-x border-b border-slate-200">
        <div className="px-6 py-5">
          <h3 className="text-sm font-semibold text-slate-900">Specific Reasons & Signals</h3>
          <ul className="mt-3 space-y-2.5 text-sm text-slate-700">
            {report.flaggedReasons.map((reason, idx) => (
              <li key={idx} className="flex items-start gap-2.5">
                <span className="mt-1.5 h-1.5 w-1.5 rounded-full bg-slate-400 shrink-0" aria-hidden="true" />
                <span className="leading-relaxed">{reason}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="px-6 py-5">
          <h3 className="text-sm font-semibold text-slate-900">Threat-Intelligence Sources Checked</h3>
          <ul className="mt-3 divide-y divide-slate-100">
            {report.threatIntelResults.map((provider) => {
              const visual = getProviderStatusVisual(provider.status);
              const StatusIcon = visual.icon;
              return (
                <li key={provider.provider} className="py-2.5 first:pt-0 last:pb-0">
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2 min-w-0">
                      <StatusIcon className={`h-4 w-4 shrink-0 ${visual.color}`} aria-hidden="true" />
                      <span className="text-sm font-medium text-slate-900 truncate">
                        {provider.provider}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-xs shrink-0">
                      <span className={`font-medium ${visual.color}`}>{visual.label}</span>
                      <span aria-hidden="true" className="text-slate-300">·</span>
                      <span className="font-mono tabular-nums text-slate-500">{provider.latencyMs}ms</span>
                    </div>
                  </div>
                  <p className="mt-1 pl-6 text-xs text-slate-600">{provider.message}</p>
                </li>
              );
            })}
          </ul>
        </div>
      </div>

      {/* Suspicious Keywords Table (if any detected) */}
      {report.keywordMatches.length > 0 && (
        <div className="border-b border-slate-200 px-6 py-5">
          <h3 className="text-sm font-semibold text-slate-900">Detected Suspicious Keywords</h3>
          <p className="mt-1 text-xs text-slate-500">
            Keywords alone do not mark a site malicious; they are weighted alongside ML and structural evidence.
          </p>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs font-medium text-slate-500">
                  <th className="pb-2 pr-4">Keyword</th>
                  <th className="pb-2 pr-4">Category</th>
                  <th className="pb-2 pr-4">Location</th>
                  <th className="pb-2">Why It May Be Suspicious</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {report.keywordMatches.map((kw, idx) => (
                  <tr key={`${kw.location}-${kw.keyword}-${idx}`}>
                    <td className="py-2.5 pr-4 font-mono text-xs font-semibold text-slate-900 whitespace-nowrap">
                      {kw.keyword}
                    </td>
                    <td className="py-2.5 pr-4 text-xs text-slate-700 whitespace-nowrap">{kw.category}</td>
                    <td className="py-2.5 pr-4 text-xs text-slate-600 whitespace-nowrap">{kw.location}</td>
                    <td className="py-2.5 text-xs text-slate-600">{kw.rationale}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Expandable Detection Details & Actions Footer */}
      <div className="px-6 py-4 bg-white">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <button
            type="button"
            aria-expanded={detailsExpanded}
            onClick={() => setDetailsExpanded((v) => !v)}
            className="inline-flex items-center gap-1.5 text-sm font-medium text-blue-700 hover:text-blue-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-700"
          >
            {detailsExpanded ? (
              <ChevronUp className="h-4 w-4" aria-hidden="true" />
            ) : (
              <ChevronDown className="h-4 w-4" aria-hidden="true" />
            )}
            <span>{detailsExpanded ? 'Hide Detection Details' : 'Show Detection Details'}</span>
          </button>

          <button
            type="button"
            onClick={() => onReportCurrentUrl(report.normalizedUrl)}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-700"
          >
            <Flag className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Report URL for Review</span>
          </button>
        </div>

        {detailsExpanded && (
          <div className="mt-5 grid grid-cols-1 gap-6 border-t border-slate-200 pt-5 md:grid-cols-2">
            {/* Scoring Breakdown & Structural Features */}
            <div>
              <h4 className="text-xs font-semibold text-slate-900">Risk Score Breakdown</h4>
              <dl className="mt-2.5 space-y-1.5 text-xs">
                <div className="flex justify-between py-1 border-b border-slate-100">
                  <dt className="text-slate-600">Threat Intelligence Contribution</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900">
                    +{report.scoringBreakdown.threatIntelPoints} pts
                  </dd>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-100">
                  <dt className="text-slate-600">ML Classifier Contribution</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900">
                    +{report.scoringBreakdown.mlPoints} pts
                  </dd>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-100">
                  <dt className="text-slate-600">URL Structure Anomalies</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900">
                    +{report.scoringBreakdown.structuralPoints} pts
                  </dd>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-100">
                  <dt className="text-slate-600">Suspicious Keywords</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900">
                    +{report.scoringBreakdown.keywordPoints} pts
                  </dd>
                </div>
                <div className="flex justify-between py-1">
                  <dt className="text-slate-600">Isolated Website Inspection</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900">
                    +{report.scoringBreakdown.inspectionPoints} pts
                  </dd>
                </div>
              </dl>

              <h4 className="mt-5 text-xs font-semibold text-slate-900">URL Structural Telemetry</h4>
              <dl className="mt-2.5 grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                <div>
                  <dt className="text-slate-500">URL Length</dt>
                  <dd className="font-mono tabular-nums text-slate-900">{report.structuralSignals.urlLength} chars</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Domain Length</dt>
                  <dd className="font-mono tabular-nums text-slate-900">{report.structuralSignals.domainLength} chars</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Subdomains / Hyphens</dt>
                  <dd className="font-mono tabular-nums text-slate-900">
                    {report.structuralSignals.subdomainCount} / {report.structuralSignals.hyphenCount}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500">Character Entropy</dt>
                  <dd className="font-mono tabular-nums text-slate-900">{report.structuralSignals.charEntropy}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Punycode / IP Literal</dt>
                  <dd className="font-mono text-slate-900">
                    {report.structuralSignals.isPunycode ? 'Yes' : 'No'} /{' '}
                    {report.structuralSignals.hasIpAddress ? 'Yes' : 'No'}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500">Shortener / @ Mask</dt>
                  <dd className="font-mono text-slate-900">
                    {report.structuralSignals.isUrlShortener ? 'Yes' : 'No'} /{' '}
                    {report.structuralSignals.hasAtSymbol ? 'Yes' : 'No'}
                  </dd>
                </div>
              </dl>
            </div>

            {/* ML Top Contributing Features & Website Inspection Status */}
            <div>
              <h4 className="text-xs font-semibold text-slate-900">
                ML Feature Contributions ({report.mlPrediction.engine})
              </h4>
              <ul className="mt-2.5 space-y-1.5 text-xs">
                {report.mlPrediction.topFeatures.map((feat, idx) => (
                  <li
                    key={idx}
                    className="flex items-center justify-between gap-3 py-1 border-b border-slate-100 last:border-b-0"
                  >
                    <span className="text-slate-700 truncate">
                      {feat.name} <span className="text-slate-400">({feat.value})</span>
                    </span>
                    <span
                      className={`font-mono tabular-nums font-medium shrink-0 ${
                        feat.contribution >= 0 ? 'text-red-700' : 'text-emerald-700'
                      }`}
                    >
                      {feat.contribution >= 0 ? `+${feat.contribution}` : feat.contribution}
                    </span>
                  </li>
                ))}
              </ul>

              <h4 className="mt-5 text-xs font-semibold text-slate-900">Isolated Website Inspection</h4>
              <p className="mt-1.5 text-xs leading-relaxed text-slate-600">
                {report.websiteInspection.reason}
              </p>
              {report.websiteInspection.status === 'completed' && report.websiteInspection.pageTitle && (
                <div className="mt-2 text-xs text-slate-700">
                  <span className="font-medium">Page Title:</span> {report.websiteInspection.pageTitle}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
