import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Loader2, Search, X } from 'lucide-react';
import type { AnalysisReport, RecentScanItem, StatsSummary } from '../shared/types';
import { AnalysisResultCard } from './components/AnalysisResultCard';
import { ModelEvaluationView } from './components/ModelEvaluationView';
import { RecentScansSection } from './components/RecentScansSection';
import { ReportUrlModal } from './components/ReportUrlModal';
import { ThreatDatabaseView } from './components/ThreatDatabaseView';
import { TopNav, type ActiveTab } from './components/TopNav';
import { analyzeUrl, fetchAnalysisById, fetchStatsAndRecent } from './services/api';

const SAFE_TEST_EXAMPLES = [
  {
    label: 'Legitimate reference',
    url: 'https://www.wikipedia.org/wiki/Phishing',
  },
  {
    label: 'Suspicious phishing pattern',
    url: 'http://secure-paypal-login-verify.xyz/account/update?confirm-identity=1',
  },
  {
    label: 'Safe threat-feed fixture',
    url: 'http://testsafebrowsing.appspot.com/s/phishing.html',
  },
  {
    label: 'Punycode homograph test',
    url: 'http://xn--pple-43d.com/support/reset-password?urgent-action=true',
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('analyzer');
  const [urlInput, setUrlInput] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentReport, setCurrentReport] = useState<AnalysisReport | null>(null);

  const [summary, setSummary] = useState<StatsSummary | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScanItem[]>([]);

  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportPrefillUrl, setReportPrefillUrl] = useState('');

  const loadDashboardData = useCallback(async () => {
    try {
      const data = await fetchStatsAndRecent(15);
      setSummary(data.summary);
      setRecentScans(data.recentScans);
    } catch {
      // Keep UI functional even if initial stats fail
    }
  }, []);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  async function runAnalysis(targetUrl: string) {
    setError(null);
    setAnalyzing(true);
    try {
      const report = await analyzeUrl(targetUrl);
      setCurrentReport(report);
      await loadDashboardData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to analyze URL.');
    } finally {
      setAnalyzing(false);
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    runAnalysis(urlInput);
  }

  function handleClear() {
    setUrlInput('');
    setError(null);
    setCurrentReport(null);
  }

  async function handleSelectRecentScan(id: string) {
    setError(null);
    try {
      const report = await fetchAnalysisById(id);
      setCurrentReport(report);
      setUrlInput(report.normalizedUrl);
      setActiveTab('analyzer');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load scan record.');
    }
  }

  function openReportDialog(prefill = '') {
    setReportPrefillUrl(prefill || urlInput);
    setReportModalOpen(true);
  }

  return (
    <div id="top" className="min-h-screen flex flex-col bg-slate-50 text-slate-900">
      <TopNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenReportModal={() => openReportDialog()}
      />

      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6">
        {activeTab === 'analyzer' && (
          <div className="space-y-8">
            {/* Primary URL Analyzer Hero Card */}
            <section className="rounded-xl border border-slate-200 bg-white px-6 py-8 sm:px-8">
              <div className="max-w-3xl">
                <h1 className="text-3xl font-bold tracking-tight text-slate-900 sm:text-4xl text-balance">
                  Phishing URL Detector
                </h1>
                <p className="mt-2.5 text-base leading-relaxed text-slate-600">
                  Paste any website link below to evaluate phishing risk using machine learning,
                  threat-intelligence databases, URL structure inspection, and suspicious keyword
                  analysis.
                </p>
              </div>

              <form onSubmit={handleSubmit} className="mt-6">
                <label htmlFor="url-input" className="sr-only">
                  Website URL to analyze
                </label>
                <div className="flex flex-col gap-3 sm:flex-row">
                  <div className="relative flex-1">
                    <Search
                      className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400"
                      aria-hidden="true"
                    />
                    <input
                      id="url-input"
                      type="text"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="Paste a website URL here..."
                      autoComplete="off"
                      spellCheck={false}
                      className="w-full rounded-lg border border-slate-300 bg-white py-3.5 pl-11 pr-10 font-mono text-sm text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-700/15"
                    />
                    {urlInput && (
                      <button
                        type="button"
                        onClick={handleClear}
                        aria-label="Clear URL input"
                        className="absolute right-3 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 hover:text-slate-700"
                      >
                        <X className="h-4 w-4" aria-hidden="true" />
                      </button>
                    )}
                  </div>

                  <div className="flex items-center gap-2.5 shrink-0">
                    <button
                      type="submit"
                      disabled={analyzing}
                      className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-700 px-6 py-3.5 text-sm font-semibold text-white transition-colors hover:bg-blue-800 disabled:opacity-60 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-700"
                    >
                      {analyzing && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                      <span>{analyzing ? 'Analyzing...' : 'Analyze URL'}</span>
                    </button>

                    {(urlInput || currentReport) && (
                      <button
                        type="button"
                        onClick={handleClear}
                        disabled={analyzing}
                        className="rounded-lg border border-slate-300 bg-white px-4 py-3.5 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0"
                      >
                        Clear
                      </button>
                    )}
                  </div>
                </div>
              </form>

              {/* Safe quick-test samples */}
              <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-500">
                <span>Try a safe test URL:</span>
                {SAFE_TEST_EXAMPLES.map((sample) => (
                  <button
                    key={sample.url}
                    type="button"
                    onClick={() => {
                      setUrlInput(sample.url);
                      runAnalysis(sample.url);
                    }}
                    className="font-medium text-blue-700 hover:text-blue-800 hover:underline focus-visible:outline-2 focus-visible:outline-blue-700"
                  >
                    {sample.label}
                  </button>
                ))}
              </div>

              {/* Error feedback */}
              {error && (
                <div
                  role="alert"
                  className="mt-5 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800"
                >
                  {error}
                </div>
              )}

              {/* Loading feedback */}
              {analyzing && (
                <div
                  role="status"
                  aria-live="polite"
                  className="mt-6 rounded-lg border border-slate-200 bg-slate-50 px-5 py-4"
                >
                  <div className="flex items-center gap-3 text-sm font-medium text-slate-800">
                    <Loader2 className="h-4 w-4 animate-spin text-blue-700" aria-hidden="true" />
                    <span>
                      Running URL normalization, ML classification, keyword extraction, and
                      threat-intelligence checks...
                    </span>
                  </div>
                </div>
              )}
            </section>

            {/* Analysis Results */}
            {currentReport && !analyzing && (
              <AnalysisResultCard
                report={currentReport}
                onReportCurrentUrl={(u) => openReportDialog(u)}
              />
            )}

            {/* Threat Statistics & Recent Scans */}
            <RecentScansSection
              summary={summary}
              recentScans={recentScans}
              onSelectScan={handleSelectRecentScan}
            />
          </div>
        )}

        {activeTab === 'recent' && (
          <RecentScansSection
            summary={summary}
            recentScans={recentScans}
            onSelectScan={handleSelectRecentScan}
          />
        )}

        {activeTab === 'database' && <ThreatDatabaseView />}

        {activeTab === 'model' && <ModelEvaluationView />}
      </main>

      <footer className="border-t border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl flex-col gap-2 px-4 py-5 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <span>
            Phishing URL Detector · Evidence-based security assessment combining ML, keywords, and
            threat intelligence.
          </span>
          <span>
            Automated detection assists security decisions and does not guarantee absolute safety.
          </span>
        </div>
      </footer>

      <ReportUrlModal
        open={reportModalOpen}
        initialUrl={reportPrefillUrl}
        onClose={() => setReportModalOpen(false)}
        onSubmitted={loadDashboardData}
      />
    </div>
  );
}
