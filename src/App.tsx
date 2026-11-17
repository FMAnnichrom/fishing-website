import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import type {
  AnalysisReport,
  RecentScanItem,
  StatsSummary,
  UserReportRecord,
} from '../shared/types';
import { AboutDocsView } from './components/AboutDocsView';
import { AnalysisResultCard } from './components/AnalysisResultCard';
import { RecentScansSection } from './components/RecentScansSection';
import { ReportUrlModal } from './components/ReportUrlModal';
import { ScannerHero } from './components/ScannerHero';
import { SettingsView, type UiPreferences } from './components/SettingsView';
import { StatsOverview } from './components/StatsOverview';
import { ThreatDatabaseView } from './components/ThreatDatabaseView';
import { ThreatIntelSidebar } from './components/ThreatIntelSidebar';
import { TopNav, type ActiveTab } from './components/TopNav';
import {
  analyzeUrl,
  fetchAnalysisById,
  fetchHealth,
  fetchStatsAndRecent,
  fetchThreatFeeds,
  type HealthResponse,
} from './services/api';

const PREFS_STORAGE_KEY = 'phish_detector_ui_prefs_v1';
const DEFAULT_PREFS: UiPreferences = {
  pageSize: 10,
  autoExpandUrlBreakdown: false,
};

function readInitialPreferences(): UiPreferences {
  try {
    const raw = window.localStorage.getItem(PREFS_STORAGE_KEY);
    if (!raw) return DEFAULT_PREFS;
    const parsed = JSON.parse(raw) as Partial<UiPreferences>;
    return {
      pageSize:
        typeof parsed.pageSize === 'number' && [5, 10, 15, 25].includes(parsed.pageSize)
          ? parsed.pageSize
          : DEFAULT_PREFS.pageSize,
      autoExpandUrlBreakdown: Boolean(parsed.autoExpandUrlBreakdown),
    };
  } catch {
    return DEFAULT_PREFS;
  }
}

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [urlInput, setUrlInput] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentReport, setCurrentReport] = useState<AnalysisReport | null>(null);

  const [summary, setSummary] = useState<StatsSummary | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScanItem[]>([]);
  const [pendingReports, setPendingReports] = useState<UserReportRecord[]>([]);
  const [reportsById, setReportsById] = useState<Record<string, AnalysisReport>>({});
  const fetchedReportIdsRef = useRef<Set<string>>(new Set());

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthError, setHealthError] = useState(false);

  const [preferences, setPreferences] = useState<UiPreferences>(readInitialPreferences);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportPrefillUrl, setReportPrefillUrl] = useState('');

  const updatePreferences = useCallback((next: UiPreferences) => {
    setPreferences(next);
    try {
      window.localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(next));
    } catch {
      // Ignore storage quota / private-browsing errors
    }
  }, []);

  const hydrateScanReports = useCallback(async (scans: RecentScanItem[]) => {
    const targets = scans
      .slice(0, 12)
      .filter((scan) => !fetchedReportIdsRef.current.has(scan.id));
    if (targets.length === 0) return;

    for (const scan of targets) {
      fetchedReportIdsRef.current.add(scan.id);
    }

    const results = await Promise.allSettled(targets.map((s) => fetchAnalysisById(s.id)));
    const loaded: Record<string, AnalysisReport> = {};
    for (const res of results) {
      if (res.status === 'fulfilled') {
        loaded[res.value.id] = res.value;
      }
    }
    if (Object.keys(loaded).length > 0) {
      setReportsById((prev) => ({ ...prev, ...loaded }));
    }
  }, []);

  const loadDashboardData = useCallback(async () => {
    try {
      const [statsData, feedData] = await Promise.all([
        fetchStatsAndRecent(50),
        fetchThreatFeeds().catch(() => ({ indicators: [], pendingReports: [] })),
      ]);
      setSummary(statsData.summary);
      setRecentScans(statsData.recentScans);
      setPendingReports(feedData.pendingReports);
      void hydrateScanReports(statsData.recentScans);
    } catch {
      // Keep UI responsive if initial stats fail
    }
  }, [hydrateScanReports]);

  useEffect(() => {
    let active = true;
    fetchHealth()
      .then((data) => {
        if (!active) return;
        setHealth(data);
        setHealthError(false);
      })
      .catch(() => {
        if (!active) return;
        setHealthError(true);
      })
      .finally(() => {
        if (active) setHealthLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    void loadDashboardData();
  }, [loadDashboardData]);

  async function runAnalysis(targetUrl: string) {
    setError(null);
    setAnalyzing(true);
    try {
      const report = await analyzeUrl(targetUrl);
      fetchedReportIdsRef.current.add(report.id);
      setReportsById((prev) => ({ ...prev, [report.id]: report }));
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
    void runAnalysis(urlInput);
  }

  function handleClear() {
    setUrlInput('');
    setError(null);
    setCurrentReport(null);
  }

  async function handleSelectRecentScan(id: string) {
    setError(null);
    const cached = reportsById[id];
    if (cached) {
      setCurrentReport(cached);
      setUrlInput(cached.normalizedUrl);
      setActiveTab('dashboard');
      window.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }

    try {
      const report = await fetchAnalysisById(id);
      fetchedReportIdsRef.current.add(report.id);
      setReportsById((prev) => ({ ...prev, [report.id]: report }));
      setCurrentReport(report);
      setUrlInput(report.normalizedUrl);
      setActiveTab('dashboard');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load scan record.');
    }
  }

  function handleClearStandaloneHistory() {
    try {
      window.localStorage.removeItem('phish_detector_standalone_analyses_v1');
      window.localStorage.removeItem('phish_detector_standalone_reports_v1');
    } catch {
      // Ignore storage failures
    }
    fetchedReportIdsRef.current.clear();
    setReportsById({});
    setCurrentReport(null);
    void loadDashboardData();
  }

  function openReportDialog(prefill = '') {
    setReportPrefillUrl(prefill || urlInput);
    setReportModalOpen(true);
  }

  const inspectedReports = Object.values(reportsById);

  return (
    <div id="top" className="min-h-screen flex flex-col bg-[#F8FAFC] text-[#111827]">
      <TopNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenReportModal={() => openReportDialog()}
      />

      <main className="mx-auto w-[94%] max-w-[1760px] flex-1 py-6 sm:py-8">
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* 12-Column Hero URL Scanner + Security Engine Overview */}
            <ScannerHero
              urlInput={urlInput}
              onChangeUrl={setUrlInput}
              onSubmit={handleSubmit}
              onSelectSample={(sampleUrl) => {
                setUrlInput(sampleUrl);
                void runAnalysis(sampleUrl);
              }}
              onClear={handleClear}
              analyzing={analyzing}
              hasReport={Boolean(currentReport)}
              error={error}
              health={health}
              healthLoading={healthLoading}
              healthError={healthError}
            />

            {/* 5-Card Horizontal Statistics Overview */}
            <StatsOverview summary={summary} />

            {/* Active Security Investigation Report */}
            {currentReport && !analyzing && (
              <AnalysisResultCard
                report={currentReport}
                onReportCurrentUrl={(u) => openReportDialog(u)}
                defaultDetailsExpanded={preferences.autoExpandUrlBreakdown}
              />
            )}

            {/* Main 2-Column Body: ~70% Recent Scans + ~30% Threat Intel Sidebar */}
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-12 items-start">
              <div className="lg:col-span-8">
                <RecentScansSection
                  recentScans={recentScans}
                  reportsById={reportsById}
                  selectedScanId={currentReport?.id}
                  onSelectScan={handleSelectRecentScan}
                  pageSize={preferences.pageSize}
                />
              </div>
              <div className="lg:col-span-4">
                <ThreatIntelSidebar
                  health={health}
                  healthLoading={healthLoading}
                  recentScans={recentScans}
                  inspectedReports={inspectedReports}
                  pendingReports={pendingReports}
                  onSelectScan={handleSelectRecentScan}
                  onOpenThreatIntelTab={() => setActiveTab('threat-intel')}
                />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'history' && (
          <div className="space-y-6">
            <StatsOverview summary={summary} />
            <RecentScansSection
              recentScans={recentScans}
              reportsById={reportsById}
              selectedScanId={currentReport?.id}
              onSelectScan={handleSelectRecentScan}
              pageSize={preferences.pageSize}
              title="Complete Scan History"
              subtitle="Search, filter by domain or verdict, sort columns, and click any record to open its full report."
            />
          </div>
        )}

        {activeTab === 'threat-intel' && <ThreatDatabaseView />}

        {activeTab === 'docs' && <AboutDocsView />}

        {activeTab === 'settings' && (
          <SettingsView
            preferences={preferences}
            onUpdatePreferences={updatePreferences}
            health={health}
            healthLoading={healthLoading}
            onClearStandaloneHistory={handleClearStandaloneHistory}
          />
        )}
      </main>

      <footer className="border-t border-[#E2E8F0] bg-white">
        <div className="mx-auto flex w-[94%] max-w-[1760px] flex-col gap-2 py-5 text-xs text-[#64748B] sm:flex-row sm:items-center sm:justify-between">
          <span>
            Phishing URL Detector · Evidence-based security assessment combining ML, URL
            forensics, keywords, and threat intelligence.
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
        onSubmitted={() => void loadDashboardData()}
      />
    </div>
  );
}
