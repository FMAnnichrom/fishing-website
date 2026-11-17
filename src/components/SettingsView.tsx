import { useState } from 'react';
import { CheckCircle2, HelpCircle, Server, Settings as SettingsIcon, Sliders, Trash2 } from 'lucide-react';
import type { HealthResponse } from '../services/api';

export interface UiPreferences {
  pageSize: number;
  autoExpandUrlBreakdown: boolean;
}

interface SettingsViewProps {
  preferences: UiPreferences;
  onUpdatePreferences: (next: UiPreferences) => void;
  health: HealthResponse | null;
  healthLoading: boolean;
  onClearStandaloneHistory?: () => void;
}

export function SettingsView({
  preferences,
  onUpdatePreferences,
  health,
  healthLoading,
  onClearStandaloneHistory,
}: SettingsViewProps) {
  const [clearedMsg, setClearedMsg] = useState(false);
  const isStandalone = Boolean(health?.status.includes('standalone'));

  function handleClearLocalCache() {
    if (onClearStandaloneHistory) {
      onClearStandaloneHistory();
      setClearedMsg(true);
      setTimeout(() => setClearedMsg(false), 2500);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-[#E2E8F0] bg-white p-6 shadow-xs">
        <div className="flex items-start gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-blue-200 bg-blue-50 text-[#2563EB] shrink-0">
            <SettingsIcon className="h-5 w-5" aria-hidden="true" />
          </span>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-[#111827]">
              Workspace Settings & Runtime Configuration
            </h1>
            <p className="mt-1 text-sm text-[#64748B]">
              Manage analyst display preferences and inspect read-only backend security engine
              configuration.
            </p>
          </div>
        </div>
      </section>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left: Client Display Preferences */}
        <section className="lg:col-span-6 rounded-xl border border-[#E2E8F0] bg-white p-6 shadow-xs space-y-5">
          <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
            <Sliders className="h-4 w-4 text-[#2563EB]" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-[#111827]">Investigation Preferences</h2>
          </div>

          <div className="space-y-4">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <label htmlFor="pref-page-size" className="text-sm font-medium text-[#111827]">
                  Scan History Rows Per Page
                </label>
                <p className="text-xs text-[#64748B]">
                  Controls pagination density in Recent URL Scans and Scan History.
                </p>
              </div>
              <select
                id="pref-page-size"
                value={preferences.pageSize}
                onChange={(e) =>
                  onUpdatePreferences({
                    ...preferences,
                    pageSize: Number(e.target.value),
                  })
                }
                className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-mono text-[#111827] focus:border-[#2563EB] focus:outline-none"
              >
                <option value={5}>5 rows</option>
                <option value={10}>10 rows</option>
                <option value={15}>15 rows</option>
                <option value={25}>25 rows</option>
              </select>
            </div>

            <div className="flex items-start justify-between gap-4 border-t border-slate-100 pt-4">
              <div>
                <label
                  htmlFor="pref-auto-expand"
                  className="text-sm font-medium text-[#111827] cursor-pointer"
                >
                  Auto-Expand Advanced URL Breakdown
                </label>
                <p className="text-xs text-[#64748B]">
                  Automatically open PSL domain parsing, query parameter tables, and scoring
                  telemetry when inspecting a report.
                </p>
              </div>
              <input
                id="pref-auto-expand"
                type="checkbox"
                checked={preferences.autoExpandUrlBreakdown}
                onChange={(e) =>
                  onUpdatePreferences({
                    ...preferences,
                    autoExpandUrlBreakdown: e.target.checked,
                  })
                }
                className="mt-1 h-4 w-4 rounded border-slate-300 text-[#2563EB] focus:ring-[#2563EB]"
              />
            </div>

            {isStandalone && onClearStandaloneHistory && (
              <div className="border-t border-slate-100 pt-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="text-sm font-medium text-[#111827]">
                    Reset Local Standalone Cache
                  </div>
                  <p className="text-xs text-[#64748B]">
                    Clears browser-local scan history stored in static standalone mode and restores
                    baseline fixtures.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={handleClearLocalCache}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3.5 py-2 text-xs font-medium text-red-700 hover:bg-red-100 shrink-0"
                >
                  <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Clear Local Cache</span>
                </button>
              </div>
            )}

            {clearedMsg && (
              <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-3.5 py-2 text-xs text-emerald-800">
                Local standalone scan cache cleared and reset to baseline fixtures.
              </div>
            )}
          </div>
        </section>

        {/* Right: Read-Only Runtime & Server Environment Configuration */}
        <section className="lg:col-span-6 rounded-xl border border-[#E2E8F0] bg-white p-6 shadow-xs space-y-5">
          <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
            <Server className="h-4 w-4 text-[#2563EB]" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-[#111827]">
              Runtime Environment Status (Read-Only)
            </h2>
          </div>

          {healthLoading ? (
            <div className="space-y-2.5" aria-hidden="true">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="h-10 animate-pulse rounded-lg bg-slate-100" />
              ))}
            </div>
          ) : health ? (
            <div className="space-y-4">
              <dl className="divide-y divide-slate-100 text-xs">
                <div className="flex items-center justify-between py-2.5 first:pt-0">
                  <dt className="text-[#64748B]">Execution Mode</dt>
                  <dd className="font-mono font-medium text-[#111827]">{health.status}</dd>
                </div>
                <div className="flex items-center justify-between py-2.5">
                  <dt className="text-[#64748B]">ML Engine</dt>
                  <dd className="font-mono font-medium text-[#111827]">
                    {health.mlEngine.loaded ? `Loaded (v${health.mlEngine.version})` : 'Not Loaded'}
                  </dd>
                </div>
                <div className="flex items-center justify-between py-2.5">
                  <dt className="text-[#64748B]">External ML Service</dt>
                  <dd className="font-mono font-medium text-[#111827]">
                    {health.mlEngine.externalServiceConfigured ? 'Configured' : 'Local In-Process'}
                  </dd>
                </div>
                <div className="flex items-center justify-between py-2.5 last:pb-0">
                  <dt className="text-[#64748B]">Isolated Website Inspection</dt>
                  <dd className="font-mono font-medium text-[#111827]">
                    {health.websiteInspectionEnabled ? 'Enabled (SSRF Guarded)' : 'Disabled'}
                  </dd>
                </div>
              </dl>

              <div className="border-t border-slate-100 pt-3">
                <h3 className="text-xs font-semibold text-[#111827]">
                  Threat-Intelligence Providers
                </h3>
                <ul className="mt-2 space-y-2">
                  {health.threatIntelProviders.map((provider) => (
                    <li
                      key={provider.name}
                      className="flex items-center justify-between rounded-lg border border-[#E2E8F0] bg-[#F8FAFC] px-3 py-2 text-xs"
                    >
                      <span className="font-medium text-[#111827]">{provider.name}</span>
                      {provider.configured ? (
                        <span className="inline-flex items-center gap-1 font-medium text-emerald-700">
                          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>Configured</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 font-medium text-[#64748B]">
                          <HelpCircle className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>Env Key Not Set</span>
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
                <p className="mt-3 text-[11px] leading-relaxed text-[#64748B]">
                  For security, external API credentials are read exclusively from server
                  environment variables and are never exposed or edited in the browser.
                </p>
              </div>
            </div>
          ) : (
            <p className="text-xs text-[#64748B]">
              Unable to retrieve runtime health metadata from the server.
            </p>
          )}
        </section>
      </div>
    </div>
  );
}
