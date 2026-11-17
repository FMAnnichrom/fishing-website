import { Flag, ShieldCheck } from 'lucide-react';

export type ActiveTab = 'analyzer' | 'recent' | 'database' | 'model';

interface TopNavProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  onOpenReportModal: () => void;
}

export function TopNav({ activeTab, onSelectTab, onOpenReportModal }: TopNavProps) {
  const navItems: Array<{ id: ActiveTab; label: string }> = [
    { id: 'analyzer', label: 'Analyzer' },
    { id: 'recent', label: 'Recent Scans' },
    { id: 'database', label: 'Threat Database' },
    { id: 'model', label: 'ML Model' },
  ];

  return (
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-3 md:gap-8 px-4 py-3.5 sm:px-6">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            onSelectTab('analyzer');
          }}
          className="flex items-center gap-2 text-base sm:text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-blue-700"
        >
          <ShieldCheck className="h-5 w-5 text-blue-700 shrink-0" aria-hidden="true" />
          <span>Phishing URL Detector</span>
        </a>

        <nav aria-label="Primary navigation" className="hidden md:flex items-center gap-6">
          {navItems.map((item) => {
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectTab(item.id)}
                aria-current={active ? 'page' : undefined}
                className={`py-1.5 text-sm font-medium transition-colors whitespace-nowrap shrink-0 border-b-2 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-blue-700 ${
                  active
                    ? 'border-blue-700 text-slate-900'
                    : 'border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={onOpenReportModal}
            className="inline-flex items-center gap-1.5 sm:gap-2 rounded-lg border border-slate-300 bg-white px-3 py-1.5 sm:px-4 sm:py-2 text-xs sm:text-sm font-medium text-slate-800 transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-700"
          >
            <Flag className="h-3.5 w-3.5 sm:h-4 sm:w-4 text-slate-600 shrink-0" aria-hidden="true" />
            <span>Report URL</span>
          </button>
        </div>
      </div>

      {/* Compact mobile navigation row */}
      <nav
        aria-label="Mobile navigation"
        className="flex md:hidden items-center gap-4 overflow-x-auto border-t border-slate-100 px-4 py-2"
      >
        {navItems.map((item) => {
          const active = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onSelectTab(item.id)}
              aria-current={active ? 'page' : undefined}
              className={`py-1.5 text-sm font-medium whitespace-nowrap shrink-0 border-b-2 ${
                active
                  ? 'border-blue-700 text-slate-900'
                  : 'border-transparent text-slate-600'
              }`}
            >
              {item.label}
            </button>
          );
        })}
      </nav>
    </header>
  );
}
