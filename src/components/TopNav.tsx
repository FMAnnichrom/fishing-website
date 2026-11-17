import { useState } from 'react';
import { Flag, Menu, ShieldCheck, X } from 'lucide-react';

export type ActiveTab = 'dashboard' | 'history' | 'threat-intel' | 'docs' | 'settings';

interface TopNavProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  onOpenReportModal: () => void;
}

const NAV_ITEMS: Array<{ id: ActiveTab; label: string }> = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'history', label: 'Scan History' },
  { id: 'threat-intel', label: 'Threat Intelligence' },
  { id: 'docs', label: 'About / Documentation' },
  { id: 'settings', label: 'Settings' },
];

export function TopNav({ activeTab, onSelectTab, onOpenReportModal }: TopNavProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  function handleSelect(tab: ActiveTab) {
    onSelectTab(tab);
    setMobileMenuOpen(false);
  }

  return (
    <header className="border-b border-[#E2E8F0] bg-white">
      <div className="mx-auto flex w-[94%] max-w-[1760px] items-center justify-between gap-4 py-3">
        {/* Left Brand Block */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            handleSelect('dashboard');
          }}
          className="flex items-center gap-3 shrink-0 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#2563EB]"
        >
          <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-blue-200 bg-blue-50 text-[#2563EB]">
            <ShieldCheck className="h-5 w-5" aria-hidden="true" />
          </span>
          <span className="flex flex-col">
            <span className="text-base font-bold tracking-tight text-[#111827] leading-tight whitespace-nowrap">
              Phishing URL Detector
            </span>
            <span className="text-[11px] font-medium text-[#64748B] leading-tight whitespace-nowrap">
              AI-Powered Threat Intelligence
            </span>
          </span>
        </a>

        {/* Center/Right Desktop Navigation Links */}
        <nav aria-label="Primary navigation" className="hidden lg:flex items-center gap-1">
          {NAV_ITEMS.map((item) => {
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleSelect(item.id)}
                aria-current={active ? 'page' : undefined}
                className={`relative px-3.5 py-2 text-sm font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#2563EB] ${
                  active
                    ? 'bg-blue-50/80 text-[#2563EB]'
                    : 'text-[#64748B] hover:bg-slate-50 hover:text-[#111827]'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Right Action + Mobile Toggle */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={onOpenReportModal}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[#E2E8F0] bg-white px-3.5 py-2 text-xs sm:text-sm font-medium text-[#111827] transition-colors hover:border-slate-300 hover:bg-slate-50 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#2563EB]"
          >
            <Flag className="h-3.5 w-3.5 sm:h-4 sm:w-4 text-[#64748B] shrink-0" aria-hidden="true" />
            <span>Report URL</span>
          </button>

          <button
            type="button"
            onClick={() => setMobileMenuOpen((v) => !v)}
            aria-expanded={mobileMenuOpen}
            aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            className="inline-flex lg:hidden items-center justify-center rounded-lg border border-[#E2E8F0] bg-white p-2 text-[#111827] hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-[#2563EB]"
          >
            {mobileMenuOpen ? (
              <X className="h-4 w-4" aria-hidden="true" />
            ) : (
              <Menu className="h-4 w-4" aria-hidden="true" />
            )}
          </button>
        </div>
      </div>

      {/* Responsive Tablet/Mobile Menu Drawer */}
      {mobileMenuOpen && (
        <nav
          aria-label="Mobile navigation"
          className="lg:hidden border-t border-[#E2E8F0] bg-white px-4 py-2.5"
        >
          <div className="mx-auto flex w-full max-w-[1760px] flex-col gap-1">
            {NAV_ITEMS.map((item) => {
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleSelect(item.id)}
                  aria-current={active ? 'page' : undefined}
                  className={`w-full text-left rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                    active
                      ? 'bg-blue-50 text-[#2563EB]'
                      : 'text-[#64748B] hover:bg-slate-50 hover:text-[#111827]'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </div>
        </nav>
      )}
    </header>
  );
}
