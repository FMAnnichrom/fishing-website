import { Activity, AlertTriangle, Database, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { StatsSummary } from '../../shared/types';

interface StatsOverviewProps {
  summary: StatsSummary | null;
}

export function StatsOverview({ summary }: StatsOverviewProps) {
  const cards = [
    {
      label: 'Total URLs Analyzed',
      value: summary?.totalAnalyzed ?? 0,
      icon: Activity,
      iconBox: 'bg-blue-50 border-blue-200/80 text-[#2563EB]',
      valueColor: 'text-[#111827]',
    },
    {
      label: 'Malicious Detected',
      value: summary?.maliciousDetected ?? 0,
      icon: ShieldAlert,
      iconBox: 'bg-red-50 border-red-200/80 text-red-700',
      valueColor: 'text-red-700',
    },
    {
      label: 'Suspicious Detected',
      value: summary?.suspiciousDetected ?? 0,
      icon: AlertTriangle,
      iconBox: 'bg-amber-50 border-amber-200/80 text-amber-700',
      valueColor: 'text-amber-700',
    },
    {
      label: 'No Known Threat',
      value: summary?.noKnownThreat ?? 0,
      icon: ShieldCheck,
      iconBox: 'bg-emerald-50 border-emerald-200/80 text-emerald-700',
      valueColor: 'text-emerald-700',
    },
    {
      label: 'Threat Intelligence Matches',
      value: summary?.threatIntelMatches ?? 0,
      icon: Database,
      iconBox: 'bg-slate-100 border-slate-200 text-slate-700',
      valueColor: 'text-[#111827]',
    },
  ];

  return (
    <section aria-label="Threat detection metrics">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        {cards.map((card, index) => {
          const Icon = card.icon;
          const isLastOddMobile = index === cards.length - 1 ? 'col-span-2 md:col-span-1' : '';
          return (
            <div
              key={card.label}
              className={`rounded-xl border border-[#E2E8F0] bg-white px-4 py-3.5 sm:px-5 sm:py-4 shadow-xs flex items-start justify-between gap-2.5 ${isLastOddMobile}`}
            >
              <div className="min-w-0">
                <div className="text-xs font-medium text-[#64748B] leading-snug">{card.label}</div>
                {summary ? (
                  <div
                    className={`mt-2 text-2xl font-bold font-mono tabular-nums tracking-tight ${card.valueColor}`}
                  >
                    {card.value}
                  </div>
                ) : (
                  <div
                    aria-hidden="true"
                    className="mt-2.5 h-7 w-14 animate-pulse rounded bg-slate-100"
                  />
                )}
              </div>
              <span
                className={`flex h-8 w-8 sm:h-9 sm:w-9 items-center justify-center rounded-lg border shrink-0 ${card.iconBox}`}
              >
                <Icon className="h-4 w-4" aria-hidden="true" />
              </span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
