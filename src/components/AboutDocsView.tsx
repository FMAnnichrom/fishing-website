import { BookOpen, Cpu, Database, GlobeLock, Layers, ShieldAlert, ShieldCheck } from 'lucide-react';
import { ModelEvaluationView } from './ModelEvaluationView';

export function AboutDocsView() {
  const layers = [
    {
      icon: Layers,
      title: '1. URL Normalization & Public Suffix List (PSL) Parser',
      description:
        'Parses every submitted URL using the Public Suffix List (tldts) to separate subdomains, actual registrable domain, ports, decoded paths, fragments, and query parameters. Detects multi-layer percent encoding, uppercase hostname masking, and nested redirect targets.',
    },
    {
      icon: ShieldAlert,
      title: '2. Brand Impersonation & Lookalike Detection',
      description:
        'Evaluates hostnames, subdomains, paths, and redirect query parameters against protected brands. Identifies subdomain confusion (e.g., accounts.google.com.login.example.test), Unicode homoglyphs, punycode, leetspeak substitutions, and low edit-distance typosquats.',
    },
    {
      icon: Cpu,
      title: '3. Machine Learning Classifier (v2.0.0)',
      description:
        'Combines 34 normalized structural URL signals with TF-IDF character 3–4 gram features using L2-regularized logistic regression trained on domain-grouped, leak-free dataset splits. Outputs phishing probability and feature-level explanations.',
    },
    {
      icon: Database,
      title: '4. Threat-Intelligence & Keyword Databases',
      description:
        'Queries configured threat-intelligence feeds (Local Threat Feed Index, Google Safe Browsing v4, PhishTank, URLhaus) and evaluates weighted phishing/credential-lure keywords across decoded URL surfaces.',
    },
    {
      icon: GlobeLock,
      title: '5. SSRF-Protected Website Inspection & Honest Verdicts',
      description:
        'When server-side inspection is enabled, fetches target pages in an isolated, private-IP-blocked sandbox to inspect login/payment forms. Combined verdicts never claim a site is guaranteed safe simply because no threat database match was found.',
    },
  ];

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-[#E2E8F0] bg-white p-6 shadow-xs">
        <div className="flex items-start gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-blue-200 bg-blue-50 text-[#2563EB] shrink-0">
            <BookOpen className="h-5 w-5" aria-hidden="true" />
          </span>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-[#111827]">
              Detection Architecture & Documentation
            </h1>
            <p className="mt-1 max-w-3xl text-sm leading-relaxed text-[#64748B]">
              Phishing URL Detector combines deterministic URL forensics, machine learning, and
              threat-intelligence feeds into an evidence-based security assessment without
              requiring the user to open suspicious links.
            </p>
          </div>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {layers.map((layer) => {
            const Icon = layer.icon;
            return (
              <article
                key={layer.title}
                className="rounded-xl border border-[#E2E8F0] bg-[#F8FAFC] p-5"
              >
                <div className="flex items-center gap-2.5">
                  <Icon className="h-4 w-4 text-[#2563EB] shrink-0" aria-hidden="true" />
                  <h2 className="text-sm font-semibold text-[#111827]">{layer.title}</h2>
                </div>
                <p className="mt-2.5 text-xs leading-relaxed text-[#64748B]">
                  {layer.description}
                </p>
              </article>
            );
          })}

          <article className="rounded-xl border border-[#E2E8F0] bg-[#F8FAFC] p-5">
            <div className="flex items-center gap-2.5">
              <ShieldCheck className="h-4 w-4 text-emerald-700 shrink-0" aria-hidden="true" />
              <h2 className="text-sm font-semibold text-[#111827]">Verdict Scale & Limitations</h2>
            </div>
            <ul className="mt-2.5 space-y-1.5 text-xs text-[#64748B]">
              <li>
                <strong className="text-[#111827]">Confirmed Malicious:</strong> Verified match in a
                trusted threat-intelligence feed.
              </li>
              <li>
                <strong className="text-[#111827]">High Risk / Suspicious:</strong> Deceptive
                patterns, impersonation, redirects, or high ML risk signals.
              </li>
              <li>
                <strong className="text-[#111827]">No Known Threat:</strong> No threats found in
                checked sources; never a guarantee of absolute safety.
              </li>
            </ul>
          </article>
        </div>
      </section>

      {/* Live ML Model Metrics & Confusion Matrix */}
      <ModelEvaluationView />
    </div>
  );
}
