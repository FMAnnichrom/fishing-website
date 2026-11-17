import { useEffect, useState } from 'react';
import { Cpu } from 'lucide-react';
import type { ModelEvaluationReport } from '../../shared/types';
import { fetchModelEvaluation } from '../services/api';

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

export function ModelEvaluationView() {
  const [report, setReport] = useState<ModelEvaluationReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    fetchModelEvaluation()
      .then((data) => {
        if (active) setReport(data);
      })
      .catch((err) => {
        if (active) setError(err instanceof Error ? err.message : 'Failed to load evaluation.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  if (loading) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-8 text-sm text-slate-500">
        Loading ML model evaluation metrics...
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="rounded-xl border border-red-200 bg-red-50 p-6 text-sm text-red-800">
        {error || 'Trained ML model metadata unavailable.'}
      </div>
    );
  }

  const tm = report.testMetrics;
  const cm = tm.confusionMatrix;

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-6">
        <div className="flex items-start gap-3">
          <Cpu className="h-5 w-5 text-blue-700 mt-0.5 shrink-0" aria-hidden="true" />
          <div>
            <h2 className="text-lg font-semibold text-slate-900">
              Machine Learning Model & Evaluation
            </h2>
            <p className="mt-1 text-sm text-slate-600">{report.algorithm}</p>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <span>Model v{report.modelVersion}</span>
              <span aria-hidden="true">·</span>
              <span>{report.featureCount} total features</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums">
                Trained {new Date(report.trainedAt).toLocaleString()}
              </span>
            </div>
          </div>
        </div>

        {/* Held-out Test Set Metrics */}
        <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
          <div className="rounded-lg border border-slate-200 px-4 py-3">
            <div className="text-xs text-slate-500">Test Accuracy</div>
            <div className="mt-1 text-xl font-bold font-mono tabular-nums text-slate-900">
              {pct(tm.accuracy)}
            </div>
          </div>
          <div className="rounded-lg border border-slate-200 px-4 py-3">
            <div className="text-xs text-slate-500">Precision</div>
            <div className="mt-1 text-xl font-bold font-mono tabular-nums text-slate-900">
              {pct(tm.precision)}
            </div>
          </div>
          <div className="rounded-lg border border-slate-200 px-4 py-3">
            <div className="text-xs text-slate-500">Recall</div>
            <div className="mt-1 text-xl font-bold font-mono tabular-nums text-slate-900">
              {pct(tm.recall)}
            </div>
          </div>
          <div className="rounded-lg border border-slate-200 px-4 py-3">
            <div className="text-xs text-slate-500">F1-Score</div>
            <div className="mt-1 text-xl font-bold font-mono tabular-nums text-slate-900">
              {pct(tm.f1Score)}
            </div>
          </div>
          <div className="rounded-lg border border-slate-200 px-4 py-3">
            <div className="text-xs text-slate-500">False Positive Rate</div>
            <div className="mt-1 text-xl font-bold font-mono tabular-nums text-slate-900">
              {pct(tm.falsePositiveRate)}
            </div>
          </div>
          <div className="rounded-lg border border-slate-200 px-4 py-3">
            <div className="text-xs text-slate-500">False Negative Rate</div>
            <div className="mt-1 text-xl font-bold font-mono tabular-nums text-slate-900">
              {pct(tm.falseNegativeRate)}
            </div>
          </div>
        </div>
      </section>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Dataset Split & Confusion Matrix */}
        <section className="rounded-xl border border-slate-200 bg-white p-6 space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-slate-900">
              Leak-Free Dataset Splits (Grouped by Domain)
            </h3>
            <dl className="mt-3 space-y-2 text-xs">
              <div className="flex justify-between border-b border-slate-100 py-1.5">
                <dt className="text-slate-600">Deduplicated Labeled URLs</dt>
                <dd className="font-mono tabular-nums font-medium text-slate-900">
                  {report.datasetStats.deduplicatedRows} ({report.datasetStats.uniqueDomains} unique domains)
                </dd>
              </div>
              <div className="flex justify-between border-b border-slate-100 py-1.5">
                <dt className="text-slate-600">Training Split</dt>
                <dd className="font-mono tabular-nums font-medium text-slate-900">
                  {report.datasetStats.trainCount} URLs
                </dd>
              </div>
              <div className="flex justify-between border-b border-slate-100 py-1.5">
                <dt className="text-slate-600">Validation Split</dt>
                <dd className="font-mono tabular-nums font-medium text-slate-900">
                  {report.datasetStats.validationCount} URLs (Acc: {pct(report.validationMetrics.accuracy)})
                </dd>
              </div>
              <div className="flex justify-between py-1.5">
                <dt className="text-slate-600">Held-Out Test Split</dt>
                <dd className="font-mono tabular-nums font-medium text-slate-900">
                  {report.datasetStats.testCount} URLs
                </dd>
              </div>
            </dl>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-slate-900">Test Set Confusion Matrix</h3>
            <div className="mt-3 grid grid-cols-2 gap-3 text-center text-xs">
              <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3">
                <div className="text-emerald-800 font-medium">True Positives (Phishing Caught)</div>
                <div className="mt-1 text-xl font-bold font-mono tabular-nums text-emerald-900">
                  {cm.tp}
                </div>
              </div>
              <div className="rounded-lg border border-amber-200 bg-amber-50 p-3">
                <div className="text-amber-800 font-medium">False Positives (Legit Flagged)</div>
                <div className="mt-1 text-xl font-bold font-mono tabular-nums text-amber-900">
                  {cm.fp}
                </div>
              </div>
              <div className="rounded-lg border border-red-200 bg-red-50 p-3">
                <div className="text-red-800 font-medium">False Negatives (Phishing Missed)</div>
                <div className="mt-1 text-xl font-bold font-mono tabular-nums text-red-900">
                  {cm.fn}
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                <div className="text-slate-700 font-medium">True Negatives (Legit Cleared)</div>
                <div className="mt-1 text-xl font-bold font-mono tabular-nums text-slate-900">
                  {cm.tn}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Top Learned Weights */}
        <section className="rounded-xl border border-slate-200 bg-white p-6">
          <h3 className="text-sm font-semibold text-slate-900">
            Top Learned Model Feature Weights
          </h3>
          <p className="mt-1 text-xs text-slate-500">
            Strongest positive (phishing-leaning) and negative (legitimate-leaning) model parameters.
          </p>
          <ul className="mt-4 divide-y divide-slate-100 text-xs">
            {report.topLearnedWeights.map((item) => (
              <li key={item.feature} className="flex items-center justify-between py-2">
                <span className="font-mono text-slate-800">{item.feature}</span>
                <span
                  className={`font-mono tabular-nums font-medium ${
                    item.direction === 'phishing' ? 'text-red-700' : 'text-emerald-700'
                  }`}
                >
                  {item.weight >= 0 ? `+${item.weight}` : item.weight} ({item.direction})
                </span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
