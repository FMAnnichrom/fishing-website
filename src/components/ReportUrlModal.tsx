import { useEffect, useState, type FormEvent } from 'react';
import { X } from 'lucide-react';
import { submitUserReport } from '../services/api';

interface ReportUrlModalProps {
  open: boolean;
  initialUrl?: string;
  onClose: () => void;
  onSubmitted: () => void;
}

export function ReportUrlModal({ open, initialUrl = '', onClose, onSubmitted }: ReportUrlModalProps) {
  const [url, setUrl] = useState(initialUrl);
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setUrl(initialUrl);
      setError(null);
      setSuccessMsg(null);
    }
  }, [open, initialUrl]);

  if (!open) return null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);
    setSubmitting(true);
    try {
      const res = await submitUserReport(url, reason);
      setSuccessMsg(res.message);
      setReason('');
      onSubmitted();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to submit report.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="report-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 px-4"
    >
      <div className="w-full max-w-lg rounded-xl border border-slate-200 bg-white p-6 shadow-lg">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id="report-modal-title" className="text-lg font-semibold text-slate-900">
              Report Suspicious URL
            </h2>
            <p className="mt-1 text-xs text-slate-600">
              Submitted URLs are queued for analyst review as unverified reports and are never
              automatically labeled malicious.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close report dialog"
            className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="mt-5 space-y-4">
          <div>
            <label htmlFor="report-url-input" className="block text-xs font-medium text-slate-700">
              Suspicious Website URL
            </label>
            <input
              id="report-url-input"
              type="text"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://suspicious-example.com/login"
              className="mt-1.5 w-full rounded-lg border border-slate-300 px-3.5 py-2 font-mono text-sm text-slate-900 focus:border-blue-700 focus:outline-none"
            />
          </div>

          <div>
            <label htmlFor="report-reason-input" className="block text-xs font-medium text-slate-700">
              Why does this URL look suspicious?
            </label>
            <textarea
              id="report-reason-input"
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Example: Impersonates bank login page via SMS link"
              className="mt-1.5 w-full rounded-lg border border-slate-300 px-3.5 py-2 text-sm text-slate-900 focus:border-blue-700 focus:outline-none"
            />
          </div>

          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-3.5 py-2.5 text-xs text-red-800">
              {error}
            </div>
          )}

          {successMsg && (
            <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-3.5 py-2.5 text-xs text-emerald-800">
              {successMsg}
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
            >
              Close
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="rounded-lg bg-[#2563EB] px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-60"
            >
              {submitting ? 'Submitting...' : 'Submit for Review'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
