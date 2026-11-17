import {
  extractRegistrableDomainPsl,
  performAdvancedUrlAnalysis,
} from './advancedUrlAnalyzer';
import type { AdvancedUrlBreakdown, UrlStructuralSignals } from '../../shared/types';

const MAX_URL_LENGTH = 2048;

export interface ValidatedUrlResult {
  valid: boolean;
  error?: string;
  submittedUrl: string;
  normalizedUrl: string;
  domain: string;
  registrableDomain: string;
  signals?: UrlStructuralSignals;
  breakdown?: AdvancedUrlBreakdown;
}

export function extractRegistrableDomain(hostname: string): string {
  return extractRegistrableDomainPsl(hostname).registrableDomain;
}

export function validateAndNormalizeUrl(rawInput: string): ValidatedUrlResult {
  if (typeof rawInput !== 'string') {
    return {
      valid: false,
      error: 'URL input must be a string.',
      submittedUrl: '',
      normalizedUrl: '',
      domain: '',
      registrableDomain: '',
    };
  }

  const trimmed = rawInput.trim();
  if (!trimmed) {
    return {
      valid: false,
      error: 'Please enter a website URL to analyze.',
      submittedUrl: rawInput,
      normalizedUrl: '',
      domain: '',
      registrableDomain: '',
    };
  }

  if (trimmed.length > MAX_URL_LENGTH) {
    return {
      valid: false,
      error: `URL exceeds the maximum supported length of ${MAX_URL_LENGTH} characters.`,
      submittedUrl: trimmed.slice(0, 120) + '...',
      normalizedUrl: '',
      domain: '',
      registrableDomain: '',
    };
  }

  if (/[\r\n\t\0]/.test(trimmed) || /\s/.test(trimmed)) {
    return {
      valid: false,
      error: 'Invalid URL: URLs cannot contain spaces or control characters.',
      submittedUrl: trimmed,
      normalizedUrl: '',
      domain: '',
      registrableDomain: '',
    };
  }

  const lower = trimmed.toLowerCase();
  if (/^(javascript|data|vbscript|file|about|blob|ftp):/i.test(lower)) {
    return {
      valid: false,
      error: 'Unsupported or unsafe URL scheme. Only http:// and https:// URLs are supported.',
      submittedUrl: trimmed,
      normalizedUrl: '',
      domain: '',
      registrableDomain: '',
    };
  }

  let candidate = trimmed;
  if (!/^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(candidate)) {
    if (
      !/^[a-zA-Z0-9\-\.\[\]:%@]+(\/.*)?$/.test(candidate) ||
      (!candidate.includes('.') && !candidate.startsWith('localhost'))
    ) {
      return {
        valid: false,
        error: 'Invalid URL format. Please provide a valid web address such as https://example.com.',
        submittedUrl: trimmed,
        normalizedUrl: '',
        domain: '',
        registrableDomain: '',
      };
    }
    candidate = `http://${candidate}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return {
      valid: false,
      error: 'Unable to parse URL. Please check for typos or malformed characters.',
      submittedUrl: trimmed,
      normalizedUrl: '',
      domain: '',
      registrableDomain: '',
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      error: 'Only HTTP and HTTPS protocols are supported for URL analysis.',
      submittedUrl: trimmed,
      normalizedUrl: '',
      domain: '',
      registrableDomain: '',
    };
  }

  const domain = parsed.hostname.toLowerCase().replace(/\.$/, '');
  const psl = extractRegistrableDomainPsl(domain);
  if (!domain || (!domain.includes('.') && domain !== 'localhost' && !psl.isIp)) {
    return {
      valid: false,
      error: 'URL must contain a valid domain name or IP address.',
      submittedUrl: trimmed,
      normalizedUrl: '',
      domain: '',
      registrableDomain: '',
    };
  }

  if (
    domain.includes('..') ||
    domain.split('.').some((lbl) => lbl.startsWith('-') || lbl.endsWith('-'))
  ) {
    return {
      valid: false,
      error: 'URL contains a malformed hostname.',
      submittedUrl: trimmed,
      normalizedUrl: '',
      domain: '',
      registrableDomain: '',
    };
  }

  const { breakdown, signals } = performAdvancedUrlAnalysis(trimmed, parsed);

  return {
    valid: true,
    submittedUrl: trimmed,
    normalizedUrl: breakdown.normalizedUrl,
    domain,
    registrableDomain: breakdown.registrableDomain,
    signals,
    breakdown,
  };
}
