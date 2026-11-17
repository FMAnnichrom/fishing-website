import { validateAndNormalizeUrl } from '../services/urlValidator';
import type { UrlStructuralSignals } from '../../shared/types';

export const STRUCTURAL_FEATURE_NAMES = [
  'url_length',
  'domain_length',
  'path_length',
  'subdomain_count',
  'hyphen_count',
  'dot_count',
  'special_char_count',
  'digit_ratio',
  'has_ip_address',
  'has_at_symbol',
  'is_https',
  'is_punycode',
  'has_suspicious_tld',
  'is_url_shortener',
  'has_suspicious_extension',
  'has_word_number_anomaly',
  'char_entropy',
  'impersonated_brand_count',
] as const;

export interface ExtractedUrlFeatures {
  structural: number[];
  ngrams: Map<string, number>;
  signals: UrlStructuralSignals;
}

export function extractCharNgrams(url: string): Map<string, number> {
  // Strip protocol prefix so n-grams focus on host/path/query lexical patterns
  const surface = url
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .slice(0, 220);

  const counts = new Map<string, number>();
  const padded = `^${surface}$`;
  let total = 0;

  for (const n of [3, 4]) {
    if (padded.length < n) continue;
    for (let i = 0; i <= padded.length - n; i++) {
      const gram = padded.slice(i, i + n);
      counts.set(gram, (counts.get(gram) ?? 0) + 1);
      total++;
    }
  }

  if (total > 0) {
    for (const [gram, cnt] of counts.entries()) {
      counts.set(gram, cnt / total);
    }
  }

  return counts;
}

export function extractMlFeatures(rawUrl: string): ExtractedUrlFeatures | null {
  const validated = validateAndNormalizeUrl(rawUrl);
  if (!validated.valid || !validated.signals) {
    return null;
  }

  const s = validated.signals;
  const structural = [
    Math.min(s.urlLength, 500) / 100,
    Math.min(s.domainLength, 120) / 30,
    Math.min(s.pathLength, 200) / 50,
    s.subdomainCount,
    s.hyphenCount,
    s.dotCount,
    s.specialCharCount,
    s.digitRatio * 10,
    s.hasIpAddress ? 1 : 0,
    s.hasAtSymbol ? 1 : 0,
    s.isHttps ? 1 : 0,
    s.isPunycode ? 1 : 0,
    s.hasSuspiciousTld ? 1 : 0,
    s.isUrlShortener ? 1 : 0,
    s.hasSuspiciousExtension ? 1 : 0,
    s.hasWordNumberAnomaly ? 1 : 0,
    s.charEntropy,
    s.impersonatedBrands.length,
  ];

  const ngrams = extractCharNgrams(validated.normalizedUrl);
  return { structural, ngrams, signals: s };
}
