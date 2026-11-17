import type { UrlStructuralSignals } from '../../shared/types';

const MAX_URL_LENGTH = 2048;

const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'click',
  'buzz',
  'club',
  'icu',
  'sbs',
  'cyou',
  'cfd',
  'pw',
  'su',
  'ws',
  'zip',
  'mov',
  'online',
  'site',
  'info',
  'cc',
  'ru',
  'cn',
]);

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'cutt.ly',
  'rb.gy',
  'shorturl.at',
  't.ly',
  'short.io',
  'tiny.cc',
  'rebrand.ly',
]);

const SUSPICIOUS_EXTENSIONS = [
  '.exe',
  '.scr',
  '.msi',
  '.bat',
  '.cmd',
  '.ps1',
  '.vbs',
  '.hta',
  '.apk',
  '.iso',
  '.dll',
  '.jar',
];

const PROTECTED_BRANDS: Array<{ brand: string; officialDomains: string[]; lookalikes?: RegExp }> = [
  { brand: 'PayPal', officialDomains: ['paypal.com', 'paypal.me'], lookalikes: /paypa[l1]|pypal/i },
  { brand: 'Microsoft', officialDomains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com'], lookalikes: /micr[o0]s[o0]ft|office365/i },
  { brand: 'Apple', officialDomains: ['apple.com', 'icloud.com'], lookalikes: /app[l1]e|icl[o0]ud/i },
  { brand: 'Google', officialDomains: ['google.com', 'gmail.com', 'accounts.google.com', 'appspot.com'], lookalikes: /g[o0]{2}g[l1]e/i },
  { brand: 'Amazon', officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com'], lookalikes: /arnaz[o0]n|amaz[o0]n/i },
  { brand: 'Chase', officialDomains: ['chase.com', 'jpmorganchase.com'], lookalikes: /ch[a4]se/i },
  { brand: 'Bank of America', officialDomains: ['bankofamerica.com'], lookalikes: /bankofamerica/i },
  { brand: 'Wells Fargo', officialDomains: ['wellsfargo.com'], lookalikes: /wellsfarg[o0]/i },
  { brand: 'Citibank', officialDomains: ['citi.com', 'citibank.com'], lookalikes: /citibank/i },
  { brand: 'Netflix', officialDomains: ['netflix.com'], lookalikes: /netf[l1]ix/i },
  { brand: 'Coinbase', officialDomains: ['coinbase.com'], lookalikes: /c[o0]inbase/i },
  { brand: 'Binance', officialDomains: ['binance.com', 'binance.us'], lookalikes: /b[i1]nance/i },
  { brand: 'MetaMask', officialDomains: ['metamask.io'], lookalikes: /metamask/i },
  { brand: 'Dropbox', officialDomains: ['dropbox.com'], lookalikes: /dr[o0]pb[o0]x/i },
  { brand: 'DocuSign', officialDomains: ['docusign.com', 'docusign.net'], lookalikes: /docusign/i },
  { brand: 'DHL', officialDomains: ['dhl.com'], lookalikes: /\bdhl\b|dhl-/i },
  { brand: 'FedEx', officialDomains: ['fedex.com'], lookalikes: /fedex/i },
  { brand: 'USPS', officialDomains: ['usps.com'], lookalikes: /\busps\b|usps-/i },
  { brand: 'Facebook', officialDomains: ['facebook.com', 'fb.com', 'meta.com'], lookalikes: /faceb[o0]{2}k/i },
  { brand: 'Instagram', officialDomains: ['instagram.com'], lookalikes: /instagram/i },
  { brand: 'GitHub', officialDomains: ['github.com'], lookalikes: /github/i },
  { brand: 'Stripe', officialDomains: ['stripe.com'], lookalikes: /stripe/i },
];

export interface ValidatedUrlResult {
  valid: boolean;
  error?: string;
  submittedUrl: string;
  normalizedUrl: string;
  domain: string;
  registrableDomain: string;
  signals?: UrlStructuralSignals;
}

function shannonEntropy(input: string): number {
  if (!input) return 0;
  const freq = new Map<string, number>();
  for (const ch of input) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = input.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

function isIpLiteralHost(hostname: string): boolean {
  const clean = hostname.replace(/^\[|\]$/g, '');
  // Standard dotted IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) return true;
  // Hex, octal, or single integer IPv4 (e.g., 0x7f.0x00.0x00.0x01 or 2130706433)
  if (/^(0x[0-9a-f]+|0[0-7]+|\d+)(\.(0x[0-9a-f]+|0[0-7]+|\d+)){0,3}$/i.test(clean)) {
    return true;
  }
  // IPv6
  if (clean.includes(':')) return true;
  return false;
}

export function extractRegistrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (isIpLiteralHost(host)) return host;
  const parts = host.split('.').filter(Boolean);
  if (parts.length <= 2) return host;
  // Handle common two-level ccTLDs (co.uk, com.au, etc.)
  const lastTwo = parts.slice(-2).join('.');
  const twoLevelSuffixes = new Set([
    'co.uk',
    'org.uk',
    'gov.uk',
    'ac.uk',
    'com.au',
    'net.au',
    'org.au',
    'co.jp',
    'co.in',
    'com.br',
    'com.mx',
  ]);
  if (twoLevelSuffixes.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
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

  // Reject dangerous non-HTTP schemes explicitly before attempting normalization
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

  // Add http:// only if no scheme is present and input looks like a domain/IP with at least one dot or localhost
  let candidate = trimmed;
  if (!/^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(candidate)) {
    // Reject inputs like "not a url" or single words without dots/ports
    if (!/^[a-zA-Z0-9\-\.\[\]:%@]+(\/.*)?$/.test(candidate) || (!candidate.includes('.') && !candidate.startsWith('localhost'))) {
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
  if (!domain || (!domain.includes('.') && domain !== 'localhost' && !isIpLiteralHost(domain))) {
    return {
      valid: false,
      error: 'URL must contain a valid domain name or IP address.',
      submittedUrl: trimmed,
      normalizedUrl: '',
      domain: '',
      registrableDomain: '',
    };
  }

  // Detect consecutive dots or invalid leading/trailing hyphens in labels
  if (domain.includes('..') || domain.split('.').some((lbl) => lbl.startsWith('-') || lbl.endsWith('-'))) {
    return {
      valid: false,
      error: 'URL contains a malformed hostname.',
      submittedUrl: trimmed,
      normalizedUrl: '',
      domain: '',
      registrableDomain: '',
    };
  }

  // Normalize URL while preserving security-relevant indicators (e.g., username/password for @ detection)
  const normalizedUrl = parsed.toString();
  const registrableDomain = extractRegistrableDomain(domain);
  const signals = extractStructuralSignals(trimmed, parsed, domain, registrableDomain);

  return {
    valid: true,
    submittedUrl: trimmed,
    normalizedUrl,
    domain,
    registrableDomain,
    signals,
  };
}

export function extractStructuralSignals(
  rawUrl: string,
  parsed: URL,
  domain: string,
  registrableDomain: string,
): UrlStructuralSignals {
  const full = parsed.toString();
  const pathAndQuery = `${parsed.pathname}${parsed.search}`;
  const isIp = isIpLiteralHost(domain);
  const labels = isIp ? [domain] : domain.split('.').filter(Boolean);
  const tld = isIp ? '' : labels[labels.length - 1] ?? '';
  const regPartsCount = registrableDomain.split('.').filter(Boolean).length;
  const subdomainCount = isIp ? 0 : Math.max(0, labels.length - regPartsCount);

  const hyphenCount = (domain.match(/-/g) ?? []).length;
  const dotCount = (domain.match(/\./g) ?? []).length;
  const specialCharCount = (full.match(/[@!$&'*+,;=~%]/g) ?? []).length;
  const digitsCount = (full.match(/\d/g) ?? []).length;
  const digitRatio = full.length > 0 ? Number((digitsCount / full.length).toFixed(3)) : 0;

  const hasAtSymbol = Boolean(parsed.username || parsed.password || rawUrl.includes('@'));
  const isHttps = parsed.protocol === 'https:';
  const isPunycode = labels.some((lbl) => lbl.startsWith('xn--'));
  const hasMixedScript = /[^\x00-\x7F]/.test(rawUrl) && !isPunycode;
  const hasSuspiciousTld = Boolean(tld && SUSPICIOUS_TLDS.has(tld));
  const isUrlShortener = URL_SHORTENERS.has(domain) || URL_SHORTENERS.has(registrableDomain);
  const lowerPath = parsed.pathname.toLowerCase();
  const hasSuspiciousExtension = SUSPICIOUS_EXTENSIONS.some((ext) => lowerPath.endsWith(ext));
  const hasExcessiveSubdomains = subdomainCount >= 3;

  // Unusual word+number concatenation or numeric noise inside domain labels (excluding common v4/365/24)
  const domainWithoutTld = labels.slice(0, -1).join('.');
  const hasWordNumberAnomaly =
    /(?:[a-z]{3,}\d{3,}|\d{3,}[a-z]{3,})/i.test(domainWithoutTld) ||
    /(?:paypa1|app1e|g00gle|micr0soft|ch4se|b1nance|c0inbase|netf1ix)/i.test(domain);

  const charEntropy = shannonEntropy(`${domain}${parsed.pathname}`);

  // Brand impersonation detection: brand name appears in domain/subdomain/path while registrable domain is NOT official
  const impersonatedBrands: string[] = [];
  const checkSurface = `${domain}${parsed.pathname}`.toLowerCase();
  for (const entry of PROTECTED_BRANDS) {
    const isOfficial = entry.officialDomains.some(
      (official) => registrableDomain === official || domain.endsWith(`.${official}`),
    );
    if (!isOfficial) {
      const matched = entry.lookalikes
        ? entry.lookalikes.test(checkSurface)
        : checkSurface.includes(entry.brand.toLowerCase().replace(/\s+/g, ''));
      if (matched) {
        impersonatedBrands.push(entry.brand);
      }
    }
  }

  const nonPunycodeDomain = labels
    .map((lbl) => (lbl.startsWith('xn--') ? lbl.slice(4) : lbl))
    .join('.');
  const nonPunycodeHyphenCount = (nonPunycodeDomain.match(/-/g) ?? []).length;

  const anomalies: string[] = [];
  if (isIp) anomalies.push('Uses a raw or encoded IP address instead of a registered domain name.');
  if (hasAtSymbol) anomalies.push('Contains an "@" symbol, which can disguise the true destination host.');
  if (isPunycode) anomalies.push('Uses Punycode (xn--) internationalized domain encoding, which can mask homograph spoofing.');
  if (hasMixedScript) anomalies.push('Contains non-ASCII characters in the URL.');
  if (hasExcessiveSubdomains) anomalies.push(`Uses ${subdomainCount} subdomain levels, a common tactic to imitate legitimate hosts.`);
  if (nonPunycodeHyphenCount >= 3) anomalies.push(`Domain contains ${nonPunycodeHyphenCount} hyphens, often seen in deceptive lookalike domains.`);
  if (isUrlShortener) anomalies.push('Uses a URL shortening service that obscures the final destination.');
  if (hasSuspiciousTld) anomalies.push(`Uses high-risk or frequently abused top-level domain (.${tld}).`);
  if (hasSuspiciousExtension) anomalies.push('Path points to a potentially dangerous executable or script file.');
  if (hasWordNumberAnomaly) anomalies.push('Domain contains unusual alphanumeric substitutions or digit sequences.');
  if (full.length >= 100) anomalies.push(`Unusually long URL (${full.length} characters) often used to hide malicious parameters.`);
  if (!isHttps) anomalies.push('Uses unencrypted HTTP rather than HTTPS (note: HTTPS alone does not guarantee safety).');
  if (impersonatedBrands.length > 0) {
    anomalies.push(
      `References protected brand (${impersonatedBrands.join(', ')}) on an unrelated domain (${registrableDomain}).`,
    );
  }

  return {
    urlLength: full.length,
    domainLength: domain.length,
    pathLength: parsed.pathname.length,
    queryLength: parsed.search.length,
    subdomainCount,
    hyphenCount,
    dotCount,
    specialCharCount,
    digitRatio,
    hasIpAddress: isIp,
    hasAtSymbol,
    isHttps,
    isPunycode,
    hasMixedScript,
    hasSuspiciousTld,
    tld,
    isUrlShortener,
    hasSuspiciousExtension,
    hasExcessiveSubdomains,
    hasWordNumberAnomaly,
    charEntropy,
    impersonatedBrands,
    anomalies,
  };
}
