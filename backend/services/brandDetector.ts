import type { BrandSimilarityResult } from '../../shared/types';

export interface BrandConfig {
  brand: string;
  tokens: string[];
  officialDomains: string[];
}

export const POPULAR_BRANDS: BrandConfig[] = [
  {
    brand: 'Google',
    tokens: ['google', 'gmail', 'googleapis', 'googledrive'],
    officialDomains: ['google.com', 'gmail.com', 'googleapis.com', 'youtube.com', 'android.com', 'appspot.com'],
  },
  {
    brand: 'PayPal',
    tokens: ['paypal'],
    officialDomains: ['paypal.com', 'paypal.me'],
  },
  {
    brand: 'Microsoft',
    tokens: ['microsoft', 'microsoftonline', 'office365', 'outlook', 'onedrive'],
    officialDomains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com', 'windows.net'],
  },
  {
    brand: 'Apple',
    tokens: ['apple', 'appleid', 'icloud'],
    officialDomains: ['apple.com', 'icloud.com'],
  },
  {
    brand: 'Amazon',
    tokens: ['amazon', 'awsamazon'],
    officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'aws.amazon.com'],
  },
  {
    brand: 'Chase',
    tokens: ['chase', 'jpmorganchase'],
    officialDomains: ['chase.com', 'jpmorganchase.com'],
  },
  {
    brand: 'Bank of America',
    tokens: ['bankofamerica'],
    officialDomains: ['bankofamerica.com'],
  },
  {
    brand: 'Wells Fargo',
    tokens: ['wellsfargo'],
    officialDomains: ['wellsfargo.com'],
  },
  {
    brand: 'Citibank',
    tokens: ['citibank'],
    officialDomains: ['citi.com', 'citibank.com'],
  },
  {
    brand: 'Netflix',
    tokens: ['netflix'],
    officialDomains: ['netflix.com'],
  },
  {
    brand: 'Coinbase',
    tokens: ['coinbase'],
    officialDomains: ['coinbase.com'],
  },
  {
    brand: 'Binance',
    tokens: ['binance'],
    officialDomains: ['binance.com', 'binance.us'],
  },
  {
    brand: 'MetaMask',
    tokens: ['metamask'],
    officialDomains: ['metamask.io'],
  },
  {
    brand: 'Dropbox',
    tokens: ['dropbox'],
    officialDomains: ['dropbox.com'],
  },
  {
    brand: 'DocuSign',
    tokens: ['docusign'],
    officialDomains: ['docusign.com', 'docusign.net'],
  },
  {
    brand: 'DHL',
    tokens: ['dhlexpress'],
    officialDomains: ['dhl.com'],
  },
  {
    brand: 'FedEx',
    tokens: ['fedex'],
    officialDomains: ['fedex.com'],
  },
  {
    brand: 'USPS',
    tokens: ['usps'],
    officialDomains: ['usps.com'],
  },
  {
    brand: 'Facebook',
    tokens: ['facebook'],
    officialDomains: ['facebook.com', 'fb.com', 'meta.com'],
  },
  {
    brand: 'Instagram',
    tokens: ['instagram'],
    officialDomains: ['instagram.com'],
  },
  {
    brand: 'GitHub',
    tokens: ['github'],
    officialDomains: ['github.com', 'github.io', 'githubusercontent.com'],
  },
  {
    brand: 'Stripe',
    tokens: ['stripe'],
    officialDomains: ['stripe.com'],
  },
  {
    brand: 'LinkedIn',
    tokens: ['linkedin'],
    officialDomains: ['linkedin.com'],
  },
  {
    brand: 'Okta',
    tokens: ['okta'],
    officialDomains: ['okta.com'],
  },
];

// Unicode homoglyph / confusable characters mapped to ASCII equivalents
const UNICODE_CONFUSABLES: Record<string, string> = {
  '\u0430': 'a', // Cyrillic а
  '\u0435': 'e', // Cyrillic е
  '\u043E': 'o', // Cyrillic о
  '\u0440': 'p', // Cyrillic р
  '\u0441': 'c', // Cyrillic с
  '\u0443': 'y', // Cyrillic у
  '\u0445': 'x', // Cyrillic х
  '\u0456': 'i', // Cyrillic і
  '\u0455': 's', // Cyrillic ѕ
  '\u0458': 'j', // Cyrillic ј
  '\u03B1': 'a', // Greek α
  '\u03BF': 'o', // Greek ο
  '\u03C1': 'p', // Greek ρ
  '\u03B5': 'e', // Greek ε
  '\u0261': 'g', // Latin script g
  '\u0131': 'i', // Dotless i
  '\uFF4F': 'o', // Fullwidth o
  '\uFF41': 'a', // Fullwidth a
};

const LEET_SUBS: Array<{ pattern: RegExp; replacement: string; description: string }> = [
  { pattern: /0/g, replacement: 'o', description: 'o replaced with 0' },
  { pattern: /1/g, replacement: 'l', description: 'l replaced with 1' },
  { pattern: /3/g, replacement: 'e', description: 'e replaced with 3' },
  { pattern: /4/g, replacement: 'a', description: 'a replaced with 4' },
  { pattern: /5/g, replacement: 's', description: 's replaced with 5' },
  { pattern: /7/g, replacement: 't', description: 't replaced with 7' },
  { pattern: /rn/g, replacement: 'm', description: 'm mimicked with rn' },
  { pattern: /vv/g, replacement: 'w', description: 'w mimicked with vv' },
];

export function normalizeUnicodeConfusables(input: string): {
  normalized: string;
  hadConfusables: boolean;
} {
  let hadConfusables = false;
  let out = '';
  for (const ch of input) {
    if (UNICODE_CONFUSABLES[ch]) {
      out += UNICODE_CONFUSABLES[ch];
      hadConfusables = true;
    } else {
      out += ch;
    }
  }
  return { normalized: out, hadConfusables };
}

function normalizeLeetspeak(token: string): {
  normalized: string;
  substitutions: string[];
} {
  let current = token.toLowerCase();
  const substitutions: string[] = [];

  for (const sub of LEET_SUBS) {
    if (sub.pattern.test(current)) {
      current = current.replace(sub.pattern, sub.replacement);
      substitutions.push(sub.description);
    }
  }

  // Also test 1 -> i variant (e.g., b1nance -> binance, micr0soft)
  return { normalized: current, substitutions };
}

export function damerauLevenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + cost);
      }
    }
  }
  return dp[m][n];
}

export function isOfficialDomainForBrand(
  registrableDomain: string,
  hostname: string,
  brandConfig: BrandConfig,
): boolean {
  const reg = registrableDomain.toLowerCase();
  const host = hostname.toLowerCase();
  return brandConfig.officialDomains.some(
    (official) => reg === official || host === official || host.endsWith(`.${official}`),
  );
}

export function detectBrandsInHostAndPath(params: {
  hostnameNormalized: string;
  registrableDomain: string;
  subdomains: string[];
  decodedPath: string;
  rawUnicodeHost: string;
}): {
  results: BrandSimilarityResult[];
  unicodeConfusableDetected: boolean;
} {
  const { hostnameNormalized, registrableDomain, subdomains, decodedPath, rawUnicodeHost } = params;
  const results: BrandSimilarityResult[] = [];
  const seenKeys = new Set<string>();

  const { normalized: confusableFreeRawHost, hadConfusables } = normalizeUnicodeConfusables(
    rawUnicodeHost.toLowerCase(),
  );
  const unicodeConfusableDetected = hadConfusables;

  const subdomainTokens = subdomains
    .join('.')
    .split(/[.-]/)
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t.length >= 3);

  const regBase = registrableDomain.split('.')[0] ?? '';
  const regTokens = regBase
    .split('-')
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t.length >= 3);

  const checkTokenAgainstBrands = (
    token: string,
    location: 'subdomain' | 'registrable_domain',
  ) => {
    const cleanToken = normalizeUnicodeConfusables(token).normalized;
    const leet = normalizeLeetspeak(cleanToken);
    const leetAltI = cleanToken.replace(/1/g, 'i').replace(/0/g, 'o').replace(/3/g, 'e').replace(/4/g, 'a');

    for (const brandCfg of POPULAR_BRANDS) {
      if (isOfficialDomainForBrand(registrableDomain, hostnameNormalized, brandCfg)) {
        continue;
      }

      for (const brandToken of brandCfg.tokens) {
        const key = `${brandCfg.brand}:${location}:${token}`;
        if (seenKeys.has(key)) continue;

        // 1. Exact brand name embedded inside unrelated subdomain or hyphenated registrable domain token
        if (cleanToken === brandToken || (brandToken.length >= 5 && cleanToken.includes(brandToken))) {
          seenKeys.add(key);
          results.push({
            brand: brandCfg.brand,
            officialDomains: brandCfg.officialDomains,
            matchedToken: token,
            location,
            matchType: hadConfusables ? 'unicode_confusable' : 'exact_impersonation',
            similarityScore: 1.0,
            editDistance: 0,
            details: hadConfusables
              ? `Unicode confusable character normalized to "${brandToken}" on unrelated domain ${registrableDomain}.`
              : `Brand name "${brandCfg.brand}" appears in ${location.replace('_', ' ')} "${token}" while registrable domain is "${registrableDomain}".`,
          });
          break;
        }

        // 2. Leetspeak substitution match (e.g., g00gle -> google, paypa1 -> paypal, amaz0n -> amazon)
        if (
          leet.substitutions.length > 0 &&
          (leet.normalized === brandToken || leetAltI === brandToken)
        ) {
          seenKeys.add(key);
          const dist = damerauLevenshtein(cleanToken, brandToken);
          const sim = Number(
            Math.max(0, 1 - dist / Math.max(cleanToken.length, brandToken.length)).toFixed(2),
          );
          results.push({
            brand: brandCfg.brand,
            officialDomains: brandCfg.officialDomains,
            matchedToken: token,
            location,
            matchType: 'leetspeak_substitution',
            similarityScore: Math.max(0.75, sim),
            editDistance: dist,
            details: `Suspicious character substitution (${leet.substitutions.join(', ')}) impersonating ${brandCfg.brand} on unrelated domain ${registrableDomain}.`,
          });
          break;
        }

        // 3. Edit-distance typosquatting (skip very short <=3 char tokens unless exact)
        if (brandToken.length >= 5 && Math.abs(cleanToken.length - brandToken.length) <= 2) {
          const dist = damerauLevenshtein(cleanToken, brandToken);
          const maxDist = brandToken.length >= 7 ? 2 : 1;
          if (dist > 0 && dist <= maxDist) {
            // Ensure first letter matches or it's a transposition/omission of the brand
            const sim = Number((1 - dist / Math.max(cleanToken.length, brandToken.length)).toFixed(2));
            if (sim >= 0.72) {
              seenKeys.add(key);
              results.push({
                brand: brandCfg.brand,
                officialDomains: brandCfg.officialDomains,
                matchedToken: token,
                location,
                matchType: 'typosquat_edit_distance',
                similarityScore: sim,
                editDistance: dist,
                details: `Lookalike token "${token}" is ${dist} edit(s) away from ${brandCfg.brand} ("${brandToken}") on unrelated domain ${registrableDomain}.`,
              });
              break;
            }
          }
        }
      }
    }
  };

  for (const tok of subdomainTokens) {
    checkTokenAgainstBrands(tok, 'subdomain');
  }
  for (const tok of regTokens) {
    checkTokenAgainstBrands(tok, 'registrable_domain');
  }

  // Also check raw Unicode host string if Punycode converted it differently
  if (hadConfusables) {
    const rawHostTokens = confusableFreeRawHost.split(/[.-]/).filter((t) => t.length >= 4);
    for (const tok of rawHostTokens) {
      checkTokenAgainstBrands(tok, 'registrable_domain');
    }
  }

  // Check brand names in URL path
  const pathSegments = decodedPath
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((s) => s.length >= 4);

  for (const seg of pathSegments) {
    for (const brandCfg of POPULAR_BRANDS) {
      if (isOfficialDomainForBrand(registrableDomain, hostnameNormalized, brandCfg)) {
        continue;
      }
      if (brandCfg.tokens.includes(seg)) {
        const key = `${brandCfg.brand}:path:${seg}`;
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);
        results.push({
          brand: brandCfg.brand,
          officialDomains: brandCfg.officialDomains,
          matchedToken: seg,
          location: 'path',
          matchType: 'brand_in_path',
          similarityScore: 1.0,
          editDistance: 0,
          details: `Brand "${brandCfg.brand}" referenced in URL path ("/${seg}/") on unrelated domain ${registrableDomain}.`,
        });
      }
    }
  }

  return { results, unicodeConfusableDetected };
}
