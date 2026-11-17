import { parse as parseTld } from 'tldts';
import {
  detectBrandsInHostAndPath,
  isOfficialDomainForBrand,
  POPULAR_BRANDS,
} from './brandDetector';
import type {
  AdvancedUrlBreakdown,
  BrandSimilarityResult,
  QueryParameterAnalysis,
  UrlStructuralSignals,
} from '../../shared/types';

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
];

const REDIRECT_PARAM_NAMES = new Set([
  'next',
  'url',
  'redirect',
  'redirect_uri',
  'redirect_url',
  'return',
  'return_to',
  'returnto',
  'continue',
  'destination',
  'dest',
  'target',
  'forward',
  'callback',
  'redir',
  'goto',
  'out',
]);

const AUTH_PARAM_NAMES = new Set([
  'token',
  'password',
  'pass',
  'session',
  'sessionid',
  'redirect',
  'verify',
  'auth',
  'code',
  'otp',
  'pin',
  'login',
  'signin',
  'continue',
  'next',
]);

const ENCODED_SECURITY_KEYWORDS = [
  'account',
  'login',
  'signin',
  'verify',
  'password',
  'authentication',
  'auth',
  'confirm',
  'update',
  'billing',
  'payment',
  'wallet',
  'token',
  'session',
  'continue',
];

const AUTH_PATH_KEYWORDS = new Set([
  'login',
  'signin',
  'sign-in',
  'auth',
  'authenticate',
  'authentication',
  'account',
  'accounts',
  'verify',
  'verification',
  'password',
  'reset-password',
  'billing',
  'payment',
  'checkout',
  'session',
  'oauth',
  'sso',
  'confirm',
  'security',
  'update',
]);

export function safeBoundedDecode(
  input: string,
  maxLayers = 3,
): { decoded: string; layers: number } {
  let current = input;
  let layers = 0;

  for (let i = 0; i < maxLayers; i++) {
    if (!/%[0-9a-fA-F]{2}/.test(current)) break;
    let next: string;
    try {
      next = decodeURIComponent(current);
    } catch {
      // Partial safe decode of valid %XX ASCII sequences without crashing on malformed %
      next = current.replace(/%([0-9a-fA-F]{2})/g, (full, hex) => {
        const code = Number.parseInt(hex, 16);
        if (code >= 0x20 && code <= 0x7e) {
          return String.fromCharCode(code);
        }
        return full;
      });
    }
    if (next === current) break;
    current = next;
    layers++;
  }

  return { decoded: current, layers };
}

export function extractRawHostnameBeforeLowercase(rawUrl: string): string {
  const withoutScheme = rawUrl.replace(/^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//, '');
  const authority = withoutScheme.split('/')[0]?.split('?')[0]?.split('#')[0] ?? '';
  const withoutUserinfo = authority.includes('@') ? authority.split('@').pop() ?? authority : authority;
  if (withoutUserinfo.startsWith('[')) {
    const closeIdx = withoutUserinfo.indexOf(']');
    return closeIdx !== -1 ? withoutUserinfo.slice(0, closeIdx + 1) : withoutUserinfo;
  }
  return withoutUserinfo.split(':')[0] ?? '';
}

function isIpLiteralHost(hostname: string): boolean {
  const clean = hostname.replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) return true;
  if (/^(0x[0-9a-f]+|0[0-7]+|\d+)(\.(0x[0-9a-f]+|0[0-7]+|\d+)){0,3}$/i.test(clean)) {
    return true;
  }
  if (clean.includes(':')) return true;
  return false;
}

export function extractRegistrableDomainPsl(hostname: string): {
  registrableDomain: string;
  publicSuffix: string;
  subdomains: string[];
  isIp: boolean;
} {
  const cleanHost = hostname.toLowerCase().replace(/\.$/, '');
  if (isIpLiteralHost(cleanHost)) {
    return {
      registrableDomain: cleanHost,
      publicSuffix: '',
      subdomains: [],
      isIp: true,
    };
  }

  const tldInfo = parseTld(cleanHost, {
    allowPrivateDomains: true,
    detectIp: true,
    validHosts: ['localhost'],
  });

  if (tldInfo.isIp) {
    return {
      registrableDomain: cleanHost,
      publicSuffix: '',
      subdomains: [],
      isIp: true,
    };
  }

  const registrableDomain = tldInfo.domain || cleanHost;
  const publicSuffix = tldInfo.publicSuffix || '';
  const subdomains = tldInfo.subdomain
    ? tldInfo.subdomain.split('.').filter(Boolean)
    : [];

  return {
    registrableDomain,
    publicSuffix,
    subdomains,
    isIp: false,
  };
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

function detectAsciiAlphaHexEncoding(rawSegment: string): boolean {
  // Detects hex encoding of ordinary ASCII letters (a-z / A-Z) e.g. %61%63%63%6F%75%6E%74
  const hexMatches = rawSegment.match(/%[0-9a-fA-F]{2}/g) ?? [];
  let alphaEncodedCount = 0;
  for (const match of hexMatches) {
    const code = Number.parseInt(match.slice(1), 16);
    if ((code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a)) {
      alphaEncodedCount++;
    }
  }
  return alphaEncodedCount >= 3;
}

export function performAdvancedUrlAnalysis(
  rawSubmittedUrl: string,
  parsed: URL,
): {
  breakdown: AdvancedUrlBreakdown;
  signals: UrlStructuralSignals;
} {
  const normalizedUrl = parsed.toString();
  const hostnameRaw = extractRawHostnameBeforeLowercase(rawSubmittedUrl) || parsed.hostname;
  const hostnameNormalized = parsed.hostname.toLowerCase().replace(/\.$/, '');
  const hostnameCaseMixed =
    hostnameRaw !== hostnameRaw.toLowerCase() && hostnameRaw !== hostnameRaw.toUpperCase();

  const psl = extractRegistrableDomainPsl(hostnameNormalized);
  const labels = psl.isIp ? [hostnameNormalized] : hostnameNormalized.split('.').filter(Boolean);
  const maxSubdomainLength = psl.subdomains.reduce((max, s) => Math.max(max, s.length), 0);

  // Port analysis
  const explicitPort = parsed.port || '';
  const portNumber = explicitPort ? Number.parseInt(explicitPort, 10) : null;
  const isStandardPort =
    !explicitPort ||
    (parsed.protocol === 'http:' && portNumber === 80) ||
    (parsed.protocol === 'https:' && portNumber === 443);
  const isUnusualPort = Boolean(explicitPort && !isStandardPort);

  // Path decoding & obfuscation analysis
  const rawPath = parsed.pathname || '/';
  const { decoded: decodedPath, layers: pathEncodingLayers } = safeBoundedDecode(rawPath);
  const rawEncodedMatches = `${rawPath}${parsed.search}`.match(/%[0-9a-fA-F]{2}/g) ?? [];
  const encodedCharacterRatio = Number(
    ((rawEncodedMatches.length * 3) / Math.max(1, rawPath.length + parsed.search.length)).toFixed(3),
  );

  // Detect security keywords concealed specifically via ASCII hex encoding in path/query
  const encodedKeywords: string[] = [];
  const pathUsesAlphaHex = detectAsciiAlphaHexEncoding(rawPath);
  if (pathUsesAlphaHex || pathEncodingLayers >= 2) {
    const lowerDecodedPath = decodedPath.toLowerCase();
    for (const kw of ENCODED_SECURITY_KEYWORDS) {
      if (
        lowerDecodedPath.includes(kw) &&
        !rawPath.toLowerCase().includes(kw)
      ) {
        encodedKeywords.push(kw);
      }
    }
  }

  // Brand similarity & impersonation in host and path
  const { results: brandSimilarityResults, unicodeConfusableDetected } = detectBrandsInHostAndPath({
    hostnameNormalized,
    registrableDomain: psl.registrableDomain,
    subdomains: psl.subdomains,
    decodedPath,
    rawUnicodeHost: hostnameRaw,
  });

  // Query parameter & nested redirect inspection (parse raw query string to count duplicates accurately)
  const rawSearch = parsed.search.startsWith('?') ? parsed.search.slice(1) : '';
  const rawPairs = rawSearch ? rawSearch.split('&').filter(Boolean) : [];
  const paramCounts = new Map<string, number>();
  const parsedPairs: Array<{ rawName: string; name: string; rawVal: string }> = [];

  for (const pair of rawPairs) {
    const eqIdx = pair.indexOf('=');
    const rawName = eqIdx === -1 ? pair : pair.slice(0, eqIdx);
    const rawVal = eqIdx === -1 ? '' : pair.slice(eqIdx + 1);
    const name = safeBoundedDecode(rawName.replace(/\+/g, ' ')).decoded.toLowerCase();
    paramCounts.set(name, (paramCounts.get(name) ?? 0) + 1);
    parsedPairs.push({ rawName, name, rawVal });
  }

  const queryParams: QueryParameterAnalysis[] = [];
  let duplicateParameterCount = 0;
  let redirectParameterCount = 0;
  let nestedUrlDetected = false;
  let externalRedirectDetected = false;
  let hasEmbeddedAuthKeyword = false;

  for (const [_, count] of paramCounts.entries()) {
    if (count > 1) duplicateParameterCount += count - 1;
  }

  for (const { name, rawVal } of parsedPairs) {
    const plusNormalized = rawVal.replace(/\+/g, ' ');
    const { decoded: decodedVal, layers } = safeBoundedDecode(plusNormalized);
    const isDuplicate = (paramCounts.get(name) ?? 0) > 1;
    const isRedirectParam = REDIRECT_PARAM_NAMES.has(name);
    const isAuthParam = AUTH_PARAM_NAMES.has(name);

    if (isRedirectParam) redirectParameterCount++;

    // Detect encoded keywords inside parameter values when alpha-hex obfuscated or multi-encoded
    if (detectAsciiAlphaHexEncoding(rawVal) || layers >= 2) {
      const lowerVal = decodedVal.toLowerCase();
      for (const kw of ENCODED_SECURITY_KEYWORDS) {
        if (lowerVal.includes(kw) && !rawVal.toLowerCase().includes(kw) && !encodedKeywords.includes(kw)) {
          encodedKeywords.push(kw);
        }
      }
    }

    let embeddedUrl: QueryParameterAnalysis['embeddedUrl'] | undefined;
    const trimmedDecoded = decodedVal.trim();

    if (/^https?:\/\//i.test(trimmedDecoded) || /^\/\/[a-z0-9.-]+/i.test(trimmedDecoded)) {
      try {
        const parseTarget = trimmedDecoded.startsWith('//')
          ? `${parsed.protocol}${trimmedDecoded}`
          : trimmedDecoded;
        const innerUrl = new URL(parseTarget);
        const innerHost = innerUrl.hostname.toLowerCase();
        const innerPsl = extractRegistrableDomainPsl(innerHost);
        const sameBrandOrg = POPULAR_BRANDS.some(
          (b) =>
            isOfficialDomainForBrand(psl.registrableDomain, hostnameNormalized, b) &&
            isOfficialDomainForBrand(innerPsl.registrableDomain, innerHost, b),
        );
        const isExternal =
          innerPsl.registrableDomain !== psl.registrableDomain && !sameBrandOrg;

        const claimedBrands: string[] = [];
        for (const brandCfg of POPULAR_BRANDS) {
          if (isOfficialDomainForBrand(innerPsl.registrableDomain, innerHost, brandCfg)) {
            claimedBrands.push(brandCfg.brand);
          }
        }

        embeddedUrl = {
          raw: trimmedDecoded,
          hostname: innerHost,
          registrableDomain: innerPsl.registrableDomain,
          isRelative: false,
          isExternal,
          claimedBrands,
        };

        nestedUrlDetected = true;
        if (isExternal) {
          externalRedirectDetected = true;
          // If outer domain is unrelated to claimed brand inside redirect parameter, record redirect brand lure
          if (claimedBrands.length > 0) {
            for (const brand of claimedBrands) {
              const brandCfg = POPULAR_BRANDS.find((b) => b.brand === brand);
              if (
                brandCfg &&
                !isOfficialDomainForBrand(psl.registrableDomain, hostnameNormalized, brandCfg)
              ) {
                brandSimilarityResults.push({
                  brand,
                  officialDomains: brandCfg.officialDomains,
                  matchedToken: innerHost,
                  location: 'query_redirect',
                  matchType: 'redirect_brand_lure',
                  similarityScore: 1.0,
                  editDistance: 0,
                  details: `External redirect parameter "${name}" targets "${innerHost}" (${brand}) from unrelated domain ${psl.registrableDomain}.`,
                });
              }
            }
          }
        }
      } catch {
        // Ignore unparseable URL-like text
      }
    } else if (isRedirectParam && trimmedDecoded.startsWith('/') && !trimmedDecoded.startsWith('//')) {
      embeddedUrl = {
        raw: trimmedDecoded,
        hostname: hostnameNormalized,
        registrableDomain: psl.registrableDomain,
        isRelative: true,
        isExternal: false,
        claimedBrands: [],
      };
      if (layers >= 1) {
        nestedUrlDetected = true;
      }
      if (/auth|login|signin|verify|password|continue|oauth/i.test(trimmedDecoded)) {
        hasEmbeddedAuthKeyword = true;
      }
    }

    queryParams.push({
      name,
      rawValue: rawVal,
      decodedValue: decodedVal,
      isDuplicate,
      isRedirectParam,
      isAuthParam,
      encodingLayers: layers,
      embeddedUrl,
    });
  }

  // Path authentication tokens check
  const pathTokens = decodedPath
    .toLowerCase()
    .split(/[^a-z0-9-]+/)
    .filter(Boolean);
  const authPathHits = pathTokens.filter((t) => AUTH_PATH_KEYWORDS.has(t));
  const suspiciousAuthenticationPath = authPathHits.length >= 1;

  // Subdomain & structural metrics
  const subdomainCount = psl.subdomains.length;
  const hyphenCount = (hostnameNormalized.match(/-/g) ?? []).length;
  const dotCount = (hostnameNormalized.match(/\./g) ?? []).length;
  const specialCharCount = (normalizedUrl.match(/[@!$&'*+,;=~%]/g) ?? []).length;
  const digitsCount = (normalizedUrl.match(/\d/g) ?? []).length;
  const digitRatio =
    normalizedUrl.length > 0 ? Number((digitsCount / normalizedUrl.length).toFixed(3)) : 0;

  const hasAtSymbol = Boolean(parsed.username || parsed.password || rawSubmittedUrl.includes('@'));
  const isHttps = parsed.protocol === 'https:';
  const isPunycode = labels.some((lbl) => lbl.startsWith('xn--'));
  const hasMixedScript = /[^\x00-\x7F]/.test(rawSubmittedUrl) && !isPunycode;
  const hasSuspiciousTld = Boolean(psl.publicSuffix && SUSPICIOUS_TLDS.has(psl.publicSuffix));
  const isUrlShortener =
    URL_SHORTENERS.has(hostnameNormalized) || URL_SHORTENERS.has(psl.registrableDomain);
  const hasSuspiciousExtension = SUSPICIOUS_EXTENSIONS.some((ext) =>
    decodedPath.toLowerCase().endsWith(ext),
  );
  const hasExcessiveSubdomains = subdomainCount >= 3;

  const domainWithoutSuffix = labels.slice(0, -1).join('.');
  const hasWordNumberAnomaly =
    /(?:[a-z]{3,}\d{3,}|\d{3,}[a-z]{3,})/i.test(domainWithoutSuffix) ||
    brandSimilarityResults.some((b) => b.matchType === 'leetspeak_substitution');

  const charEntropy = shannonEntropy(`${hostnameNormalized}${decodedPath}`);

  const subdomainBrands = brandSimilarityResults.filter((b) => b.location === 'subdomain');
  const regDomainBrands = brandSimilarityResults.filter(
    (b) => b.location === 'registrable_domain',
  );
  const pathBrands = brandSimilarityResults.filter((b) => b.location === 'path');

  const suspiciousBrandInSubdomain = subdomainBrands.length > 0;
  const brandInPath = pathBrands.length > 0;
  const brandDomainMismatch =
    subdomainBrands.length > 0 ||
    regDomainBrands.length > 0 ||
    (brandInPath && suspiciousAuthenticationPath) ||
    brandSimilarityResults.some((b) => b.location === 'query_redirect');

  const maxBrandSimilarityScore = brandSimilarityResults.reduce(
    (max, item) => Math.max(max, item.similarityScore),
    0,
  );

  const impersonatedBrands = Array.from(
    new Set(
      brandSimilarityResults
        .filter((b) => b.location !== 'path' || suspiciousAuthenticationPath)
        .map((b) => b.brand),
    ),
  );

  // Check Punycode non-ACE hyphens
  const nonPunycodeDomain = labels
    .map((lbl) => (lbl.startsWith('xn--') ? lbl.slice(4) : lbl))
    .join('.');
  const nonPunycodeHyphenCount = (nonPunycodeDomain.match(/-/g) ?? []).length;

  const anomalies: string[] = [];
  if (psl.isIp) anomalies.push('Uses a raw or encoded IP address instead of a registered domain name.');
  if (hasAtSymbol) anomalies.push('Contains an "@" symbol, which can disguise the true destination host.');
  if (isPunycode) anomalies.push('Uses Punycode (xn--) internationalized domain encoding, which can mask homograph spoofing.');
  if (unicodeConfusableDetected) anomalies.push('Contains visually confusable Unicode homoglyph characters in the hostname.');
  if (hasMixedScript && !unicodeConfusableDetected) anomalies.push('Contains non-ASCII characters in the URL.');
  if (hasExcessiveSubdomains) {
    anomalies.push(`Uses ${subdomainCount} subdomain levels (${psl.subdomains.join('.')}), which can obscure the actual registrable domain (${psl.registrableDomain}).`);
  }
  if (nonPunycodeHyphenCount >= 3) {
    anomalies.push(`Hostname contains ${nonPunycodeHyphenCount} hyphens, often seen in deceptive lookalike domains.`);
  }
  if (isUrlShortener) anomalies.push('Uses a URL shortening service that obscures the final destination.');
  if (hasSuspiciousTld) anomalies.push(`Uses frequently abused top-level domain (.${psl.publicSuffix}).`);
  if (hasSuspiciousExtension) anomalies.push('Path points to a potentially dangerous executable or script file.');
  if (encodedKeywords.length > 0) {
    anomalies.push(`Percent-encoding conceals security-sensitive keyword(s): ${encodedKeywords.join(', ')}.`);
  }
  if (externalRedirectDetected) {
    anomalies.push('Query parameters embed an external redirect destination.');
  }
  if (isUnusualPort && portNumber !== null) {
    if (portNumber === 8443) {
      anomalies.push('Uses alternate HTTPS port 8443 (common for admin consoles; risky mainly when combined with auth impersonation).');
    } else {
      anomalies.push(`Uses nonstandard port :${portNumber} instead of standard web ports.`);
    }
  }
  if (normalizedUrl.length >= 110) {
    anomalies.push(`Unusually long URL (${normalizedUrl.length} characters).`);
  }
  if (!isHttps) {
    anomalies.push('Uses unencrypted HTTP rather than HTTPS (note: HTTPS alone does not guarantee safety).');
  }
  if (hasEmbeddedAuthKeyword && redirectParameterCount > 0 && !externalRedirectDetected) {
    // Kept purely informational unless paired with stronger signals
  }

  const breakdown: AdvancedUrlBreakdown = {
    originalUrl: rawSubmittedUrl.trim(),
    normalizedUrl,
    protocol: parsed.protocol.replace(':', ''),
    hostnameRaw,
    hostnameNormalized,
    hostnameCaseMixed,
    subdomains: psl.subdomains,
    registrableDomain: psl.registrableDomain,
    publicSuffix: psl.publicSuffix,
    port: explicitPort || (parsed.protocol === 'https:' ? '443 (default)' : '80 (default)'),
    isStandardPort,
    isUnusualPort,
    rawPath,
    decodedPath,
    pathEncodingLayers,
    encodedCharacterRatio,
    encodedKeywords,
    fragment: parsed.hash,
    queryParams,
    queryParameterCount: parsedPairs.length,
    duplicateParameterCount,
    redirectParameterCount,
    nestedUrlDetected,
    externalRedirectDetected,
    brandSimilarityResults,
  };

  const signals: UrlStructuralSignals = {
    urlLength: normalizedUrl.length,
    domainLength: hostnameNormalized.length,
    pathLength: decodedPath.length,
    queryLength: parsed.search.length,
    subdomainCount,
    maxSubdomainLength,
    hyphenCount,
    dotCount,
    specialCharCount,
    digitRatio,
    hasIpAddress: psl.isIp,
    hasAtSymbol,
    isHttps,
    isPunycode,
    hasMixedScript,
    unicodeConfusableDetected,
    hasSuspiciousTld,
    tld: psl.publicSuffix,
    isUrlShortener,
    hasSuspiciousExtension,
    hasExcessiveSubdomains,
    hasWordNumberAnomaly,
    charEntropy,
    suspiciousBrandInSubdomain,
    brandDomainMismatch,
    brandInPath,
    maxBrandSimilarityScore,
    encodedCharacterRatio,
    encodedKeywordDetected: encodedKeywords.length > 0,
    nestedUrlDetected,
    externalRedirectDetected,
    redirectParameterCount,
    queryParameterCount: parsedPairs.length,
    duplicateParameterCount,
    unusualPort: isUnusualPort,
    portNumber,
    suspiciousAuthenticationPath,
    hostnameCaseNormalized: hostnameCaseMixed,
    impersonatedBrands,
    anomalies,
  };

  return { breakdown, signals };
}
