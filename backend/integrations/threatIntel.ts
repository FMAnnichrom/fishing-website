import {
  logFeedSync,
  lookupLocalThreatIndicator,
  purgeExpiredIndicators,
  upsertThreatIndicators,
} from '../db/database';
import { validateAndNormalizeUrl } from '../services/urlValidator';
import type { ProviderCheckResult } from '../../shared/types';

const DEFAULT_TIMEOUT_MS = 4000;

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 1. Local Threat Intelligence Database Adapter
 */
export async function checkLocalThreatFeed(
  normalizedUrl: string,
  domain: string,
): Promise<ProviderCheckResult> {
  const started = Date.now();
  try {
    const match = lookupLocalThreatIndicator(normalizedUrl, domain);
    const latencyMs = Date.now() - started;
    if (match) {
      return {
        provider: 'Local Threat Feed Index',
        status: 'match',
        threatCategory: match.threatCategory,
        detectionStatus: match.verificationStatus,
        firstSeen: match.firstSeen,
        lastSeen: match.lastSeen,
        source: match.source,
        activity: 'Listed in locally ingested threat-intelligence database',
        message: `Matched indicator from ${match.source} (${match.threatCategory}).`,
        latencyMs,
      };
    }
    return {
      provider: 'Local Threat Feed Index',
      status: 'clean',
      message: 'No exact match found in active local threat-feed records.',
      latencyMs,
    };
  } catch {
    return {
      provider: 'Local Threat Feed Index',
      status: 'error',
      message: 'Local threat-feed query encountered an error.',
      latencyMs: Date.now() - started,
    };
  }
}

/**
 * 2. Google Safe Browsing API v4 Adapter
 */
export async function checkGoogleSafeBrowsing(normalizedUrl: string): Promise<ProviderCheckResult> {
  const started = Date.now();
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim();
  if (!apiKey) {
    return {
      provider: 'Google Safe Browsing',
      status: 'not_configured',
      message: 'API key (GOOGLE_SAFE_BROWSING_API_KEY) is not configured on the server.',
      latencyMs: Date.now() - started,
    };
  }

  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;
    const body = {
      client: { clientId: 'phishing-url-detector', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: normalizedUrl }],
      },
    };

    const resp = await fetchWithTimeout(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const latencyMs = Date.now() - started;
    if (!resp.ok) {
      return {
        provider: 'Google Safe Browsing',
        status: 'unavailable',
        message: `Provider returned HTTP ${resp.status}.`,
        latencyMs,
      };
    }

    const data = (await resp.json()) as {
      matches?: Array<{ threatType?: string; platformType?: string }>;
    };

    if (data.matches && data.matches.length > 0) {
      const top = data.matches[0];
      return {
        provider: 'Google Safe Browsing',
        status: 'match',
        threatCategory: top.threatType || 'SOCIAL_ENGINEERING',
        detectionStatus: 'confirmed_external',
        source: 'Google Safe Browsing v4',
        activity: `Flagged for ${top.threatType ?? 'phishing/malware'}`,
        message: `Flagged by Google Safe Browsing (${top.threatType ?? 'SOCIAL_ENGINEERING'}).`,
        latencyMs,
      };
    }

    return {
      provider: 'Google Safe Browsing',
      status: 'clean',
      source: 'Google Safe Browsing v4',
      message: 'No threat match returned by Google Safe Browsing.',
      latencyMs,
    };
  } catch {
    return {
      provider: 'Google Safe Browsing',
      status: 'unavailable',
      message: 'Request timed out or network was unreachable.',
      latencyMs: Date.now() - started,
    };
  }
}

/**
 * 3. PhishTank API Adapter
 */
export async function checkPhishTank(normalizedUrl: string): Promise<ProviderCheckResult> {
  const started = Date.now();
  const apiKey = process.env.PHISHTANK_API_KEY?.trim();
  if (!apiKey) {
    return {
      provider: 'PhishTank',
      status: 'not_configured',
      message: 'API key (PHISHTANK_API_KEY) is not configured on the server.',
      latencyMs: Date.now() - started,
    };
  }

  try {
    const form = new URLSearchParams();
    form.set('url', normalizedUrl);
    form.set('format', 'json');
    form.set('app_key', apiKey);

    const resp = await fetchWithTimeout('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': process.env.PHISHTANK_USER_AGENT || 'phishtank/phishing-url-detector',
      },
      body: form.toString(),
    });

    const latencyMs = Date.now() - started;
    if (!resp.ok) {
      return {
        provider: 'PhishTank',
        status: 'unavailable',
        message: `Provider returned HTTP ${resp.status}.`,
        latencyMs,
      };
    }

    const data = (await resp.json()) as {
      results?: {
        in_database?: boolean;
        valid?: boolean;
        verified?: boolean;
        verified_at?: string;
        phish_detail_page?: string;
      };
    };

    const res = data.results;
    if (res?.in_database && res?.valid) {
      return {
        provider: 'PhishTank',
        status: 'match',
        threatCategory: 'Phishing',
        detectionStatus: res.verified ? 'verified' : 'reported',
        lastSeen: res.verified_at,
        source: 'PhishTank',
        activity: 'Reported phishing URL in PhishTank database',
        message: res.verified
          ? 'Confirmed verified phishing URL in PhishTank.'
          : 'Present in PhishTank database.',
        latencyMs,
      };
    }

    return {
      provider: 'PhishTank',
      status: 'clean',
      source: 'PhishTank',
      message: 'URL not listed as active phishing in PhishTank.',
      latencyMs,
    };
  } catch {
    return {
      provider: 'PhishTank',
      status: 'unavailable',
      message: 'Request timed out or network was unreachable.',
      latencyMs: Date.now() - started,
    };
  }
}

/**
 * 4. abuse.ch URLhaus API Adapter
 */
export async function checkUrlHaus(normalizedUrl: string): Promise<ProviderCheckResult> {
  const started = Date.now();
  const authKey = process.env.URLHAUS_AUTH_KEY?.trim();
  if (!authKey) {
    return {
      provider: 'URLhaus (abuse.ch)',
      status: 'not_configured',
      message: 'Auth key (URLHAUS_AUTH_KEY) is not configured on the server.',
      latencyMs: Date.now() - started,
    };
  }

  try {
    const form = new URLSearchParams();
    form.set('url', normalizedUrl);

    const resp = await fetchWithTimeout('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Auth-Key': authKey,
      },
      body: form.toString(),
    });

    const latencyMs = Date.now() - started;
    if (!resp.ok) {
      return {
        provider: 'URLhaus (abuse.ch)',
        status: 'unavailable',
        message: `Provider returned HTTP ${resp.status}.`,
        latencyMs,
      };
    }

    const data = (await resp.json()) as {
      query_status?: string;
      threat?: string;
      url_status?: string;
      date_added?: string;
      last_online?: string;
      tags?: string[];
    };

    if (data.query_status === 'ok') {
      return {
        provider: 'URLhaus (abuse.ch)',
        status: 'match',
        threatCategory: data.threat || 'malware_download',
        detectionStatus: data.url_status || 'active',
        firstSeen: data.date_added,
        lastSeen: data.last_online || data.date_added,
        source: 'abuse.ch URLhaus',
        activity: data.tags?.length ? `Tags: ${data.tags.join(', ')}` : 'Malicious payload distribution',
        message: `Listed in URLhaus (${data.threat ?? 'malware'}, status: ${data.url_status ?? 'unknown'}).`,
        latencyMs,
      };
    }

    return {
      provider: 'URLhaus (abuse.ch)',
      status: 'clean',
      source: 'abuse.ch URLhaus',
      message: 'URL not found in URLhaus threat database.',
      latencyMs,
    };
  } catch {
    return {
      provider: 'URLhaus (abuse.ch)',
      status: 'unavailable',
      message: 'Request timed out or network was unreachable.',
      latencyMs: Date.now() - started,
    };
  }
}

export async function runAllThreatIntelChecks(
  normalizedUrl: string,
  domain: string,
): Promise<ProviderCheckResult[]> {
  const results = await Promise.all([
    checkLocalThreatFeed(normalizedUrl, domain),
    checkGoogleSafeBrowsing(normalizedUrl),
    checkPhishTank(normalizedUrl),
    checkUrlHaus(normalizedUrl),
  ]);
  return results;
}

/**
 * Background / Admin Feed Ingestion from Public Feeds (OpenPhish community feed + URLhaus public text feed)
 */
export async function syncPublicThreatFeeds(): Promise<{
  purgedExpired: number;
  results: Array<{ source: string; status: string; ingested: number; message: string }>;
}> {
  const purgedExpired = purgeExpiredIndicators();
  const results: Array<{ source: string; status: string; ingested: number; message: string }> = [];

  const feedConfigs = [
    {
      name: 'OpenPhish Community Feed',
      url: 'https://openphish.com/feed.txt',
      category: 'Phishing',
    },
    {
      name: 'URLhaus Public Online Feed',
      url: 'https://urlhaus.abuse.ch/downloads/text_online/',
      category: 'Malware / Malicious URL',
    },
  ];

  for (const feed of feedConfigs) {
    try {
      const resp = await fetchWithTimeout(feed.url, { method: 'GET' }, 6000);
      if (!resp.ok) {
        const msg = `Feed returned HTTP ${resp.status}.`;
        logFeedSync(feed.name, 'unavailable', 0, msg);
        results.push({ source: feed.name, status: 'unavailable', ingested: 0, message: msg });
        continue;
      }

      const text = await resp.text();
      const lines = text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith('#'))
        .slice(0, 500);

      const cleaned: Array<{
        normalizedUrl: string;
        domain: string;
        threatCategory: string;
        source: string;
        verificationStatus: string;
      }> = [];

      for (const rawLine of lines) {
        const parsed = validateAndNormalizeUrl(rawLine);
        if (!parsed.valid) continue;
        cleaned.push({
          normalizedUrl: parsed.normalizedUrl,
          domain: parsed.domain,
          threatCategory: feed.category,
          source: feed.name,
          verificationStatus: 'feed_reported',
        });
      }

      const { insertedOrUpdated, skippedDuplicates } = upsertThreatIndicators(cleaned);
      const msg = `Ingested ${insertedOrUpdated} indicators (${skippedDuplicates} batch duplicates skipped).`;
      logFeedSync(feed.name, 'success', insertedOrUpdated, msg);
      results.push({ source: feed.name, status: 'success', ingested: insertedOrUpdated, message: msg });
    } catch {
      const msg = 'Feed unreachable or timed out.';
      logFeedSync(feed.name, 'unavailable', 0, msg);
      results.push({ source: feed.name, status: 'unavailable', ingested: 0, message: msg });
    }
  }

  return { purgedExpired, results };
}
