import * as cheerio from 'cheerio';
import { validateOutboundTarget } from './ssrfGuard';
import { detectSuspiciousKeywords } from './keywordDetector';
import { extractRegistrableDomain } from './urlValidator';
import type { WebsiteInspectionResult } from '../../shared/types';

const MAX_REDIRECTS = 3;
const DEFAULT_MAX_BYTES = 524288; // 512 KB
const DEFAULT_TIMEOUT_MS = 4000;

/**
 * Optional Isolated Website Inspector
 * DISABLED BY DEFAULT (ENABLE_WEBSITE_INSPECTION=true required).
 * Enforces SSRF & DNS-rebinding validation before the initial request and on
 * every redirect hop, strict byte limits, timeouts, no cookies/credentials,
 * and non-executing static HTML text extraction.
 */
export async function inspectWebsiteSafely(normalizedUrl: string): Promise<WebsiteInspectionResult> {
  const enabled = process.env.ENABLE_WEBSITE_INSPECTION === 'true';
  if (!enabled) {
    return {
      enabled: false,
      status: 'disabled',
      reason:
        'Isolated website inspection is disabled by default (ENABLE_WEBSITE_INSPECTION=false). Analysis completed using ML, URL structure, keywords, and threat intelligence.',
    };
  }

  const maxBytes = Number(process.env.INSPECTION_MAX_BYTES || DEFAULT_MAX_BYTES);
  const timeoutMs = Number(process.env.INSPECTION_TIMEOUT_MS || DEFAULT_TIMEOUT_MS);

  const redirectChain: string[] = [normalizedUrl];
  let currentUrl = normalizedUrl;
  let finalResponse: Response | null = null;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const ssrf = await validateOutboundTarget(currentUrl);
    if (!ssrf.allowed) {
      return {
        enabled: true,
        status: 'blocked_ssrf',
        reason: ssrf.reason || 'Outbound inspection blocked by SSRF policy.',
        redirectChain,
      };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        credentials: 'omit',
        headers: {
          'User-Agent': 'PhishingURLDetector-IsolatedInspector/1.0',
          Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1',
        },
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (resp.status >= 300 && resp.status < 400) {
        const location = resp.headers.get('location');
        if (!location) {
          finalResponse = resp;
          break;
        }
        if (hop === MAX_REDIRECTS) {
          return {
            enabled: true,
            status: 'failed',
            reason: `Exceeded maximum redirect limit (${MAX_REDIRECTS}).`,
            redirectChain,
          };
        }
        const nextUrl = new URL(location, currentUrl).toString();
        redirectChain.push(nextUrl);
        currentUrl = nextUrl;
        continue;
      }

      finalResponse = resp;
      break;
    } catch {
      clearTimeout(timer);
      return {
        enabled: true,
        status: 'failed',
        reason: 'Website inspection timed out or target refused connection.',
        redirectChain,
      };
    }
  }

  if (!finalResponse) {
    return {
      enabled: true,
      status: 'failed',
      reason: 'No HTTP response received during isolated inspection.',
      redirectChain,
    };
  }

  const contentType = finalResponse.headers.get('content-type') || '';
  if (!contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
    return {
      enabled: true,
      status: 'completed',
      reason: `Skipped HTML parsing for non-HTML content-type (${contentType || 'unknown'}).`,
      redirectChain,
    };
  }

  try {
    const reader = finalResponse.body?.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;

    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          totalBytes += value.byteLength;
          if (totalBytes > maxBytes) {
            await reader.cancel();
            break;
          }
          chunks.push(value);
        }
      }
    }

    const html = Buffer.concat(chunks).toString('utf8');
    const $ = cheerio.load(html);
    // Strip scripts/styles so only visible text is inspected
    $('script, style, noscript').remove();

    const pageTitle = $('title').first().text().trim().slice(0, 160);
    const bodyText = $('body').text().replace(/\s+/g, ' ').trim();
    const textExcerpt = bodyText.slice(0, 320);

    const hasPasswordField = $('input[type="password"]').length > 0;
    const hasLoginForm =
      hasPasswordField ||
      $('form').filter((_, el) => /login|signin|auth|account/i.test($(el).text() + ($(el).attr('action') || ''))).length > 0;

    const hasPaymentField =
      $('input[name*="card" i], input[name*="cvv" i], input[name*="cc" i], input[autocomplete="cc-number"]').length > 0;

    const finalHost = new URL(currentUrl).hostname.toLowerCase();
    const finalRegDomain = extractRegistrableDomain(finalHost);

    const formActionDomains: string[] = [];
    $('form').each((_, el) => {
      const action = $(el).attr('action');
      if (action && /^https?:\/\//i.test(action)) {
        try {
          const actionHost = new URL(action).hostname.toLowerCase();
          if (!formActionDomains.includes(actionHost)) {
            formActionDomains.push(actionHost);
          }
        } catch {
          // Ignore invalid action URL
        }
      }
    });

    const brandHints: string[] = [];
    const checkBrandSurface = `${pageTitle} ${textExcerpt}`.toLowerCase();
    const brandKeywords = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'chase', 'wellsfargo', 'coinbase', 'binance'];
    for (const brand of brandKeywords) {
      if (checkBrandSurface.includes(brand) && !finalRegDomain.includes(brand)) {
        brandHints.push(`Page content references "${brand}" while hosted on unrelated domain ${finalRegDomain}.`);
      }
    }

    const contentKeywords = detectSuspiciousKeywords(currentUrl, `${pageTitle} ${bodyText.slice(0, 4000)}`).filter(
      (k) => k.location === 'Website Content',
    );

    return {
      enabled: true,
      status: 'completed',
      reason: 'Isolated static HTML inspection completed safely.',
      pageTitle,
      textExcerpt,
      redirectChain,
      hasLoginForm,
      hasPasswordField,
      hasPaymentField,
      formActionDomains,
      brandImpersonationHints: brandHints,
      keywordMatches: contentKeywords,
    };
  } catch {
    return {
      enabled: true,
      status: 'failed',
      reason: 'Failed to safely parse HTML payload.',
      redirectChain,
    };
  }
}
