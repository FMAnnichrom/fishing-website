import { getActiveKeywords } from '../db/database';
import { safeBoundedDecode } from './advancedUrlAnalyzer';
import type { KeywordMatch, KeywordRecord } from '../../shared/types';

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function matchesKeywordSurface(surface: string, keyword: string): boolean {
  const escaped = escapeRegex(keyword.toLowerCase());
  // Match at token boundaries (start/end or non-alphanumeric delimiters like -, _, /, ., ?, &, =)
  const regex = new RegExp(`(?:^|[^a-z0-9])${escaped}(?:$|[^a-z0-9])`, 'i');
  if (regex.test(surface)) return true;

  // Also detect concatenated multi-word phishing tokens like "verifyaccount" or "claimreward"
  const compactKeyword = keyword.toLowerCase().replace(/-/g, '');
  if (compactKeyword.length >= 6 && surface.includes(compactKeyword)) {
    return true;
  }
  return false;
}

export function detectSuspiciousKeywords(
  normalizedUrl: string,
  websiteText?: string,
  customKeywords?: KeywordRecord[],
): KeywordMatch[] {
  const keywords = customKeywords ?? getActiveKeywords();
  const matches: KeywordMatch[] = [];
  const seen = new Set<string>();

  let urlSurface = normalizedUrl.toLowerCase();
  let decodedSurface = urlSurface;
  try {
    const parsed = new URL(normalizedUrl);
    // Focus on host + path + search rather than protocol
    urlSurface = `${parsed.hostname}${parsed.pathname}${parsed.search}`.toLowerCase();
    const decodedPath = safeBoundedDecode(parsed.pathname).decoded;
    const decodedSearch = safeBoundedDecode(parsed.search).decoded;
    decodedSurface = `${parsed.hostname}${decodedPath}${decodedSearch}`.toLowerCase();
  } catch {
    // Fallback to raw normalizedUrl
  }

  for (const kw of keywords) {
    if (
      matchesKeywordSurface(urlSurface, kw.keyword) ||
      matchesKeywordSurface(decodedSurface, kw.keyword)
    ) {
      const key = `URL:${kw.keyword}`;
      if (!seen.has(key)) {
        seen.add(key);
        matches.push({
          keyword: kw.keyword,
          category: kw.category,
          location: 'URL',
          rationale: kw.rationale,
          weight: kw.weight,
        });
      }
    }
  }

  if (websiteText && websiteText.trim().length > 0) {
    const lowerText = websiteText.toLowerCase();
    for (const kw of keywords) {
      const normalizedPhrase = kw.keyword.replace(/-/g, ' ');
      if (
        matchesKeywordSurface(lowerText, kw.keyword) ||
        (normalizedPhrase !== kw.keyword && matchesKeywordSurface(lowerText, normalizedPhrase))
      ) {
        const key = `Website Content:${kw.keyword}`;
        if (!seen.has(key)) {
          seen.add(key);
          matches.push({
            keyword: kw.keyword,
            category: kw.category,
            location: 'Website Content',
            rationale: kw.rationale,
            weight: kw.weight,
          });
        }
      }
    }
  }

  return matches.sort((a, b) => b.weight - a.weight || a.keyword.localeCompare(b.keyword));
}
