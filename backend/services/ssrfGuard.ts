import dns from 'node:dns/promises';
import net from 'node:net';

/**
 * SSRF & DNS Rebinding Guard
 * Validates IPv4 and IPv6 addresses and resolved hostnames to prevent access to
 * loopback, private RFC1918 networks, link-local / cloud metadata (169.254.169.254),
 * carrier-grade NAT, or multicast ranges.
 */

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const val = Number(part);
    if (val < 0 || val > 255) return null;
    num = (num << 8) | val;
  }
  return num >>> 0;
}

function inCidr4(ipInt: number, baseStr: string, maskBits: number): boolean {
  const base = ipv4ToInt(baseStr);
  if (base === null) return false;
  const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
  return (ipInt & mask) === (base & mask);
}

export function isPrivateOrReservedIp(rawIp: string): boolean {
  const ip = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!ip) return true;

  // Handle IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1
  if (ip.startsWith('::ffff:')) {
    const mappedV4 = ip.slice(7);
    if (net.isIPv4(mappedV4)) {
      return isPrivateOrReservedIp(mappedV4);
    }
  }

  if (net.isIPv4(ip)) {
    const ipInt = ipv4ToInt(ip);
    if (ipInt === null) return true;
    return (
      inCidr4(ipInt, '0.0.0.0', 8) || // Current network
      inCidr4(ipInt, '10.0.0.0', 8) || // RFC1918 Private
      inCidr4(ipInt, '100.64.0.0', 10) || // Carrier-grade NAT
      inCidr4(ipInt, '127.0.0.0', 8) || // Loopback
      inCidr4(ipInt, '169.254.0.0', 16) || // Link-local & cloud metadata (169.254.169.254)
      inCidr4(ipInt, '172.16.0.0', 12) || // RFC1918 Private
      inCidr4(ipInt, '192.0.0.0', 24) || // IETF Protocol Assignments
      inCidr4(ipInt, '192.0.2.0', 24) || // TEST-NET-1
      inCidr4(ipInt, '192.168.0.0', 16) || // RFC1918 Private
      inCidr4(ipInt, '198.18.0.0', 15) || // Benchmarking
      inCidr4(ipInt, '198.51.100.0', 24) || // TEST-NET-2
      inCidr4(ipInt, '203.0.113.0', 24) || // TEST-NET-3
      inCidr4(ipInt, '224.0.0.0', 4) || // Multicast
      inCidr4(ipInt, '240.0.0.0', 4) // Reserved / Broadcast
    );
  }

  if (net.isIPv6(ip)) {
    const clean = ip.split('%')[0];
    if (clean === '::' || clean === '::1') return true;
    // Unique local (fc00::/7), link-local (fe80::/10), multicast (ff00::/8)
    if (/^(fc|fd)[0-9a-f]{2}:/i.test(clean)) return true;
    if (/^fe[89ab][0-9a-f]:/i.test(clean)) return true;
    if (/^ff[0-9a-f]{2}:/i.test(clean)) return true;
    // Documentation prefix 2001:db8::/32
    if (/^2001:0?db8:/i.test(clean)) return true;
    return false;
  }

  return true;
}

export function isBlockedHostname(hostname: string): boolean {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '');
  if (!host) return true;
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host === 'metadata.google.internal' ||
    host === 'metadata' ||
    host === '169.254.169.254'
  ) {
    return true;
  }
  const cleanIp = host.replace(/^\[|\]$/g, '');
  if (net.isIP(cleanIp)) {
    return isPrivateOrReservedIp(cleanIp);
  }
  return false;
}

export interface SsrfCheckResult {
  allowed: boolean;
  reason?: string;
  resolvedIps: string[];
}

export async function validateOutboundTarget(urlString: string): Promise<SsrfCheckResult> {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return { allowed: false, reason: 'Malformed URL rejected before outbound request.', resolvedIps: [] };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { allowed: false, reason: 'Disallowed protocol for outbound inspection.', resolvedIps: [] };
  }

  if (parsed.username || parsed.password) {
    return { allowed: false, reason: 'URLs containing embedded credentials are blocked from inspection.', resolvedIps: [] };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (isBlockedHostname(hostname)) {
    return {
      allowed: false,
      reason: `SSRF guard blocked private, loopback, or internal hostname (${hostname}).`,
      resolvedIps: [],
    };
  }

  const cleanIp = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(cleanIp)) {
    if (isPrivateOrReservedIp(cleanIp)) {
      return {
        allowed: false,
        reason: `SSRF guard blocked private or reserved IP address (${cleanIp}).`,
        resolvedIps: [cleanIp],
      };
    }
    return { allowed: true, resolvedIps: [cleanIp] };
  }

  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    if (!records || records.length === 0) {
      return { allowed: false, reason: `DNS resolution returned no records for ${hostname}.`, resolvedIps: [] };
    }
    const resolvedIps = records.map((r) => r.address);
    for (const ip of resolvedIps) {
      if (isPrivateOrReservedIp(ip)) {
        return {
          allowed: false,
          reason: `DNS rebinding / SSRF guard blocked hostname ${hostname} resolving to private/reserved IP (${ip}).`,
          resolvedIps,
        };
      }
    }
    return { allowed: true, resolvedIps };
  } catch {
    return {
      allowed: false,
      reason: `Unable to resolve DNS for ${hostname} safely.`,
      resolvedIps: [],
    };
  }
}
