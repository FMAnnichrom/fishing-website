import type { KeywordRecord } from './types';

export const SEED_KEYWORDS: Array<Omit<KeywordRecord, 'id' | 'active'>> = [
  {
    keyword: 'login',
    category: 'Credential theft',
    rationale: 'Commonly used in phishing paths or fake subdomains to mimic authentication portals.',
    weight: 4,
  },
  {
    keyword: 'signin',
    category: 'Credential theft',
    rationale: 'Frequently paired with spoofed brand names to harvest account credentials.',
    weight: 4,
  },
  {
    keyword: 'password',
    category: 'Credential theft',
    rationale: 'Direct reference to password entry or expiration traps outside official domains.',
    weight: 5,
  },
  {
    keyword: 'reset-password',
    category: 'Credential theft',
    rationale: 'Urges targets to click fake password reset flows to capture current credentials.',
    weight: 6,
  },
  {
    keyword: 'credentials',
    category: 'Credential theft',
    rationale: 'Explicit credential collection indicator uncommon in normal user-facing URLs.',
    weight: 6,
  },
  {
    keyword: 'seed-phrase',
    category: 'Credential theft',
    rationale: 'Targets cryptocurrency wallet recovery phrases in Web3 phishing kits.',
    weight: 8,
  },
  {
    keyword: 'verify',
    category: 'Account verification',
    rationale: 'Used in pretexting links claiming an account requires immediate verification.',
    weight: 5,
  },
  {
    keyword: 'confirm-identity',
    category: 'Account verification',
    rationale: 'Social engineering phrase designed to bypass user skepticism before collecting PII.',
    weight: 7,
  },
  {
    keyword: 'authentication',
    category: 'Account verification',
    rationale: 'Appears in counterfeit MFA or single sign-on interception pages.',
    weight: 5,
  },
  {
    keyword: 'account',
    category: 'Account verification',
    rationale: 'Often combined with urgency modifiers in deceptive subdomains or paths.',
    weight: 3,
  },
  {
    keyword: 'update',
    category: 'Account verification',
    rationale: 'Used in fake billing, security, or software update lures.',
    weight: 3,
  },
  {
    keyword: 'reauth',
    category: 'Account verification',
    rationale: 'Mimics session re-authentication prompts to capture active login tokens.',
    weight: 6,
  },
  {
    keyword: 'bank',
    category: 'Banking and financial fraud',
    rationale: 'Financial institution keyword frequently abused on non-bank domains.',
    weight: 5,
  },
  {
    keyword: 'wire-transfer',
    category: 'Banking and financial fraud',
    rationale: 'Associated with business email compromise and fraudulent banking portals.',
    weight: 7,
  },
  {
    keyword: 'tax-refund',
    category: 'Banking and financial fraud',
    rationale: 'Seasonal government and tax impersonation lure targeting banking details.',
    weight: 7,
  },
  {
    keyword: 'payment',
    category: 'Payment fraud',
    rationale: 'Commonly used in fake invoice, delivery fee, and billing-update scams.',
    weight: 5,
  },
  {
    keyword: 'wallet',
    category: 'Payment fraud',
    rationale: 'Targeted in digital wallet and crypto drainer phishing campaigns.',
    weight: 6,
  },
  {
    keyword: 'billing',
    category: 'Payment fraud',
    rationale: 'Frequently appears in subscription-declined phishing notifications.',
    weight: 5,
  },
  {
    keyword: 'invoice',
    category: 'Payment fraud',
    rationale: 'Used in document-share lures that harvest corporate email credentials.',
    weight: 5,
  },
  {
    keyword: 'free-prize',
    category: 'Fake rewards and offers',
    rationale: 'Classic bait phrase used in sweepstakes and advance-fee phishing sites.',
    weight: 8,
  },
  {
    keyword: 'claim-reward',
    category: 'Fake rewards and offers',
    rationale: 'Induces urgency to claim nonexistent prizes, gift cards, or crypto airdrops.',
    weight: 8,
  },
  {
    keyword: 'giveaway',
    category: 'Fake rewards and offers',
    rationale: 'Frequently exploited in social media and cryptocurrency impersonation scams.',
    weight: 7,
  },
  {
    keyword: 'airdrop',
    category: 'Fake rewards and offers',
    rationale: 'High-risk Web3 lure prompting users to sign malicious wallet approvals.',
    weight: 7,
  },
  {
    keyword: 'account-suspended',
    category: 'Urgent security alerts',
    rationale: 'Creates artificial panic so victims submit credentials without checking the domain.',
    weight: 8,
  },
  {
    keyword: 'urgent-action',
    category: 'Urgent security alerts',
    rationale: 'High-pressure social engineering phrase common in phishing lures.',
    weight: 7,
  },
  {
    keyword: 'fraud-alert',
    category: 'Urgent security alerts',
    rationale: 'Impersonates bank fraud teams to trick users into divulging OTPs or PINs.',
    weight: 7,
  },
  {
    keyword: 'secure',
    category: 'Impersonation',
    rationale: 'Frequently prepended to lookalike domains (e.g., secure-brand-login) to manufacture false trust.',
    weight: 4,
  },
  {
    keyword: 'support',
    category: 'Impersonation',
    rationale: 'Used on unauthorized helpdesk domains mimicking official customer support.',
    weight: 3,
  },
];

export const SEED_TEST_INDICATORS: Array<{
  normalizedUrl: string;
  domain: string;
  threatCategory: string;
  source: string;
  verificationStatus: string;
}> = [
  {
    normalizedUrl: 'http://testsafebrowsing.appspot.com/s/phishing.html',
    domain: 'testsafebrowsing.appspot.com',
    threatCategory: 'Phishing (Safe Test Fixture)',
    source: 'Safe Reference Test Feed',
    verificationStatus: 'verified_test_indicator',
  },
  {
    normalizedUrl: 'http://testsafebrowsing.appspot.com/s/malware.html',
    domain: 'testsafebrowsing.appspot.com',
    threatCategory: 'Malware (Safe Test Fixture)',
    source: 'Safe Reference Test Feed',
    verificationStatus: 'verified_test_indicator',
  },
  {
    normalizedUrl: 'http://phishing.example.invalid/login/verify',
    domain: 'phishing.example.invalid',
    threatCategory: 'Phishing (RFC 2606 Test Fixture)',
    source: 'Safe Reference Test Feed',
    verificationStatus: 'verified_test_indicator',
  },
];
