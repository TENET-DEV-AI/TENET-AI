import { describe, expect, it } from 'vitest';
import { decodeIdToken, verifyIdToken } from './google';

/** Builds an unsigned JWT-shaped string (header.payload.signature). */
function makeToken(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: 'RS256', typ: 'JWT' }): string {
  const encode = (value: Record<string, unknown>) =>
    btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${encode(header)}.${encode(claims)}.signature-not-checked-here`;
}

const CLIENT_ID = '1234567890-abc.apps.googleusercontent.com';

const validClaims = {
  iss: 'https://accounts.google.com',
  aud: CLIENT_ID,
  sub: '110169484474386276334',
  email: 'analyst@tenet.ai',
  email_verified: true,
  name: 'Savio D Souza',
  picture: 'https://example.com/a.png',
  iat: 1_700_000_000,
  exp: 1_700_003_600,
};

describe('decodeIdToken', () => {
  it('reads the claims out of a JWT payload', () => {
    const claims = decodeIdToken(makeToken(validClaims));
    expect(claims?.email).toBe('analyst@tenet.ai');
    expect(claims?.name).toBe('Savio D Souza');
  });

  it('returns null for anything that is not a three-part token', () => {
    expect(decodeIdToken('not-a-token')).toBeNull();
    expect(decodeIdToken('')).toBeNull();
  });

  it('returns null when the payload is not JSON', () => {
    const broken = `${btoa('{"alg":"RS256"}')}.${btoa('not json')}.sig`;
    expect(decodeIdToken(broken)).toBeNull();
  });
});

describe('verifyIdToken', () => {
  const now = 1_700_001_000 * 1000;

  it('accepts a well-formed token for this client', () => {
    const result = verifyIdToken(makeToken(validClaims), CLIENT_ID, now);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.claims.email).toBe('analyst@tenet.ai');
  });

  it('rejects a token issued for another client', () => {
    const token = makeToken({ ...validClaims, aud: 'someone-else.apps.googleusercontent.com' });
    const result = verifyIdToken(token, CLIENT_ID, now);
    expect(result).toEqual({ ok: false, reason: 'Token was issued for a different client.' });
  });

  it('rejects a token from another issuer', () => {
    const token = makeToken({ ...validClaims, iss: 'https://evil.example.com' });
    const result = verifyIdToken(token, CLIENT_ID, now);
    expect(result.ok).toBe(false);
  });

  it('rejects an expired token', () => {
    const token = makeToken({ ...validClaims, exp: 1_699_999_000 });
    const result = verifyIdToken(token, CLIENT_ID, now);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/expired/i);
  });

  it('rejects an unverified email address', () => {
    const token = makeToken({ ...validClaims, email_verified: false });
    const result = verifyIdToken(token, CLIENT_ID, now);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/verified/i);
  });

  it('accepts the bare "accounts.google.com" issuer Google also emits', () => {
    const token = makeToken({ ...validClaims, iss: 'accounts.google.com' });
    expect(verifyIdToken(token, CLIENT_ID, now).ok).toBe(true);
  });
});
