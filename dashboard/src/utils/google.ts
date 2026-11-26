/**
 * Google Identity Services — ID token handling.
 *
 * The console reads the `credential` (a JWT) that Google hands back to the
 * callback and pulls the claims out of it. That is enough to greet the analyst
 * and to hold a session in this tab.
 *
 * It is NOT authentication. Anyone can craft a JWT. The ingest/analyzer API must
 * verify the token server-side against Google's keys (or the tokeninfo endpoint)
 * before it trusts a single request. See docs/DESIGN_SYSTEM.md § Sign-in.
 */

export interface GoogleClaims {
  iss: string;
  aud: string;
  sub: string;
  email: string;
  email_verified: boolean | string;
  name?: string;
  picture?: string;
  exp: number;
  iat?: number;
}

const VALID_ISSUERS = ['accounts.google.com', 'https://accounts.google.com'];

function base64UrlDecode(segment: string): string {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/** Decodes the payload of an ID token. Returns null if it is not a JWT we can read. */
export function decodeIdToken(token: string): GoogleClaims | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const claims = JSON.parse(base64UrlDecode(parts[1])) as GoogleClaims;
    return typeof claims?.email === 'string' ? claims : null;
  } catch {
    return null;
  }
}

export type ClaimCheck = { ok: true; claims: GoogleClaims } | { ok: false; reason: string };

/**
 * Checks the claims the browser can check cheaply. Signature verification is the
 * server's job — see the note at the top of this file.
 */
export function verifyIdToken(token: string, clientId: string, now = Date.now()): ClaimCheck {
  const claims = decodeIdToken(token);
  if (!claims) return { ok: false, reason: 'Google returned a token we could not read.' };
  if (!VALID_ISSUERS.includes(claims.iss)) return { ok: false, reason: 'Token was not issued by Google.' };
  if (claims.aud !== clientId) return { ok: false, reason: 'Token was issued for a different client.' };
  if (typeof claims.exp === 'number' && claims.exp * 1000 <= now) {
    return { ok: false, reason: 'That sign-in has expired. Try again.' };
  }
  if (claims.email_verified === false || claims.email_verified === 'false') {
    return { ok: false, reason: 'That Google account has no verified email address.' };
  }
  return { ok: true, claims };
}

/** Calls Google's sign-out helper so the next visit does not silently re-use the account. */
export function disableGoogleAutoSelect(): void {
  try {
    window.google?.accounts?.id?.disableAutoSelect?.();
  } catch {
    /* GIS not loaded — nothing to disable */
  }
}
