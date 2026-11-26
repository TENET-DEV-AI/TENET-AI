import { useEffect, useRef, useState } from 'react';
import { verifyIdToken, type GoogleClaims } from '../utils/google';

const GIS_SRC = 'https://accounts.google.com/gsi/client';

let gisPromise: Promise<void> | null = null;

/** Loads the Google Identity Services script once per page. */
function loadGis(): Promise<void> {
  if (typeof window === 'undefined') return Promise.reject(new Error('no window'));
  if (window.google?.accounts?.id) return Promise.resolve();
  if (gisPromise) return gisPromise;

  gisPromise = new Promise<void>((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${GIS_SRC}"]`);
    const script = existing ?? document.createElement('script');
    script.addEventListener('load', () => resolve(), { once: true });
    script.addEventListener('error', () => {
      gisPromise = null;
      reject(new Error('Google sign-in could not be loaded.'));
    }, { once: true });
    if (!existing) {
      script.src = GIS_SRC;
      script.async = true;
      script.defer = true;
      document.head.appendChild(script);
    }
  });
  return gisPromise;
}

interface GoogleSignInProps {
  clientId: string;
  onSignedIn: (claims: GoogleClaims, idToken: string) => void;
  onError: (message: string) => void;
  /** Called when the script cannot load at all, so the host can open the fallback form. */
  onUnavailable?: () => void;
}

/**
 * Renders Google's own button (their branding rules require it) into the sign-in
 * card. The button is themed `filled_black` so it sits on the ink ground without
 * fighting the page.
 */
export function GoogleSignIn({ clientId, onSignedIn, onError, onUnavailable }: GoogleSignInProps) {
  const holder = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState<'loading' | 'ready' | 'failed'>('loading');

  useEffect(() => {
    let cancelled = false;

    loadGis()
      .then(() => {
        if (cancelled || !holder.current || !window.google?.accounts?.id) return;

        window.google.accounts.id.initialize({
          client_id: clientId,
          auto_select: false,
          cancel_on_tap_outside: true,
          ux_mode: 'popup',
          callback: response => {
            const result = verifyIdToken(response.credential, clientId);
            if (result.ok) onSignedIn(result.claims, response.credential);
            else onError(result.reason);
          },
        });

        holder.current.replaceChildren();
        window.google.accounts.id.renderButton(holder.current, {
          type: 'standard',
          theme: 'filled_black',
          size: 'large',
          text: 'continue_with',
          shape: 'rectangular',
          logo_alignment: 'left',
          width: 320,
        });
        setStatus('ready');
      })
      .catch(() => {
        if (cancelled) return;
        setStatus('failed');
        onUnavailable?.();
      });

    return () => {
      cancelled = true;
    };
  }, [clientId, onSignedIn, onError, onUnavailable]);

  return (
    <div className="google-signin">
      <div ref={holder} className="google-slot" data-testid="google-signin-button" />
      {status === 'loading' && <div className="google-skeleton" aria-hidden="true" />}
      {status === 'failed' && (
        <p className="hint" role="status">
          Google sign-in could not load — check your network or content blockers, then sign in with
          a password instead.
        </p>
      )}
    </div>
  );
}
