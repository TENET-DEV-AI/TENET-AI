import { useCallback, useState } from 'react';
import { GoogleSignIn } from './GoogleSignIn';
import type { GoogleClaims } from '../utils/google';
import { recordSignIn } from '../utils/signinLog';

export interface ConsoleUser {
  email: string;
  role: string;
  token: string;
  name?: string;
  picture?: string;
}

interface LoginViewProps {
  onLoginSuccess: (user: ConsoleUser) => void;
}

/**
 * Demo accounts exist for local development and the e2e suite. A production
 * build has no local accounts at all — Google, and whatever the API allows, is
 * the only way in.
 */
const VALID_ACCOUNTS: Record<string, string> = import.meta.env.DEV
  ? {
      'analyst@tenet.ai': 'password123',
      'admin@tenet.ai': 'admin123',
    }
  : {};

/**
 * `VITE_GOOGLE_CLIENT_ID` switches the console to Google sign-in. Without it the
 * credential form stays the way in, so a self-hosted build or an offline demo
 * still works. Google sign-in proves *who* someone is; the API decides what they
 * may read — see docs/DESIGN_SYSTEM.md § Sign-in.
 */
const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID || '';

export function LoginView({ onLoginSuccess }: LoginViewProps) {
  const googleEnabled = Boolean(GOOGLE_CLIENT_ID);

  const [username, setUsername] = useState('analyst@tenet.ai');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('Senior SOC Responder');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleGoogle = useCallback(
    (claims: GoogleClaims, idToken: string) => {
      setError(null);
      // Best-effort: appends to the server-side sign-in log, never blocks entry.
      void recordSignIn(claims.email, 'google', 'SOC Analyst');
      onLoginSuccess({
        email: claims.email,
        name: claims.name,
        picture: claims.picture,
        role: 'SOC Analyst',
        token: idToken,
      });
    },
    [onLoginSuccess],
  );

  const handleGoogleError = useCallback((message: string) => setError(message), []);


  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);

    if (!username.trim()) {
      setError('Analyst email or ID is required.');
      return;
    }
    if (!password) {
      setError('Password is required.');
      return;
    }
    if (VALID_ACCOUNTS[username.trim()] !== password) {
      setError(
        googleEnabled
          ? 'Local credentials are not enabled in this build. Sign in with Google.'
          : 'Invalid credentials. Use analyst@tenet.ai / password123 or fill the demo credentials.',
      );
      return;
    }

    setIsLoading(true);
    setTimeout(() => {
      setIsLoading(false);
      void recordSignIn(username.trim(), 'password', role);
      onLoginSuccess({ email: username.trim(), role, token: `tenet_token_${Date.now()}` });
    }, 250);
  };

  const fillDemo = () => {
    setUsername('analyst@tenet.ai');
    setPassword('password123');
    setRole('Senior SOC Responder');
    setError(null);
  };

  return (
    <div className="auth" data-testid="soc-login-page">
      <div className="plate">
        <div className="brand">
          <svg className="mk" viewBox="0 0 100 100" width="30" height="30" aria-hidden="true">
            <circle cx="50" cy="50" r="42.5" fill="none" stroke="currentColor" strokeWidth="4.5" />
            <path d="M24 26H76V34H54V64H46V34H24Z" fill="currentColor" />
            <path d="M46 66H54V76H46Z" fill="#E1593C" />
          </svg>
          <div>
            <b style={{ fontFamily: 'var(--f-display)', fontSize: 17, display: 'block', lineHeight: 1.1 }}>TENET AI</b>
            <span className="lbl">console · 0.2.0</span>
          </div>
        </div>

        <div className="mark">
          <h2>
            Somebody still has
            <br />
            to read <em>the log.</em>
          </h2>
          <p>
            Every prompt your applications send is inspected before it reaches a model. This console is where the
            blocked ones land — evidence, verdict and the analyst who closed them.
          </p>
        </div>

        <ul>
          <li>Interceptions · 24 h</li>
          <li>Analyst sign-in required</li>
          <li>Session held on this device</li>
        </ul>
      </div>

      <div className="pane">
        <div className="card">
          <div className="hd">
            <span className="badge">Restricted · SOC portal</span>
            <h1>TENET AI Console</h1>
            <p className="hint" style={{ marginTop: 8, lineHeight: 1.65 }}>
              {googleEnabled
                ? 'Sign in with the Google account your organisation issued you, or use analyst credentials.'
                : 'Authenticate with your analyst credentials to inspect intercepted LLM events.'}
            </p>
          </div>

          {error && (
            <div className="err" role="alert" data-testid="login-error-message">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                <circle cx="12" cy="12" r="9" />
                <path d="M12 8v5M12 16h.01" />
              </svg>
              <span>{error}</span>
            </div>
          )}

          {googleEnabled && (
            <>
              <GoogleSignIn
                clientId={GOOGLE_CLIENT_ID}
                onSignedIn={handleGoogle}
                onError={handleGoogleError}
              />
              <div className="auth-divider" role="presentation">
                <span>or sign in with credentials</span>
              </div>
            </>
          )}

          <form onSubmit={handleSubmit} data-testid="login-form">
            <div className="field">
              <label htmlFor="login-username">Analyst email / ID</label>
              <input
                id="login-username"
                data-testid="login-username-input"
                type="text"
                value={username}
                onChange={event => setUsername(event.target.value)}
                placeholder="analyst@tenet.ai"
                autoComplete="username"
              />
            </div>

            <div className="field">
              <label htmlFor="login-password">Password</label>
              <input
                id="login-password"
                data-testid="login-password-input"
                type="password"
                value={password}
                onChange={event => setPassword(event.target.value)}
                placeholder="••••••••••••"
                autoComplete="current-password"
              />
            </div>

            <div className="field">
              <label htmlFor="login-role">Operational role</label>
              <select
                id="login-role"
                data-testid="login-role-select"
                value={role}
                onChange={event => setRole(event.target.value)}
              >
                <option value="Tier-1 Analyst">Tier-1 SOC Analyst</option>
                <option value="Senior SOC Responder">Senior SOC Responder</option>
                <option value="Lead SecOps Admin">Lead SecOps Admin</option>
              </select>
            </div>

            <button className="btn" type="submit" data-testid="login-submit-button" disabled={isLoading}>
              {isLoading ? 'Verifying…' : 'Enter console'}
              <svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.7" aria-hidden="true">
                <path d="M2 8h11M9 4l4 4-4 4" />
              </svg>
            </button>

            {import.meta.env.DEV && (
              <button
                className="btn ghost"
                type="button"
                data-testid="login-demo-credentials-btn"
                onClick={fillDemo}
              >
                Fill demo credentials
              </button>
            )}
          </form>

          <p className="help">
            Signing in records your email and the time, for access auditing. Trouble signing in? Ask
            your SOC lead to add your account, or{' '}
            <a href="https://github.com/TENET-DEV-AI/TENET-AI/issues" target="_blank" rel="noreferrer">
              report a problem
            </a>
            .
          </p>

          <div className="foot">
            <span>console 0.2.0 · MIT</span>
            <span>{googleEnabled ? 'google identity' : 'local accounts'}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
