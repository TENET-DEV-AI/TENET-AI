import React, { useState } from 'react';
import { Shield, Lock, AlertCircle, ArrowRight, UserCheck } from 'lucide-react';

interface LoginViewProps {
  onLoginSuccess: (user: { email: string; role: string; token: string }) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('analyst@tenet.ai');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('Senior SOC Responder');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!username.trim()) {
      setError('Analyst email or ID is required.');
      return;
    }

    if (!password) {
      setError('Password is required.');
      return;
    }

    // Validation: Match valid analyst/admin demo accounts
    const VALID_ACCOUNTS: Record<string, string> = {
      'analyst@tenet.ai': 'password123',
      'admin@tenet.ai': 'admin123',
    };
    if (VALID_ACCOUNTS[username.trim()] !== password) {
      setError('Invalid credentials. Use analyst@tenet.ai / password123 or click "Fill Demo Credentials".');
      return;
    }

    setIsLoading(true);
    setTimeout(() => {
      setIsLoading(false);
      const token = `tenet_token_${Date.now()}`;
      onLoginSuccess({
        email: username.trim(),
        role,
        token,
      });
    }, 250);
  };

  const handleQuickFill = () => {
    setUsername('analyst@tenet.ai');
    setPassword('password123');
    setRole('Senior SOC Responder');
    setError(null);
  };

  return (
    <div className="login-container" data-testid="soc-login-page">
      <div className="login-card">
        <div className="login-brand">
          <div className="login-logo-icon">
            <Shield size={32} />
          </div>
          <h2>TENET AI Console</h2>
          <span className="login-badge">SOC PORTAL · RESTRICTED</span>
        </div>

        <p className="login-subtext">
          Zero-Trust Security Operations Center. Authenticate with your analyst credentials to inspect intercepted LLM events.
        </p>

        {error && (
          <div className="login-error-alert" role="alert" data-testid="login-error-message">
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="login-form" data-testid="login-form">
          <div className="form-group">
            <label htmlFor="login-username">Analyst Email / ID</label>
            <input
              id="login-username"
              data-testid="login-username-input"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="analyst@tenet.ai"
              autoComplete="username"
            />
          </div>

          <div className="form-group">
            <label htmlFor="login-password">Analyst Password</label>
            <input
              id="login-password"
              data-testid="login-password-input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              autoComplete="current-password"
            />
          </div>

          <div className="form-group">
            <label htmlFor="login-role">Operational Role</label>
            <select
              id="login-role"
              data-testid="login-role-select"
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              <option value="Tier-1 Analyst">Tier-1 SOC Analyst</option>
              <option value="Senior SOC Responder">Senior SOC Responder</option>
              <option value="Lead SecOps Admin">Lead SecOps Admin</option>
            </select>
          </div>

          <button
            type="submit"
            className="login-submit-btn"
            data-testid="login-submit-button"
            disabled={isLoading}
          >
            {isLoading ? (
              <span>Authenticating...</span>
            ) : (
              <>
                <Lock size={16} />
                <span>Sign In to SOC Console</span>
                <ArrowRight size={16} />
              </>
            )}
          </button>
        </form>

        <div className="login-footer-actions">
          <button
            type="button"
            className="quick-fill-btn"
            data-testid="login-demo-credentials-btn"
            onClick={handleQuickFill}
          >
            <UserCheck size={14} />
            <span>Fill Demo Credentials</span>
          </button>
        </div>

        <div className="login-compliance-notice">
          <span>🔒 TENET SOC Security Console · Authorized Personnel Only</span>
        </div>
      </div>
    </div>
  );
};
