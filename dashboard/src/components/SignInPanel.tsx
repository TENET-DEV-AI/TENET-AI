import { useEffect, useState } from 'react';
import { fetchSignInStats, type SignInStats } from '../utils/signinLog';

/**
 * Who has opened the console. Reads the server-side sign-in log; if the API
 * cannot answer (older build, no Redis, logging switched off) the panel says so
 * rather than showing a confident zero.
 */
export function SignInPanel() {
  const [stats, setStats] = useState<SignInStats | null>(null);
  const [state, setState] = useState<'loading' | 'ready' | 'unavailable'>('loading');

  useEffect(() => {
    let cancelled = false;
    fetchSignInStats(7).then(result => {
      if (cancelled) return;
      setStats(result);
      setState(result ? 'ready' : 'unavailable');
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const days = stats?.by_day ?? [];
  const peak = Math.max(1, ...days.map(day => day.count));

  return (
    <section className="panel">
      <div className="hd">
        <h2>Sign-ins</h2>
        <span className="lbl">last 7 days</span>
      </div>
      <div className="bd">
        {state === 'loading' && <p className="hint">Reading the sign-in log…</p>}

        {state === 'unavailable' && (
          <p className="hint">
            Sign-in log unavailable — the API did not answer, or logging is switched off
            (<code>SIGNIN_LOG_ENABLED=false</code>).
          </p>
        )}

        {state === 'ready' && stats && (
          <>
            <div className="signin-total">
              <b>{stats.total.toLocaleString()}</b>
              <span>sign-ins · {stats.unique_accounts} accounts</span>
            </div>

            <div className="signin-bars" aria-hidden="true">
              {days.map(day => (
                <span key={day.date} title={`${day.date}: ${day.count}`}>
                  <i style={{ height: `${Math.max(3, (day.count / peak) * 100)}%` }} />
                </span>
              ))}
            </div>

            <dl className="kv" style={{ marginTop: 14 }}>
              <dt>Google</dt>
              <dd>{stats.by_provider.google ?? 0}</dd>
              <dt>Password</dt>
              <dd>{stats.by_provider.password ?? 0}</dd>
              <dt>Last sign-in</dt>
              <dd>
                {stats.last_signin
                  ? `${stats.last_signin.email} · ${new Date(stats.last_signin.at).toLocaleString('en-GB', {
                      day: '2-digit',
                      month: 'short',
                      hour: '2-digit',
                      minute: '2-digit',
                    })}`
                  : 'none recorded'}
              </dd>
            </dl>
          </>
        )}
      </div>
    </section>
  );
}
