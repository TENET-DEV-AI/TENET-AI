import type { View } from '../App';

interface RailProps {
  view: View;
  openCount: number;
  totalCount: number;
  userEmail: string;
  userName?: string;
  userRole: string;
  mobileOpen: boolean;
  onNavigate: (view: View) => void;
  onLogout: () => void;
  onCloseMobile: () => void;
}

const initials = (email: string, name?: string) => {
  const source = name?.trim() ? name.trim().split(/\s+/) : email.split('@')[0].split(/[._-]/);
  return (
    source
      .slice(0, 2)
      .map(part => part.charAt(0).toUpperCase())
      .join('') || 'SO'
  );
};

export function Rail({
  view,
  openCount,
  totalCount,
  userEmail,
  userName,
  userRole,
  mobileOpen,
  onNavigate,
  onLogout,
  onCloseMobile,
}: RailProps) {
  const go = (next: View) => {
    onNavigate(next);
    onCloseMobile();
  };

  return (
    <aside className={`rail${mobileOpen ? ' on' : ''}`} aria-label="Primary">
      <div className="brand">
        <svg className="mk" viewBox="0 0 100 100" aria-hidden="true">
          <circle cx="50" cy="50" r="42.5" fill="none" stroke="currentColor" strokeWidth="4.5" />
          <path d="M24 26H76V34H54V64H46V34H24Z" fill="currentColor" />
          <path d="M46 66H54V76H46Z" fill="#E1593C" />
        </svg>
        <div>
          <b>TENET AI</b>
          <span>console · 0.2.0</span>
        </div>
      </div>

      <nav className="nav">
        <span className="lbl g">Monitor</span>
        <a
          href="#overview"
          className={view === 'overview' ? 'on' : ''}
          onClick={e => {
            e.preventDefault();
            go('overview');
          }}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M3 13h4l2 6 4-14 2 8h6" />
          </svg>
          Overview
        </a>
        <a
          href="#triage"
          className={view === 'triage' ? 'on' : ''}
          onClick={e => {
            e.preventDefault();
            go('triage');
          }}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M4 6h16M4 12h16M4 18h10" />
          </svg>
          Triage queue
          {openCount > 0 && <span className="n">{openCount}</span>}
        </a>
        <a
          href="#feed"
          className={view === 'feed' ? 'on' : ''}
          onClick={e => {
            e.preventDefault();
            go('feed');
          }}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M12 3v18M5 8l7-5 7 5" />
          </svg>
          Alert feed
          <span className="n">{totalCount}</span>
        </a>
        <a
          href="#health"
          className={view === 'health' ? 'on' : ''}
          onClick={e => {
            e.preventDefault();
            go('health');
          }}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M3 12h4l2-5 3 10 2-5h7" />
          </svg>
          System health
        </a>

        <span className="lbl g">Tune</span>
        <a
          href="#rules"
          className="disabled"
          aria-disabled="true"
          tabIndex={-1}
          onClick={e => e.preventDefault()}
          title="Rule editor — not in this build"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M4 6h16M4 12h16M4 18h16" />
          </svg>
          Rules
        </a>
        <a
          href="#policy"
          className="disabled"
          aria-disabled="true"
          tabIndex={-1}
          onClick={e => e.preventDefault()}
          title="Policy editor — not in this build"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" />
          </svg>
          Policy
        </a>
        <a
          href="#audit"
          className="disabled"
          aria-disabled="true"
          tabIndex={-1}
          onClick={e => e.preventDefault()}
          title="Audit log — not in this build"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M4 4h16v16H4z" />
            <path d="M8 9h8M8 13h5" />
          </svg>
          Audit log
        </a>
      </nav>

      <div className="foot">
        <div className="user">
          <span className="av" title={userName ?? userEmail}>
            {initials(userEmail, userName)}
          </span>
          <div style={{ minWidth: 0 }}>
            <div className="e" data-testid="user-email">
              {userEmail}
            </div>
            <div className="r">{userRole.toLowerCase()}</div>
          </div>
          <button
            className="iconbtn signout"
            onClick={onLogout}
            data-testid="logout-button"
            aria-label="Sign out"
            title="Sign out"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" />
              <path d="M10 17l-5-5 5-5M5 12h11" />
            </svg>
          </button>
        </div>
      </div>
    </aside>
  );
}
