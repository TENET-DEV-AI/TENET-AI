interface TopBarProps {
  title: string;
  sub: string;
  syncedLabel: string;
  loading: boolean;
  onRefresh: () => void;
  onShortcuts: () => void;
  onMenu: () => void;
}

export function TopBar({ title, sub, syncedLabel, loading, onRefresh, onShortcuts, onMenu }: TopBarProps) {
  return (
    <header className="topbar">
      <button className="burger" onClick={onMenu} aria-label="Open navigation">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M4 7h16M4 12h16M4 17h16" />
        </svg>
      </button>
      <h1>{title}</h1>
      <span className="sep" />
      <span className="sub">{sub}</span>
      <div className="right">
        <span className="pill">
          <i className={loading ? 'busy' : ''} />
          live
        </span>
        <span className="sub">{syncedLabel}</span>
        <button className="iconbtn" onClick={onShortcuts} aria-label="Keyboard shortcuts" title="Shortcuts (?)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <rect x="2" y="6" width="20" height="12" rx="2" />
            <path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M8 14h8" />
          </svg>
        </button>
        <button
          className="iconbtn"
          onClick={onRefresh}
          aria-label="Refresh data"
          title="Refresh"
          disabled={loading}
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            className={loading ? 'spin' : ''}
          >
            <path d="M21 12a9 9 0 1 1-3-6.7L21 8" />
            <path d="M21 3v5h-5" />
          </svg>
        </button>
      </div>
    </header>
  );
}
