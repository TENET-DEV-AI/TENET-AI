import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import axios from 'axios';

import './styles/console.css';
import './styles/product.css';

import type { ChartFilterAction, FilterState, SecurityEvent, Stats, TimeRange } from './types/security';
import { LoginView, type ConsoleUser } from './components/LoginView';
import { AlertDetailModal } from './components/AlertDetailModal';
import { Rail } from './components/Rail';
import { TopBar } from './components/TopBar';
import { OverviewView } from './components/OverviewView';
import { TriageView, type QueueView } from './components/TriageView';
import { FeedView } from './components/FeedView';
import { HealthView } from './components/HealthView';
import { MOCK_EVENTS } from './data/mockEvents';
import { DAYS_OF_WEEK, threatTypeLabel } from './constants/charts';
import { parseEventTimestamp, withThreatType } from './utils/chartAggregations';
import {
  buildExportFilename,
  buildReportHtml,
  downloadText,
  printReport,
  toCsv,
  toJson,
  type ExportFormat,
} from './utils/exportEvents';
import type { Preset } from './components/FilterPanel';
import { API_BASE, API_KEY } from './config';
import { isOpen, rankForTriage } from './utils/alerts';
import { disableGoogleAutoSelect } from './utils/google';

export type View = 'overview' | 'triage' | 'feed' | 'health';

const EMPTY_FILTERS: FilterState = {
  search: '',
  verdict: '',
  status: '',
  alertStatus: '',
  sourceIP: '',
  detectionType: '',
  threatType: '',
  dateFrom: '',
  dateTo: '',
  dayOfWeek: '',
  hourFrom: '',
  hourTo: '',
};

const PRESETS_KEY = 'tenet_filter_presets';

function filtersToURL(filters: FilterState): void {
  const params = new URLSearchParams();
  (Object.keys(filters) as (keyof FilterState)[]).forEach(key => {
    const value = filters[key];
    if (value) params.set(key, value);
  });
  const next = params.toString()
    ? `${window.location.pathname}?${params.toString()}`
    : window.location.pathname;
  window.history.replaceState(null, '', next);
}

function filtersFromURL(): FilterState {
  const params = new URLSearchParams(window.location.search);
  return {
    search: params.get('search') || '',
    verdict: params.get('verdict') || '',
    status: params.get('status') || '',
    alertStatus: params.get('alertStatus') || '',
    sourceIP: params.get('sourceIP') || '',
    detectionType: params.get('detectionType') || '',
    threatType: params.get('threatType') || '',
    dateFrom: params.get('dateFrom') || '',
    dateTo: params.get('dateTo') || '',
    dayOfWeek: params.get('dayOfWeek') || '',
    hourFrom: params.get('hourFrom') || '',
    hourTo: params.get('hourTo') || '',
  };
}

const parseLocalDayStart = (date: string) => {
  const [y, m, d] = date.split('-').map(Number);
  return new Date(y, m - 1, d, 0, 0, 0, 0).getTime();
};

const parseLocalDayEnd = (date: string) => {
  const [y, m, d] = date.split('-').map(Number);
  return new Date(y, m - 1, d, 23, 59, 59, 999).getTime();
};

const VIEW_TITLES: Record<View, string> = {
  overview: 'Overview',
  triage: 'Triage queue',
  feed: 'Alert feed',
  health: 'System health',
};

export default function App() {
  const [user, setUser] = useState<ConsoleUser | null>(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      if (import.meta.env.DEV && params.get('auth') === 'skip') {
        return { email: 'analyst@tenet.ai', role: 'Senior SOC Responder', token: 'demo' };
      }
      // A Google session is only trusted for this tab: the token expires and the
      // API re-verifies it on every request.
      const stored = localStorage.getItem('tenet_soc_user');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  const [view, setView] = useState<View>('overview');
  const [mobileNav, setMobileNav] = useState(false);
  const [events, setEvents] = useState<SecurityEvent[]>(MOCK_EVENTS);
  const [stats, setStats] = useState<Stats>({
    total_events: 0,
    blocked_count: 0,
    threat_distribution: { malicious: 0, suspicious: 0, benign: 0 },
  });
  const [loading, setLoading] = useState(false);
  const [lastSync, setLastSync] = useState<Date | null>(null);
  const [health, setHealth] = useState({ ingest: false, analyzer: false });
  const [filters, setFilters] = useState<FilterState>(filtersFromURL);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [timeRange, setTimeRange] = useState<TimeRange>('daily');
  const [queueView, setQueueView] = useState<QueueView>('open');
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [modalId, setModalId] = useState<string | null>(null);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [feedback, setFeedback] = useState<Record<string, string>>({});
  const [presets, setPresets] = useState<Preset[]>(() => {
    try {
      const parsed = JSON.parse(localStorage.getItem(PRESETS_KEY) || '[]');
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  });
  const searchRef = useRef<HTMLInputElement>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const config = { headers: { 'X-API-Key': API_KEY } };
      const [eventsRes, statsRes, ingestHealth, analyzerHealth] = await Promise.allSettled([
        axios.get(`${API_BASE}/v1/events`, config),
        axios.get(`${API_BASE}/v1/stats`, config),
        axios.get(`${API_BASE}/health`),
        axios.get('http://localhost:8100/health'),
      ]);

      if (eventsRes.status === 'fulfilled') {
        const fetched = Array.isArray(eventsRes.value.data.events) ? eventsRes.value.data.events : [];
        setEvents(prev => {
          const previous = new Map(prev.map(event => [event.event_id, event]));
          return fetched.map((event: SecurityEvent) => {
            const existing = previous.get(event.event_id);
            if (existing?.alert_status && !event.alert_status) {
              return {
                ...event,
                alert_status: existing.alert_status,
                acknowledged_at: existing.acknowledged_at,
                resolved_at: existing.resolved_at,
                resolution_note: existing.resolution_note,
              };
            }
            return event;
          });
        });
      }
      if (statsRes.status === 'fulfilled') setStats(prev => statsRes.value.data || prev);
      setHealth({
        ingest: ingestHealth.status === 'fulfilled' && ingestHealth.value.status === 200,
        analyzer: analyzerHealth.status === 'fulfilled' && analyzerHealth.value.status === 200,
      });
      setLastSync(new Date());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchData();
    const interval = setInterval(() => void fetchData(), 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  /* ---------------------------------------------------------------- actions */
  const handleAcknowledge = useCallback((eventId: string) => {
    const timestamp = new Date().toISOString();
    setEvents(prev =>
      prev.map(event =>
        event.event_id === eventId
          ? { ...event, alert_status: 'acknowledged', acknowledged_at: timestamp }
          : event,
      ),
    );
  }, []);

  const handleResolve = useCallback((eventId: string, note?: string) => {
    const timestamp = new Date().toISOString();
    const resolutionNote = note || 'Resolved by SOC analyst';
    setEvents(prev =>
      prev.map(event =>
        event.event_id === eventId
          ? {
              ...event,
              alert_status: 'resolved',
              resolved_at: timestamp,
              resolution_note: resolutionNote,
            }
          : event,
      ),
    );
  }, []);

  const handleFeedback = useCallback((eventId: string, type: 'false_positive' | 'false_negative') => {
    setFeedback(prev => ({ ...prev, [eventId]: type }));
  }, []);

  const handleLogout = useCallback(() => {
    disableGoogleAutoSelect();
    try {
      localStorage.removeItem('tenet_soc_user');
      const url = new URL(window.location.href);
      if (url.searchParams.has('auth')) {
        url.searchParams.delete('auth');
        window.history.replaceState({}, '', url.pathname + (url.search ? url.search : ''));
      }
    } catch {
      /* storage unavailable */
    }
    setUser(null);
  }, []);

  const updateFilter = useCallback((key: keyof FilterState, value: string) => {
    setFilters(prev => {
      const next = { ...prev, [key]: value };
      filtersToURL(next);
      return next;
    });
  }, []);

  const clearFilters = useCallback(() => {
    setFilters(EMPTY_FILTERS);
    filtersToURL(EMPTY_FILTERS);
  }, []);

  const applyChartFilter = useCallback((action: ChartFilterAction) => {
    setFilters(prev => {
      const next: FilterState = {
        ...prev,
        ...(action.verdict !== undefined && { verdict: action.verdict }),
        ...(action.threatType !== undefined && { threatType: action.threatType }),
        ...(action.dateFrom !== undefined && { dateFrom: action.dateFrom }),
        ...(action.dateTo !== undefined && { dateTo: action.dateTo }),
        ...(action.dayOfWeek !== undefined && { dayOfWeek: action.dayOfWeek }),
        ...(action.hourFrom !== undefined && { hourFrom: action.hourFrom }),
        ...(action.hourTo !== undefined && { hourTo: action.hourTo }),
      };
      filtersToURL(next);
      return next;
    });
    setView('triage');
    setFiltersOpen(true);
  }, []);

  const savePreset = useCallback(
    (name: string) => {
      const next = [...presets, { name, filters }];
      setPresets(next);
      try {
        localStorage.setItem(PRESETS_KEY, JSON.stringify(next));
      } catch {
        /* storage unavailable */
      }
    },
    [presets, filters],
  );

  const applyPreset = useCallback((preset: Preset) => {
    setFilters(preset.filters);
    filtersToURL(preset.filters);
  }, []);

  const deletePreset = useCallback((index: number) => {
    setPresets(prev => {
      const next = prev.filter((_, i) => i !== index);
      try {
        localStorage.setItem(PRESETS_KEY, JSON.stringify(next));
      } catch {
        /* storage unavailable */
      }
      return next;
    });
  }, []);

  /* ---------------------------------------------------------------- derived */
  const filteredEvents = useMemo(() => {
    return events.filter(event => {
      if (filters.search) {
        const needle = filters.search.toLowerCase();
        const haystack = `${event.prompt ?? ''} ${event.source_id ?? ''} ${event.event_id ?? ''}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      if (filters.verdict && event.verdict !== filters.verdict) return false;
      if (filters.status === 'blocked' && !event.blocked) return false;
      if (filters.status === 'allowed' && event.blocked) return false;
      if (filters.sourceIP && !event.source_id?.toLowerCase().includes(filters.sourceIP.toLowerCase())) return false;
      if (filters.detectionType && event.source_type !== filters.detectionType) return false;
      if (filters.threatType && withThreatType([event])[0].resolvedThreatType !== filters.threatType) return false;
      if (filters.alertStatus && (event.alert_status || 'new') !== filters.alertStatus) return false;

      const timestamp = parseEventTimestamp(event.timestamp);
      if (!timestamp) return false;
      if (filters.dateFrom && timestamp.getTime() < parseLocalDayStart(filters.dateFrom)) return false;
      if (filters.dateTo && timestamp.getTime() > parseLocalDayEnd(filters.dateTo)) return false;
      if (filters.dayOfWeek !== '' && timestamp.getDay() !== Number(filters.dayOfWeek)) return false;
      if (filters.hourFrom !== '') {
        const hour = timestamp.getHours();
        const from = Number(filters.hourFrom);
        const to = filters.hourTo !== '' ? Number(filters.hourTo) : from;
        if (hour < from || hour > to) return false;
      }
      return true;
    });
  }, [events, filters]);

  const ranked = useMemo(() => rankForTriage(filteredEvents), [filteredEvents]);
  const openCount = useMemo(() => events.filter(isOpen).length, [events]);
  const selected = useMemo(
    () => filteredEvents.find(event => event.event_id === selectedId) ?? null,
    [filteredEvents, selectedId],
  );
  const modalEvent = useMemo(
    () => events.find(event => event.event_id === modalId) ?? null,
    [events, modalId],
  );

  const facets = useMemo(
    () => ({
      detectionTypes: [...new Set(events.map(event => event.source_type))],
      threatTypes: [...new Set(withThreatType(events).map(event => event.resolvedThreatType))],
    }),
    [events],
  );

  const activeChips = Object.entries(filters).filter(([, value]) => value !== '') as [string, string][];

  const chipLabel = (key: string, value: string) => {
    const labels: Record<string, string> = {
      search: `Search: ${value}`,
      verdict: `Verdict: ${value}`,
      status: `Enforcement: ${value}`,
      alertStatus: `Workflow: ${value}`,
      sourceIP: `Source: ${value}`,
      detectionType: `Type: ${value}`,
      threatType: `Threat: ${threatTypeLabel(value)}`,
      dateFrom: `From: ${value}`,
      dateTo: `To: ${value}`,
      dayOfWeek: `Day: ${DAYS_OF_WEEK[Number(value)] ?? value}`,
      hourFrom: `From hour: ${value.padStart(2, '0')}:00`,
      hourTo: `To hour: ${value.padStart(2, '0')}:00`,
    };
    return labels[key] || `${key}: ${value}`;
  };

  const handleExport = useCallback(
    (format: ExportFormat) => {
      const rows = withThreatType(filteredEvents).map(({ resolvedThreatType, ...event }) => ({
        ...event,
        threat_type: resolvedThreatType,
      }));
      const filename = buildExportFilename(format, filters, rows);
      if (format === 'csv') downloadText(filename, toCsv(rows), 'text/csv');
      else if (format === 'json') downloadText(filename, toJson(rows), 'application/json');
      else
        printReport(
          buildReportHtml(
            rows,
            filename.replace(/\.pdf$/, ''),
            activeChips.map(([key, value]) => chipLabel(key, value)),
          ),
        );
    },
    [filteredEvents, filters, activeChips],
  );

  const selectRelative = useCallback(
    (delta: number) => {
      if (ranked.length === 0) return;
      const current = ranked.findIndex(event => event.event_id === selectedId);
      const next = current === -1 ? 0 : (current + delta + ranked.length) % ranked.length;
      setSelectedId(ranked[next].event_id);
    },
    [ranked, selectedId],
  );

  const openAlert = useCallback((eventId: string) => {
    setSelectedId(eventId);
    setView('triage');
    setMobileNav(false);
  }, []);

  /* ---------------------------------------------------------------- keyboard */
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const tag = (event.target as HTMLElement | null)?.tagName;
      const typing = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
      if (event.key === 'Escape') {
        setShortcutsOpen(false);
        setModalId(null);
        setMobileNav(false);
        return;
      }
      if (typing) return;
      if (event.key === '?' || (event.key === '/' && event.shiftKey)) {
        event.preventDefault();
        setShortcutsOpen(prev => !prev);
        return;
      }
      if (event.key === '/' || (event.ctrlKey && event.key === 'k')) {
        event.preventDefault();
        setView('triage');
        setTimeout(() => searchRef.current?.focus(), 0);
        return;
      }
      if (event.key === 'g') {
        event.preventDefault();
        setView(prev => (prev === 'overview' ? 'triage' : 'overview'));
        return;
      }
      if (view !== 'triage') return;
      if (event.key === 'j') selectRelative(1);
      if (event.key === 'k') selectRelative(-1);
      if (selected && event.key === 'a') handleAcknowledge(selected.event_id);
      if (selected && event.key === 'f') handleFeedback(selected.event_id, 'false_positive');
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [view, selected, selectRelative, handleAcknowledge, handleFeedback]);

  if (!user) {
    return (
      <LoginView
        onLoginSuccess={loggedUser => {
          try {
            localStorage.setItem('tenet_soc_user', JSON.stringify(loggedUser));
          } catch {
            /* storage unavailable */
          }
          setUser(loggedUser);
        }}
      />
    );
  }

  const syncedLabel = lastSync
    ? `synced ${Math.max(0, Math.round((Date.now() - lastSync.getTime()) / 1000))}s ago`
    : 'not synced';

  return (
    <div className="app" data-testid="soc-dashboard-app">
      {mobileNav && <div className="scrim on" onClick={() => setMobileNav(false)} />}
      <Rail
        view={view}
        openCount={openCount}
        totalCount={events.length}
        userEmail={user.email}
        userName={user.name}
        userRole={user.role}
        mobileOpen={mobileNav}
        onNavigate={setView}
        onLogout={handleLogout}
        onCloseMobile={() => setMobileNav(false)}
      />

      <div className="main">
        <TopBar
          title={VIEW_TITLES[view]}
          sub={`${events.length} events · ${openCount} open`}
          syncedLabel={syncedLabel}
          loading={loading}
          onRefresh={() => void fetchData()}
          onShortcuts={() => setShortcutsOpen(true)}
          onMenu={() => setMobileNav(true)}
        />

        <div className="scroll">
          {view === 'overview' && (
            <OverviewView
              events={events}
              stats={stats}
              health={health}
              timeRange={timeRange}
              onRangeChange={setTimeRange}
              onFilter={applyChartFilter}
              onOpenAlert={openAlert}
            />
          )}

          {view === 'triage' && (
            <TriageView
              events={filteredEvents}
              facets={facets}
              filters={filters}
              filtersOpen={filtersOpen}
              onToggleFilters={() => setFiltersOpen(prev => !prev)}
              onUpdateFilter={updateFilter}
              onClearFilters={clearFilters}
              activeChips={activeChips}
              chipLabel={chipLabel}
              presets={presets}
              onSavePreset={savePreset}
              onApplyPreset={applyPreset}
              onDeletePreset={deletePreset}
              onExport={handleExport}
              queueView={queueView}
              onQueueView={setQueueView}
              query={query}
              onQuery={setQuery}
              searchRef={searchRef}
              selected={selected}
              onSelect={setSelectedId}
              feedback={feedback}
              onAcknowledge={handleAcknowledge}
              onResolve={handleResolve}
              onFeedback={handleFeedback}
              onOpenModal={setModalId}
              onPrevious={() => selectRelative(-1)}
              onNext={() => selectRelative(1)}
            />
          )}

          {view === 'feed' && (
            <FeedView events={events} onOpenModal={setModalId} onSelect={openAlert} />
          )}

          {view === 'health' && <HealthView health={health} stats={stats} events={events} />}
        </div>
      </div>

      {modalEvent && (
        <AlertDetailModal
          event={modalEvent}
          onClose={() => setModalId(null)}
          onAcknowledge={handleAcknowledge}
          onResolve={handleResolve}
        />
      )}

      {shortcutsOpen && (
        <div className="modal on" onClick={() => setShortcutsOpen(false)} role="presentation">
          <div className="card" onClick={event => event.stopPropagation()} role="dialog" aria-label="Keyboard shortcuts">
            <h3>Keyboard</h3>
            <div className="keys">
              {[
                ['j', 'Next alert'],
                ['k', 'Previous alert'],
                ['a', 'Acknowledge'],
                ['f', 'False positive'],
                ['/', 'Filter the queue'],
                ['g', 'Toggle overview / triage'],
                ['?', 'This panel'],
                ['esc', 'Close'],
              ].map(([key, label]) => (
                <span key={key} style={{ display: 'contents' }}>
                  <kbd>{key}</kbd>
                  <span>{label}</span>
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
