import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  Shield, Activity, CheckCircle, XCircle, BarChart3,
  RefreshCw, Search, Lock, Cpu, Menu, X, Save, Filter, Download
} from 'lucide-react';
import axios from 'axios';
import './index.css';
import './App.css';

import type { SecurityEvent, Stats, FilterState, ChartFilterAction, TimeRange } from './types/security';
import { MOCK_EVENTS } from './data/mockEvents';
import { DAYS_OF_WEEK, threatTypeLabel } from './constants/charts';
import {
  aggregateThreatTypes,
  aggregateSeverity,
  aggregateAttackVectors,
  aggregateDetectionsOverTime,
  aggregateHeatmap,
  withThreatType,
  parseEventTimestamp,
} from './utils/chartAggregations';
import {
  ThreatTypeBreakdownChart,
  DetectionsOverTimeChart,
  TopAttackVectorsChart,
  SeverityDistributionChart,
  DetectionHeatmap,
} from './components/charts';
import {
  buildExportFilename,
  buildReportHtml,
  downloadText,
  printReport,
  toCsv,
  toJson,
  type ExportFormat,
} from './utils/exportEvents';

interface Preset {
  name: string;
  filters: FilterState;
}

const EMPTY_FILTERS: FilterState = {
  search: '',
  verdict: '',
  status: '',
  sourceIP: '',
  detectionType: '',
  threatType: '',
  dateFrom: '',
  dateTo: '',
  dayOfWeek: '',
  hourFrom: '',
  hourTo: '',
};

const API_BASE = 'http://localhost:8000';
const API_KEY = import.meta.env.VITE_API_KEY || '';
const PRESETS_KEY = 'tenet_filter_presets';

function filtersToURL(f: FilterState): void {
  const params = new URLSearchParams();
  (Object.keys(f) as (keyof FilterState)[]).forEach(k => {
    if (f[k]) params.set(k, f[k]);
  });
  const newURL = params.toString()
    ? `${window.location.pathname}?${params.toString()}`
    : window.location.pathname;
  window.history.replaceState(null, '', newURL);
}

function filtersFromURL(): FilterState {
  const params = new URLSearchParams(window.location.search);
  return {
    search: params.get('search') || '',
    verdict: params.get('verdict') || '',
    status: params.get('status') || '',
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

function hasActiveFilters(f: FilterState): boolean {
  return Object.values(f).some(v => v !== '');
}

const parseLocalDayStart = (date: string) => {
  const [y, m, d] = date.split('-').map(Number);
  return new Date(y, m - 1, d, 0, 0, 0, 0).getTime();
};

const parseLocalDayEnd = (date: string) => {
  const [y, m, d] = date.split('-').map(Number);
  return new Date(y, m - 1, d, 23, 59, 59, 999).getTime();
};

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'events' | 'system'>('dashboard');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [events, setEvents] = useState<SecurityEvent[]>(MOCK_EVENTS);
  const [stats, setStats] = useState<Stats>({
    total_events: 124,
    blocked_count: 12,
    threat_distribution: { malicious: 12, suspicious: 45, benign: 67 }
  });
  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState({ ingest: false, analyzer: false });
  const [filters, setFilters] = useState<FilterState>(filtersFromURL);
  const [timeRange, setTimeRange] = useState<TimeRange>('daily');
  const [presets, setPresets] = useState<Preset[]>(() => {
    try {
      const parsed = JSON.parse(localStorage.getItem(PRESETS_KEY) || '[]');
      return Array.isArray(parsed) ? parsed : [];
    } catch { return []; }
  });
  const [presetName, setPresetName] = useState('');
  const [showPresetInput, setShowPresetInput] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [feedback, setFeedback] = useState<Record<string, string>>({});
  const searchRef = useRef<HTMLInputElement>(null);

  const updateFilter = useCallback((key: keyof FilterState, value: string) => {
    setFilters(prev => {
      const next = { ...prev, [key]: value };
      filtersToURL(next);
      return next;
    });
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
    setActiveTab('events');
    setShowFilters(true);
  }, []);

  const clearAllFilters = useCallback(() => {
    setFilters(EMPTY_FILTERS);
    filtersToURL(EMPTY_FILTERS);
  }, []);

  const savePreset = useCallback(() => {
    if (!presetName.trim()) return;
    const next = [...presets, { name: presetName.trim(), filters }];
    setPresets(next);
    try { localStorage.setItem(PRESETS_KEY, JSON.stringify(next)); } catch { /* storage unavailable */ }
    setPresetName('');
    setShowPresetInput(false);
  }, [presetName, presets, filters]);

  const applyPreset = useCallback((preset: Preset) => {
    setFilters(preset.filters);
    filtersToURL(preset.filters);
  }, []);

  const deletePreset = useCallback((index: number) => {
    const next = presets.filter((_, i) => i !== index);
    setPresets(next);
    try { localStorage.setItem(PRESETS_KEY, JSON.stringify(next)); } catch { /* storage unavailable */ }
  }, [presets]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (activeTab !== 'events') return;
      const tag = (e.target as HTMLElement).tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA') return;
      if (e.key === '/' || (e.ctrlKey && e.key === 'k')) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [activeTab]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const config = { headers: { 'X-API-Key': API_KEY } };

      const [eventsRes, statsRes, ingestHealth, analyzerHealth] = await Promise.allSettled([
        axios.get(`${API_BASE}/v1/events`, config),
        axios.get(`${API_BASE}/v1/stats`, config),
        axios.get(`${API_BASE}/health`),
        axios.get(`http://localhost:8100/health`)
      ]);
      if (eventsRes.status === 'fulfilled') {
        setEvents(Array.isArray(eventsRes.value.data.events) ? eventsRes.value.data.events : []);
      }
      if (statsRes.status === 'fulfilled') setStats(prev => statsRes.value.data || prev);
      setHealth({
        ingest: ingestHealth.status === 'fulfilled' && ingestHealth.value.status === 200,
        analyzer: analyzerHealth.status === 'fulfilled' && analyzerHealth.value.status === 200
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const filteredEvents = events.filter(ev => {
    if (filters.search) {
      const q = filters.search.toLowerCase();
      if (
        !ev.prompt?.toLowerCase().includes(q) &&
        !ev.source_id?.toLowerCase().includes(q) &&
        !ev.event_id?.toLowerCase().includes(q)
      ) return false;
    }
    if (filters.verdict && ev.verdict !== filters.verdict) return false;
    if (filters.status) {
      if (filters.status === 'blocked' && !ev.blocked) return false;
      if (filters.status === 'allowed' && ev.blocked) return false;
    }
    if (filters.sourceIP && !ev.source_id?.toLowerCase().includes(filters.sourceIP.toLowerCase())) return false;
    if (filters.detectionType && ev.source_type !== filters.detectionType) return false;
    if (filters.threatType) {
      const resolved = withThreatType([ev])[0].resolvedThreatType;
      if (resolved !== filters.threatType) return false;
    }

    const eventTs = parseEventTimestamp(ev.timestamp);
    if (!eventTs) return false;
    if (filters.dateFrom && eventTs.getTime() < parseLocalDayStart(filters.dateFrom)) return false;
    if (filters.dateTo && eventTs.getTime() > parseLocalDayEnd(filters.dateTo)) return false;
    if (filters.dayOfWeek !== '' && eventTs.getDay() !== Number(filters.dayOfWeek)) return false;
    if (filters.hourFrom !== '') {
      const hour = eventTs.getHours();
      const from = Number(filters.hourFrom);
      const to = filters.hourTo !== '' ? Number(filters.hourTo) : from;
      if (hour < from || hour > to) return false;
    }
    return true;
  });

  const threatTypeData = useMemo(() => aggregateThreatTypes(events), [events]);
  const severityData = useMemo(() => aggregateSeverity(events), [events]);
  const attackVectorData = useMemo(() => aggregateAttackVectors(events), [events]);
  const timeSeriesData = useMemo(() => aggregateDetectionsOverTime(events, timeRange), [events, timeRange]);
  const heatmapData = useMemo(() => aggregateHeatmap(events), [events]);

  const activeChips = Object.entries(filters).filter(([, v]) => v !== '');

  const chipLabel = (key: string, value: string) => {
    const labels: Record<string, string> = {
      search: `Search: ${value}`,
      verdict: `Severity: ${value}`,
      status: `Status: ${value}`,
      sourceIP: `Source: ${value}`,
      detectionType: `Type: ${value}`,
      threatType: `Threat: ${threatTypeLabel(value)}`,
      dateFrom: `From: ${value}`,
      dateTo: `To: ${value}`,
      dayOfWeek: `Day: ${DAYS_OF_WEEK[Number(value)] ?? value}`,
      hourFrom: `Hour from: ${value.padStart(2, '0')}:00`,
      hourTo: `Hour to: ${value.padStart(2, '0')}:00`,
    };
    return labels[key] || `${key}: ${value}`;
  };

  const avgRiskScore = events.length > 0
    ? (events.reduce((sum, e) => sum + e.risk_score, 0) / events.length).toFixed(2)
    : '0.00';

  const detectionTypes = [...new Set(events.map(e => e.source_type))];
  const handleFeedback = (
  eventId: string,
  type: "false_positive" | "false_negative"
) => {
  setFeedback(prev => ({
    ...prev,
    [eventId]: type
  }));

};

  const handleExport = (format: ExportFormat) => {
    // same rows as the table, with the resolved threat type filled in
    const rows = withThreatType(filteredEvents).map(({ resolvedThreatType, ...ev }) => ({
      ...ev,
      threat_type: resolvedThreatType,
    }));
    const filename = buildExportFilename(format, filters, rows);
    if (format === 'csv') downloadText(filename, toCsv(rows), 'text/csv');
    else if (format === 'json') downloadText(filename, toJson(rows), 'application/json');
    else printReport(buildReportHtml(rows, filename.replace(/\.pdf$/, ''), activeChips.map(([k, v]) => chipLabel(k, v))));
  };

  const threatTypes = [...new Set(withThreatType(events).map(e => e.resolvedThreatType))];

  return (
    <div className="app-container">
      {isSidebarOpen && <div className="sidebar-overlay" onClick={() => setIsSidebarOpen(false)} />}

      <aside className={`sidebar ${isSidebarOpen ? 'open' : ''}`}>
        <div className="logo-container">
          <div className="logo">
            <Shield className="theme-icon" />
            <span>TENET AI</span>
          </div>
          <button className="mobile-close-btn" onClick={() => setIsSidebarOpen(false)} aria-label="Close sidebar">
            <X size={20} />
          </button>
        </div>
        <nav>
          <button className={activeTab === 'dashboard' ? 'active' : ''} onClick={() => { setActiveTab('dashboard'); setIsSidebarOpen(false); }}>
            <BarChart3 size={20} /> <span>Dashboard</span>
          </button>
          <button className={activeTab === 'events' ? 'active' : ''} onClick={() => { setActiveTab('events'); setIsSidebarOpen(false); }}>
            <Activity size={20} /> <span>Alert Feed</span>
          </button>
          <button className={activeTab === 'system' ? 'active' : ''} onClick={() => { setActiveTab('system'); setIsSidebarOpen(false); }}>
            <Cpu size={20} /> <span>System Health</span>
          </button>
        </nav>
        <div className="user-info">
          <Lock size={16} /> <span>Admin Mode</span>
        </div>
      </aside>

      <main className="main-content">
        <header>
          <div className="header-title-container">
            <button className="mobile-menu-btn" onClick={() => setIsSidebarOpen(true)} aria-label="Open sidebar">
              <Menu size={24} />
            </button>
            <h1>{activeTab.charAt(0).toUpperCase() + activeTab.slice(1)}</h1>
          </div>
          <button className="refresh-btn" onClick={fetchData} disabled={loading} aria-label="Refresh data">
            <RefreshCw size={18} className={loading ? 'spinning' : ''} />
          </button>
        </header>

        {activeTab === 'dashboard' && (
          <div className="dashboard-grid">
            <div className="stat-cards">
              <div className="stat-card">
                <h3>Total Interceptions</h3>
                <div className="value">{stats.total_events}</div>
              </div>
              <div className="stat-card danger">
                <h3>Threats Blocked</h3>
                <div className="value">{stats.blocked_count}</div>
              </div>
              <div className="stat-card warning">
                <h3>Average Risk Score</h3>
                <div className="value">{avgRiskScore}</div>
              </div>
            </div>

            <p className="dashboard-hint">Click any chart segment to filter the Alert Feed. Charts use color-blind safe palettes.</p>

            <div className="charts-row">
              <ThreatTypeBreakdownChart data={threatTypeData} onFilter={applyChartFilter} />
              <SeverityDistributionChart data={severityData} onFilter={applyChartFilter} />
            </div>

            <div className="charts-row">
              <DetectionsOverTimeChart
                data={timeSeriesData}
                range={timeRange}
                onRangeChange={setTimeRange}
                onFilter={applyChartFilter}
              />
              <TopAttackVectorsChart data={attackVectorData} onFilter={applyChartFilter} />
            </div>

            <div className="charts-row charts-row-full">
              <DetectionHeatmap cells={heatmapData} onFilter={applyChartFilter} />
            </div>
          </div>
        )}

        {activeTab === 'events' && (
          <div className="events-list">
            <div className="filter-bar">
              <Search size={18} />
              <input
                ref={searchRef}
                type="text"
                placeholder="Search events, prompts, or sources... (Press / or Ctrl+K)"
                value={filters.search}
                onChange={e => updateFilter('search', e.target.value)}
                aria-label="Search events"
              />
              <button className="filter-toggle-btn" onClick={() => setShowFilters(p => !p)} aria-label={showFilters ? 'Hide filters' : 'Show filters'}>
                <Filter size={16} />
                {hasActiveFilters(filters) && <span className="filter-dot" />}
              </button>
              {hasActiveFilters(filters) && (
                <button className="clear-all-btn" onClick={clearAllFilters}>Clear all</button>
              )}
            </div>

            <div className="export-bar">
              <span className="export-count">{filteredEvents.length} event{filteredEvents.length === 1 ? '' : 's'}</span>
              <button onClick={() => handleExport('csv')} disabled={filteredEvents.length === 0} aria-label="Export filtered events as CSV">
                <Download size={14} /> CSV
              </button>
              <button onClick={() => handleExport('json')} disabled={filteredEvents.length === 0} aria-label="Export filtered events as JSON">
                <Download size={14} /> JSON
              </button>
              <button onClick={() => handleExport('pdf')} disabled={filteredEvents.length === 0} aria-label="Export filtered events as PDF report" title="Opens the print dialog, choose Save as PDF">
                <Download size={14} /> PDF
              </button>
            </div>

            {showFilters && (
              <div className="advanced-filters">
                <div className="filters-grid">
                  <select value={filters.verdict} onChange={e => updateFilter('verdict', e.target.value)} aria-label="Filter by severity">
                    <option value="">All Severities</option>
                    <option value="malicious">Malicious</option>
                    <option value="suspicious">Suspicious</option>
                    <option value="benign">Benign</option>
                  </select>
                  <select value={filters.threatType} onChange={e => updateFilter('threatType', e.target.value)} aria-label="Filter by threat type">
                    <option value="">All Threat Types</option>
                    {threatTypes.map(t => <option key={t} value={t}>{threatTypeLabel(t)}</option>)}
                  </select>
                  <select value={filters.status} onChange={e => updateFilter('status', e.target.value)} aria-label="Filter by status">
                    <option value="">All Statuses</option>
                    <option value="blocked">Blocked</option>
                    <option value="allowed">Allowed</option>
                  </select>
                  <select value={filters.detectionType} onChange={e => updateFilter('detectionType', e.target.value)} aria-label="Filter by detection type">
                    <option value="">All Types</option>
                    {detectionTypes.map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                  <input
                    type="text"
                    placeholder="Source IP / ID"
                    value={filters.sourceIP}
                    onChange={e => updateFilter('sourceIP', e.target.value)}
                    aria-label="Filter by source"
                  />
                  <input
                    type="date"
                    value={filters.dateFrom}
                    onChange={e => updateFilter('dateFrom', e.target.value)}
                    title="Date from"
                    aria-label="Date from"
                  />
                  <input
                    type="date"
                    value={filters.dateTo}
                    onChange={e => updateFilter('dateTo', e.target.value)}
                    title="Date to"
                    aria-label="Date to"
                  />
                </div>

                <div className="preset-row">
                  {presets.map((p, i) => (
                    <div key={i} className="preset-chip">
                      <button onClick={() => applyPreset(p)}>{p.name}</button>
                      <button className="preset-delete" aria-label="Delete preset" onClick={() => deletePreset(i)}><X size={12} /></button>
                    </div>
                  ))}
                  {showPresetInput ? (
                    <div className="preset-save-row">
                      <input
                        type="text"
                        placeholder="Preset name"
                        value={presetName}
                        onChange={e => setPresetName(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && savePreset()}
                        autoFocus
                      />
                        <button aria-label="Confirm preset name" onClick={savePreset}><CheckCircle size={14} /></button>
                        <button aria-label="Cancel" onClick={() => setShowPresetInput(false)}><X size={14} /></button>
                    </div>
                  ) : (
                    <button className="save-preset-btn" onClick={() => setShowPresetInput(true)}>
                      <Save size={14} /> Save preset
                    </button>
                  )}
                </div>
              </div>
            )}

            {activeChips.length > 0 && (
              <div className="active-chips">
                {activeChips.map(([key, value]) => (
                  <span key={key} className="chip">
                    {chipLabel(key, value)}
                    <button onClick={() => updateFilter(key as keyof FilterState, '')} aria-label={`Remove ${chipLabel(key, value)} filter`}><X size={11} /></button>
                  </span>
                ))}
              </div>
            )}

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Verdict</th>
                    <th>Threat Type</th>
                    <th>Timestamp</th>
                    <th>Source</th>
                    <th>Prompt</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.length === 0 ? (
                    <tr><td colSpan={6} className="no-results">No events match the current filters.</td></tr>
                  ) : (
                    filteredEvents.map(event => {
                      const threat = withThreatType([event])[0].resolvedThreatType;
                      return (
                        <tr key={event.event_id}>
                          <td><span className={`verdict-badge ${event.verdict}`}>{event.verdict}</span></td>
                          <td><span className="threat-type-badge">{threatTypeLabel(threat)}</span></td>
                          <td>{new Date(event.timestamp).toLocaleString()}</td>
                          <td>{event.source_id}</td>
                          <td className="prompt-cell">
                            "{event.prompt ? (event.prompt.length > 60 ? `${event.prompt.substring(0, 60)}...` : event.prompt) : 'N/A'}"
                          </td>
                          <td>
  <div
  style={{
    display: "flex",
    flexDirection: "column",
    gap: "8px",
  }}
>
    <span>{event.blocked ? "🚫 Blocked" : "✅ Allowed"}</span>
    {feedback[event.event_id] && (
  <span style={{ color: "`#22c55e`", fontSize: "12px" }}>
    ✓ Marked as {feedback[event.event_id] === "false_positive" ? "False Positive" : "False Negative"}
  </span>
)}

   <button
  style={{
    padding: "8px",
    borderRadius: "6px",
    cursor: "pointer",
    backgroundColor: "#2563eb",
    color: "white",
    border: "none",
    fontWeight: "bold"
  }}
  onClick={() => handleFeedback(event.event_id, "false_positive")}
>
  Mark as False Positive
</button>
<button
  style={{
    padding: "8px",
    borderRadius: "6px",
    cursor: "pointer",
    backgroundColor: "#dc2626",
    color: "white",
    border: "none",
    fontWeight: "bold"
  }}
  onClick={() => handleFeedback(event.event_id, "false_negative")}
>
  Mark as False Negative
</button>
  </div>
</td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'system' && (
          <div className="system-health">
            <div className="health-card">
              <h3>Ingest Service</h3>
              <div className="status">
                {health.ingest ? <span className="online"><CheckCircle size={16} /> Online</span> : <span className="offline"><XCircle size={16} /> Offline</span>}
                <p>Port: 8000 | Version: 0.1.0</p>
              </div>
            </div>
            <div className="health-card">
              <h3>Analyzer Service</h3>
              <div className="status">
                {health.analyzer ? <span className="online"><CheckCircle size={16} /> Online</span> : <span className="offline"><XCircle size={16} /> Offline</span>}
                <p>Port: 8100 | ML Model: PromptDetector v0.1</p>
              </div>
            </div>
            <div className="health-card">
              <h3>Message Queue</h3>
              <div className="status">
                <span className="online"><CheckCircle size={16} /> Redis Connected</span>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
