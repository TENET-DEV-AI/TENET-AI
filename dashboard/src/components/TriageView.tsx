import type { RefObject } from 'react';
import type { FilterState, SecurityEvent } from '../types/security';
import { threatTypeLabel } from '../constants/charts';
import {
  agoLabel,
  ageMinutes,
  isOpen,
  isOverSla,
  severityOf,
  slaRemainingLabel,
  visibleQueue,
  workflowStatus,
} from '../utils/alerts';
import type { ExportFormat } from '../utils/exportEvents';
import { FilterPanel, type Preset } from './FilterPanel';
import { DetailPane } from './DetailPane';

export type QueueView = 'open' | 'sla' | 'critical' | 'all';

interface TriageViewProps {
  events: SecurityEvent[];
  facets: { detectionTypes: string[]; threatTypes: string[] };
  filters: FilterState;
  filtersOpen: boolean;
  onToggleFilters: () => void;
  onUpdateFilter: (key: keyof FilterState, value: string) => void;
  onClearFilters: () => void;
  activeChips: [string, string][];
  chipLabel: (key: string, value: string) => string;
  presets: Preset[];
  onSavePreset: (name: string) => void;
  onApplyPreset: (preset: Preset) => void;
  onDeletePreset: (index: number) => void;
  onExport: (format: ExportFormat) => void;
  queueView: QueueView;
  onQueueView: (view: QueueView) => void;
  query: string;
  onQuery: (value: string) => void;
  searchRef: RefObject<HTMLInputElement | null>;
  selected: SecurityEvent | null;
  onSelect: (eventId: string) => void;
  feedback: Record<string, string>;
  onAcknowledge: (eventId: string) => void;
  onResolve: (eventId: string, note: string) => void;
  onFeedback: (eventId: string, type: 'false_positive' | 'false_negative') => void;
  onOpenModal: (eventId: string) => void;
  onPrevious: () => void;
  onNext: () => void;
  resolving: boolean;
  onStartResolve: () => void;
  onCancelResolve: () => void;
}

export function TriageView(props: TriageViewProps) {
  const {
    events,
    facets,
    filters,
    filtersOpen,
    onToggleFilters,
    onUpdateFilter,
    onClearFilters,
    activeChips,
    chipLabel,
    presets,
    onSavePreset,
    onApplyPreset,
    onDeletePreset,
    onExport,
    queueView,
    onQueueView,
    query,
    onQuery,
    searchRef,
    selected,
    onSelect,
    feedback,
    onAcknowledge,
    onResolve,
    onFeedback,
    onOpenModal,
    onPrevious,
    onNext,
    resolving,
    onStartResolve,
    onCancelResolve,
  } = props;

  const visible = visibleQueue(events, queueView, query);

  const openTotal = events.filter(isOpen).length;
  const views: { id: QueueView; label: string }[] = [
    { id: 'open', label: 'Open' },
    { id: 'sla', label: 'Over SLA' },
    { id: 'critical', label: 'Critical' },
    { id: 'all', label: 'All' },
  ];

  return (
    <section className="view on" aria-label="Triage queue">
      <div className="triage">
        <div className="queue">
          <div className="qhead">
            <div className="qrow">
              <span className="qtitle">
                Triage queue
                <span className="n">{openTotal} open</span>
              </span>
              <div className="views" id="views" style={{ marginLeft: 'auto' }}>
                {views.map(item => (
                  <button
                    key={item.id}
                    className={`vchip${queueView === item.id ? ' on' : ''}`}
                    aria-pressed={queueView === item.id}
                    onClick={() => onQueueView(item.id)}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>
            <div className="qrow">
              <div className="qsearch" style={{ flex: 1 }}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 13, height: 13, color: 'var(--faint)' }}>
                  <circle cx="11" cy="11" r="7" />
                  <path d="M20 20l-4-4" />
                </svg>
                <input
                  ref={searchRef}
                  value={query}
                  onChange={e => onQuery(e.target.value)}
                  placeholder="Filter queue…"
                  aria-label="Filter queue"
                />
                <kbd>/</kbd>
              </div>
              <button className={`abtn${filtersOpen ? ' primary' : ''}`} onClick={onToggleFilters} aria-expanded={filtersOpen}>
                Filters{activeChips.length > 0 ? ` · ${activeChips.length}` : ''}
              </button>
            </div>
          </div>

          {filtersOpen && (
            <FilterPanel
              filters={filters}
              detectionTypes={facets.detectionTypes}
              threatTypes={facets.threatTypes}
              presets={presets}
              onUpdate={onUpdateFilter}
              onClear={onClearFilters}
              onSavePreset={onSavePreset}
              onApplyPreset={onApplyPreset}
              onDeletePreset={onDeletePreset}
              onExport={onExport}
              resultCount={events.length}
            />
          )}

          {activeChips.length > 0 && (
            <div className="chips">
              {activeChips.map(([key, value]) => (
                <span className="chip" key={key}>
                  {chipLabel(key, value)}
                  <button onClick={() => onUpdateFilter(key as keyof FilterState, '')} aria-label={`Remove ${key} filter`}>
                    ×
                  </button>
                </span>
              ))}
              <button className="abtn" onClick={onClearFilters} style={{ marginLeft: 'auto' }}>
                Clear
              </button>
            </div>
          )}

          <div className="qlist">
            {visible.length === 0 && <div className="qempty">Nothing in this view.</div>}
            {visible.map(event => {
              const sev = severityOf(event);
              const status = workflowStatus(event);
              const over = isOverSla(event);
              const note = feedback[event.event_id];
              return (
                <div
                  key={event.event_id}
                  className={`qitem${selected?.event_id === event.event_id ? ' sel' : ''}${status === 'resolved' ? ' done' : ''}`}
                  data-event-id={event.event_id}
                  onClick={() => onSelect(event.event_id)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={e => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelect(event.event_id);
                    }
                  }}
                >
                  <span className={`sev sev-${sev}`} aria-hidden="true" />
                  <span className={`chk${selected?.event_id === event.event_id ? ' on' : ''}`} aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5">
                      <path d="M20 6 9 17l-5-5" />
                    </svg>
                  </span>
                  <span className="body">
                    <span className="ttl">
                      {event.threat_type ? threatTypeLabel(event.threat_type) : 'Normal query'} · {event.source_type}
                    </span>
                    <span className="meta">
                      <span className={`badge status-${status}`} data-testid={`status-badge-${event.event_id}`}>
                        {status}
                      </span>
                      <span>{event.model}</span>
                      <span>{event.source_id}</span>
                      <span>risk {event.risk_score.toFixed(2)}</span>
                    </span>
                    <span className="qacts">
                      <button
                        className="mini"
                        data-testid={`ack-alert-btn-${event.event_id}`}
                        onClick={e => {
                          e.stopPropagation();
                          onAcknowledge(event.event_id);
                        }}
                        disabled={status !== 'new'}
                      >
                        Ack
                      </button>
                      <button
                        className="mini"
                        data-testid={`view-alert-btn-${event.event_id}`}
                        onClick={e => {
                          e.stopPropagation();
                          onOpenModal(event.event_id);
                        }}
                      >
                        Open
                      </button>
                      <button
                        className={`mini${note ? ' on' : ''}`}
                        data-testid={`feedback-fp-${event.event_id}`}
                        onClick={e => {
                          e.stopPropagation();
                          onFeedback(event.event_id, 'false_positive');
                        }}
                      >
                        FP
                      </button>
                      {note && <span className="fb">Marked as False Positive</span>}
                    </span>
                  </span>
                  <span className="right">
                    <b>{agoLabel(ageMinutes(event))}</b>
                    <span className={`sla${over ? ' over' : ''}`}>{slaRemainingLabel(event)}</span>
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        <DetailPane
          key={selected?.event_id ?? 'empty'}
          event={selected}
          onAcknowledge={onAcknowledge}
          onResolve={onResolve}
          onFeedback={onFeedback}
          onOpenModal={onOpenModal}
          onPrevious={onPrevious}
          onNext={onNext}
          resolving={resolving}
          onStartResolve={onStartResolve}
          onCancelResolve={onCancelResolve}
        />
      </div>
    </section>
  );
}
