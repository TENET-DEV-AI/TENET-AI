import { useState } from 'react';
import type { SecurityEvent } from '../types/security';
import { threatTypeLabel } from '../constants/charts';
import { agoLabel, ageMinutes, dateTimeLabel, severityOf, slaRemainingLabel, verdictTone, workflowStatus } from '../utils/alerts';

interface DetailPaneProps {
  event: SecurityEvent | null;
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

type Tab = 'overview' | 'evidence' | 'trace' | 'rule' | 'activity';

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'trace', label: 'Trace' },
  { id: 'rule', label: 'Rule' },
  { id: 'activity', label: 'Activity' },
];

export function DetailPane({
  event,
  onAcknowledge,
  onResolve,
  onFeedback,
  onOpenModal,
  onPrevious,
  onNext,
  resolving,
  onStartResolve,
  onCancelResolve,
}: DetailPaneProps) {
  const [tab, setTab] = useState<Tab>('overview');
  const [note, setNote] = useState('');

  if (!event) {
    return (
      <div className="detail">
        <div className="dhead">
          <div className="t">
            <h2>Select an alert</h2>
            <div className="sub">j / k move through the queue</div>
          </div>
        </div>
        <div className="dbody">
          <div className="empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
              <path d="M4 6h16M4 12h16M4 18h10" />
            </svg>
            <span>Nothing selected. Pick a row to read the evidence.</span>
          </div>
        </div>
      </div>
    );
  }

  const sev = severityOf(event);
  const status = workflowStatus(event);
  const typeLabel = threatTypeLabel(event.threat_type ?? event.verdict);

  return (
    <div className="detail">
      <div className="dhead">
        <div className="t">
          <h2>{typeLabel}</h2>
          <div className="sub">
            {event.source_type} · {event.source_id} · {event.model} · {agoLabel(ageMinutes(event))} ago
          </div>
        </div>
        <div className="nav">
          <button className="iconbtn" onClick={onPrevious} aria-label="Previous alert (k)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M15 5l-7 7 7 7" />
            </svg>
          </button>
          <button className="iconbtn" onClick={onNext} aria-label="Next alert (j)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 5l7 7-7 7" />
            </svg>
          </button>
        </div>
      </div>

      <div className="tabs" role="tablist" aria-label="Alert detail">
        {TABS.map(item => (
          <button
            key={item.id}
            className={`tab${tab === item.id ? ' on' : ''}`}
            role="tab"
            aria-selected={tab === item.id}
            onClick={() => setTab(item.id)}
          >
            {item.label}
          </button>
        ))}
      </div>

      <div className="dbody">
        {tab === 'overview' && (
          <div className="pane on">
            <div className="sect">
              <span className="lbl">Verdict</span>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
                <span className={`badge t-${verdictTone(event)}`}>
                  {event.blocked ? 'Blocked' : event.verdict === 'malicious' ? 'Flagged' : event.verdict === 'suspicious' ? 'Flagged' : 'Allowed'}
                </span>
                <span className={`badge sev-${sev}`}>{sev}</span>
                <span className={`badge status-${status}`} data-testid={`status-badge-${event.event_id}`}>
                  {status}
                </span>
                <span className="badge">risk {event.risk_score.toFixed(2)}</span>
              </div>
              <dl className="kv">
                <dt>SLA</dt>
                <dd>{slaRemainingLabel(event)}</dd>
                <dt>Threat type</dt>
                <dd>{typeLabel}</dd>
                <dt>Event id</dt>
                <dd style={{ fontFamily: 'var(--f-mono)', fontSize: 11 }}>{event.event_id}</dd>
                <dt>Captured</dt>
                <dd>{dateTimeLabel(event.timestamp)}</dd>
                <dt>Model</dt>
                <dd>{event.model}</dd>
              </dl>
            </div>
            <div className="sect">
              <span className="lbl">Prompt</span>
              <div className="promptbox">{event.prompt || 'No prompt recorded for this event.'}</div>
            </div>
          </div>
        )}

        {tab === 'evidence' && (
          <div className="pane on">
            <div className="sect">
              <span className="lbl">Captured prompt</span>
              <div className="promptbox">{event.prompt || 'No prompt recorded for this event.'}</div>
            </div>
            <div className="sect">
              <span className="lbl">Classifier output</span>
              <dl className="kv">
                <dt>Verdict</dt>
                <dd>{event.verdict}</dd>
                <dt>Risk score</dt>
                <dd>{event.risk_score.toFixed(2)}</dd>
                <dt>Threat type</dt>
                <dd>{typeLabel}</dd>
                <dt>Enforcement</dt>
                <dd>{event.blocked ? 'request blocked before the model' : 'request forwarded to the model'}</dd>
              </dl>
            </div>
          </div>
        )}

        {tab === 'trace' && (
          <div className="pane on">
            <div className="sect">
              <span className="lbl">Pipeline</span>
              <div className="trace">
                <div className="tstep">
                  <span className="b ok" />
                  <span>Ingest service accepted the request</span>
                  <span className="mono">{event.source_type}</span>
                </div>
                <div className="tstep">
                  <span className="b ok" />
                  <span>Analyzer scored the prompt</span>
                  <span className="mono">risk {event.risk_score.toFixed(2)}</span>
                </div>
                <div className="tstep">
                  <span className={`b ${event.blocked ? 'bad' : 'ok'}`} />
                  <span>{event.blocked ? 'Policy blocked the request' : 'Policy allowed the request'}</span>
                  <span className="mono">{event.verdict}</span>
                </div>
              </div>
              <p className="hint" style={{ marginTop: 10 }}>
                Per-stage latency is reported by the analyzer; this build shows only what the event carries.
              </p>
            </div>
          </div>
        )}

        {tab === 'rule' && (
          <div className="pane on">
            <div className="sect">
              <span className="lbl">Matched detector</span>
              <div className="rulebox">
                <span className="id">prompt-injection-v4</span>
                <span className="tx">
                  <b>{typeLabel}</b>
                  <span className="hint">
                    Classifier rule family that produced this verdict. Editing rules lands with the rule editor.
                  </span>
                </span>
              </div>
            </div>
          </div>
        )}

        {tab === 'activity' && (
          <div className="pane on">
            <div className="sect">
              <span className="lbl">Workflow</span>
              <div className="trace">
                <div className="tstep">
                  <span className="b ok" />
                  <span>Captured</span>
                  <span className="mono">{dateTimeLabel(event.timestamp)}</span>
                </div>
                <div className="tstep">
                  <span className="b ok" />
                  <span>Acknowledged</span>
                  <span className="mono">{event.acknowledged_at ? dateTimeLabel(event.acknowledged_at) : 'not yet'}</span>
                </div>
                <div className="tstep">
                  <span className={`b ${event.resolved_at ? 'ok' : 'warn'}`} />
                  <span>Resolved</span>
                  <span className="mono">{event.resolved_at ? dateTimeLabel(event.resolved_at) : 'not yet'}</span>
                </div>
              </div>
              {event.resolution_note && (
                <p className="hint" style={{ marginTop: 10 }}>
                  Note: {event.resolution_note}
                </p>
              )}
            </div>
          </div>
        )}

        {resolving && (
          <div className="resolvebox">
            <label className="lbl" htmlFor="resolve-note">
              Resolution note
            </label>
            <textarea
              id="resolve-note"
              value={note}
              onChange={e => setNote(e.target.value)}
              placeholder="What did you do about it?"
            />
            <div className="dactions">
              <button
                className="abtn primary"
                onClick={() => {
                  onResolve(event.event_id, note.trim() || 'Resolved by SOC analyst');
                  onCancelResolve();
                  setNote('');
                }}
              >
                Confirm resolve
              </button>
              <button className="abtn" onClick={onCancelResolve}>
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="actions">
        <button
          className="abtn primary"
          onClick={() => onAcknowledge(event.event_id)}
          disabled={status !== 'new'}
        >
          Acknowledge
          <kbd>a</kbd>
        </button>
        <button className="abtn" onClick={onStartResolve} disabled={status === 'resolved'}>
          Resolve
          <kbd>r</kbd>
        </button>
        <button className="abtn" onClick={() => onFeedback(event.event_id, 'false_positive')}>
          False positive
          <kbd>f</kbd>
        </button>
        <span className="sp" />
        <button className="abtn" onClick={() => onOpenModal(event.event_id)}>
          Open investigation
        </button>
      </div>
    </div>
  );
}
