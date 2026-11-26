import type { SecurityEvent } from '../types/security';
import { threatTypeLabel } from '../constants/charts';
import { clockLabel, dateTimeLabel, workflowStatus } from '../utils/alerts';

interface FeedViewProps {
  events: SecurityEvent[];
  onOpenModal: (eventId: string) => void;
  onSelect: (eventId: string) => void;
}

export function FeedView({ events, onOpenModal, onSelect }: FeedViewProps) {
  const rows = [...events]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 200);

  return (
    <section className="view on" aria-label="Alert feed">
      <div className="view-head">
        <h2>Alert feed</h2>
        <span className="lbl">{rows.length} most recent</span>
      </div>
      <section className="panel">
        <div className="hd">
          <h2>Streaming events</h2>
          <span className="lbl">newest first</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="feedtable">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Decision</th>
                <th scope="col">Threat</th>
                <th scope="col">Source</th>
                <th scope="col">Model</th>
                <th scope="col">Risk</th>
                <th scope="col">Workflow</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={8} className="mono">
                    No events yet.
                  </td>
                </tr>
              )}
              {rows.map(event => {
                const status = workflowStatus(event);
                return (
                  <tr key={event.event_id}>
                    <td className="mono" title={dateTimeLabel(event.timestamp)}>
                      {clockLabel(event.timestamp)}
                    </td>
                    <td>
                      <span className={`badge t-${event.blocked ? 'blocked' : event.verdict === 'suspicious' ? 'flagged' : 'allowed'}`}>
                        {event.blocked ? 'blocked' : event.verdict === 'suspicious' ? 'flagged' : 'allowed'}
                      </span>
                    </td>
                    <td>{threatTypeLabel(event.threat_type ?? event.verdict)}</td>
                    <td className="mono">
                      {event.source_type} · {event.source_id}
                    </td>
                    <td className="mono">{event.model}</td>
                    <td className="mono">{event.risk_score.toFixed(2)}</td>
                    <td>
                      <span className={`badge status-${status}`} data-testid={`status-badge-${event.event_id}`}>
                        {status}
                      </span>
                    </td>
                    <td>
                      <span style={{ display: 'flex', gap: 5 }}>
                        <button className="mini abtn" onClick={() => onSelect(event.event_id)}>
                          Triage
                        </button>
                        <button
                          className="mini abtn"
                          data-testid={`view-alert-btn-${event.event_id}`}
                          onClick={() => onOpenModal(event.event_id)}
                        >
                          Open
                        </button>
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
      <p className="hint" style={{ marginTop: 10 }}>
        The raw stream, newest first. Triage opens the same alert in the queue; Open shows the investigation view.
      </p>
    </section>
  );
}
