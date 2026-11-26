import type { SecurityEvent, Stats } from '../types/security';
import { HealthPanel } from './HealthPanel';

interface HealthViewProps {
  health: { ingest: boolean; analyzer: boolean };
  stats: Stats;
  events: SecurityEvent[];
}

export function HealthView({ health, stats, events }: HealthViewProps) {
  const blocked = events.filter(e => e.blocked).length;
  const models = [...new Set(events.map(e => e.model))];
  const sources = [...new Set(events.map(e => e.source_type))];

  return (
    <section className="view on" aria-label="System health">
      <div className="view-head">
        <h2>System health</h2>
        <span className="lbl">{health.ingest && health.analyzer ? 'all services reachable' : 'degraded'}</span>
      </div>
      <div className="grid2">
        <section className="panel">
          <div className="hd">
            <h2>Services</h2>
            <span className="lbl">polled every 10s</span>
          </div>
          <div className="bd">
            <HealthPanel
              ingest={health.ingest}
              analyzer={health.analyzer}
              queueDepth={null}
              eventsCount={events.length}
              blockedCount={blocked}
            />
          </div>
        </section>
        <section className="panel">
          <div className="hd">
            <h2>Pipeline facts</h2>
            <span className="lbl">from the event buffer</span>
          </div>
          <div className="bd">
            <dl className="kv">
              <dt>Total events</dt>
              <dd>{stats.total_events.toLocaleString()}</dd>
              <dt>Blocked</dt>
              <dd>{stats.blocked_count.toLocaleString()}</dd>
              <dt>Malicious</dt>
              <dd>{stats.threat_distribution.malicious.toLocaleString()}</dd>
              <dt>Suspicious</dt>
              <dd>{stats.threat_distribution.suspicious.toLocaleString()}</dd>
              <dt>Benign</dt>
              <dd>{stats.threat_distribution.benign.toLocaleString()}</dd>
              <dt>Models seen</dt>
              <dd>{models.length ? models.join(' · ') : '—'}</dd>
              <dt>Sources</dt>
              <dd>{sources.length ? sources.join(' · ') : '—'}</dd>
              <dt>Detector</dt>
              <dd>prompt-injection-v4</dd>
            </dl>
          </div>
        </section>
      </div>
    </section>
  );
}
