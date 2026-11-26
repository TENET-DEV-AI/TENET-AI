import { useMemo } from 'react';
import type { ChartFilterAction, SecurityEvent, Stats, TimeRange } from '../types/security';
import type { NamedCount, TimeBucket } from '../utils/chartAggregations';
import {
  aggregateAttackVectors,
  aggregateDetectionsOverTime,
  aggregateHeatmap,
  aggregateSeverity,
  aggregateThreatTypes,
  withThreatType,
} from '../utils/chartAggregations';
import { threatTypeLabel } from '../constants/charts';
import {
  DetectionHeatmap,
  DetectionsOverTimeChart,
  SeverityDistributionChart,
  TopAttackVectorsChart,
} from './charts';
import { HealthPanel } from './HealthPanel';
import {
  agoLabel,
  ageMinutes,
  isOpen,
  isOverSla,
  rankForTriage,
  severityOf,
  slaRemainingLabel,
  clockLabel,
} from '../utils/alerts';

interface OverviewViewProps {
  events: SecurityEvent[];
  stats: Stats;
  health: { ingest: boolean; analyzer: boolean };
  timeRange: TimeRange;
  onRangeChange: (range: TimeRange) => void;
  onFilter: (action: ChartFilterAction) => void;
  onOpenAlert: (eventId: string) => void;
}

/** Turns a series of counts into a small inline sparkline path. */
function sparkPath(values: number[], width = 76, height = 26): string {
  if (values.length === 0) return `M1 ${height / 2}H${width - 5}`;
  const max = Math.max(...values);
  const min = Math.min(...values);
  // A flat series should read as a steady line through the middle, not as a
  // hairline pinned to the card edge.
  if (max === min) {
    const mid = height / 2;
    return `M1 ${mid}H${width - 5}`;
  }
  const span = max - min;
  return values
    .map((value, i) => {
      const x = 1 + (i * (width - 6)) / Math.max(values.length - 1, 1);
      const y = height - 3 - ((value - min) / span) * (height - 6);
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(' ');
}

function Sparkline({ values, stroke }: { values: number[]; stroke: string }) {
  return (
    <svg className="spark" viewBox="0 0 76 26" fill="none" stroke={stroke} strokeWidth="1.4" aria-hidden="true">
      <path d={sparkPath(values)} />
    </svg>
  );
}

export function OverviewView({
  events,
  stats,
  health,
  timeRange,
  onRangeChange,
  onFilter,
  onOpenAlert,
}: OverviewViewProps) {
  const timeSeries = useMemo(() => aggregateDetectionsOverTime(events, timeRange), [events, timeRange]);
  const threatTypes: NamedCount[] = useMemo(() => aggregateThreatTypes(events), [events]);
  const severity = useMemo(() => aggregateSeverity(events), [events]);
  const vectors = useMemo(() => aggregateAttackVectors(events), [events]);
  const heatmap = useMemo(() => aggregateHeatmap(events), [events]);

  const ranked = useMemo(() => rankForTriage(events), [events]);
  const openCount = ranked.length;
  const overSla = ranked.filter(isOverSla);
  const blockedCount = events.filter(e => e.blocked).length;
  const inBucket = (event: SecurityEvent, bucket: TimeBucket) => {
    const ts = new Date(event.timestamp).getTime();
    const from = new Date(bucket.dateFrom).getTime();
    const to = new Date(bucket.dateTo).getTime();
    return ts >= from && ts <= to;
  };
  const totalSeries = timeSeries.map((bucket: TimeBucket) => events.filter(e => inBucket(e, bucket)).length);
  const blockedSeries = timeSeries.map(
    (bucket: TimeBucket) => events.filter(e => e.blocked && inBucket(e, bucket)).length,
  );
  const openSeries = timeSeries.map(
    (bucket: TimeBucket) => events.filter(e => isOpen(e) && inBucket(e, bucket)).length,
  );
  const slaSeries = timeSeries.map(
    (bucket: TimeBucket) => events.filter(e => isOverSla(e) && inBucket(e, bucket)).length,
  );

  const topSource = useMemo(() => {
    const counts = new Map<string, number>();
    events.forEach(e => counts.set(e.source_type, (counts.get(e.source_type) ?? 0) + 1));
    const [name, count] = [...counts.entries()].sort((a, b) => b[1] - a[1])[0] ?? ['—', 0];
    return { name, share: events.length ? Math.round((count / events.length) * 100) : 0 };
  }, [events]);

  const models = useMemo(() => [...new Set(events.map(e => e.model))].slice(0, 3), [events]);
  const recent = useMemo(
    () =>
      [...events]
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, 7),
    [events],
  );
  const resolvedThreats = useMemo(() => withThreatType(events), [events]);

  const kpis = [
    {
      label: 'Total interceptions',
      value: stats.total_events || events.length,
      detail: `${events.length} in buffer`,
      series: totalSeries,
      tone: '',
      stroke: 'rgba(239,233,221,.5)',
    },
    {
      label: 'Threats blocked',
      value: stats.blocked_count || blockedCount,
      detail: `${events.length ? Math.round((blockedCount / events.length) * 100) : 0}% of traffic`,
      series: blockedSeries,
      tone: 'ember',
      stroke: '#E1593C',
    },
    {
      label: 'Awaiting triage',
      value: openCount,
      detail: openCount ? `oldest ${agoLabel(ageMinutes(ranked[0]))} in queue` : 'queue clear',
      series: openSeries,
      tone: 'amber',
      stroke: '#D9A441',
    },
    {
      label: 'Past SLA',
      value: overSla.length,
      detail: `of ${openCount} open`,
      series: slaSeries,
      tone: '',
      stroke: 'rgba(239,233,221,.5)',
    },
  ];

  return (
    <section className="view on" aria-label="Overview">
      <div className="stats">
        {kpis.map(kpi => (
          <div className={`stat ${kpi.tone}`} key={kpi.label}>
            <div className="k">{kpi.label}</div>
            <div className="v">{kpi.value.toLocaleString()}</div>
            <div className="d">{kpi.detail}</div>
            <Sparkline values={kpi.series} stroke={kpi.stroke} />
          </div>
        ))}
      </div>

      {ranked.length > 0 && (
        <div className="attention" aria-label="Needs attention">
          {ranked.slice(0, 3).map(event => {
            const sev = severityOf(event);
            return (
              <button className="att" key={event.event_id} onClick={() => onOpenAlert(event.event_id)}>
                <span className={`sev sev-${sev}`} aria-hidden="true" />
                <span className="tx">
                  <span className="t1">
                    {threatTypeLabel(event.threat_type ?? event.verdict)} · {event.source_type}
                  </span>
                  <span className="t2">
                    {sev} · {slaRemainingLabel(event)} · {event.source_id}
                  </span>
                </span>
                <span className="go">triage</span>
              </button>
            );
          })}
        </div>
      )}

      <div className="chart-grid">
        <DetectionsOverTimeChart
          data={timeSeries}
          range={timeRange}
          onRangeChange={onRangeChange}
          onFilter={onFilter}
        />
        <section className="panel">
          <div className="hd">
            <h2>Attack distribution</h2>
            <span className="lbl">{events.length} events</span>
          </div>
          <div className="bd">
            <div className="dist">
              {threatTypes.length === 0 && <p className="hint">No events in the buffer.</p>}
              {threatTypes.slice(0, 5).map(item => {
                const share = events.length ? Math.round((item.value / events.length) * 100) : 0;
                return (
                  <div className="row" key={item.name}>
                    <span className="nm">{threatTypeLabel(item.name)}</span>
                    <span className="bar">
                      <span className="fill" style={{ width: `${share}%` }} />
                    </span>
                    <span className="pc">{share}%</span>
                  </div>
                );
              })}
            </div>
            <dl className="kv" style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--line)' }}>
              <dt>Top source</dt>
              <dd>
                {topSource.name} · {topSource.share}%
              </dd>
              <dt>Models seen</dt>
              <dd>{models.length ? models.join(' · ') : '—'}</dd>
              <dt>Detector</dt>
              <dd>prompt-injection-v4 · {resolvedThreats.length} scored</dd>
            </dl>
          </div>
        </section>
      </div>

      <div className="grid2">
        <section className="panel">
          <div className="hd">
            <h2>Alert feed</h2>
            <span className="lbl">streaming</span>
          </div>
          <div className="feed">
            {recent.length === 0 && <p className="hint" style={{ padding: 14 }}>Waiting for events…</p>}
            {recent.map(event => (
              <button className="frow" key={event.event_id} onClick={() => onOpenAlert(event.event_id)}>
                <span className="tm">{clockLabel(event.timestamp)}</span>
                <span className={event.blocked ? 'b b-blocked' : 'b b-allowed'}>
                  {event.blocked ? 'blocked' : 'allowed'}
                </span>
                <span className="msg">
                  {threatTypeLabel(event.threat_type ?? event.verdict)} · {event.source_type}
                </span>
                <span className="risk">{event.risk_score.toFixed(2)}</span>
              </button>
            ))}
          </div>
        </section>
        <section className="panel">
          <div className="hd">
            <h2>System health</h2>
            <span className="lbl">3 services</span>
          </div>
          <div className="bd">
            <HealthPanel
              ingest={health.ingest}
              analyzer={health.analyzer}
              queueDepth={null}
              eventsCount={events.length}
              blockedCount={blockedCount}
              compact
            />
          </div>
        </section>
      </div>

      <div className="chart-grid">
        <SeverityDistributionChart data={severity} onFilter={onFilter} />
        <TopAttackVectorsChart data={vectors} onFilter={onFilter} />
      </div>

      <div className="chart-grid single">
        <DetectionHeatmap cells={heatmap} onFilter={onFilter} />
      </div>
    </section>
  );
}
