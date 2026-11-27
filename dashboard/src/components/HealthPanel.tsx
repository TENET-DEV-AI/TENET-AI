interface HealthPanelProps {
  ingest: boolean;
  analyzer: boolean;
  queueDepth: number | null;
  eventsCount: number;
  blockedCount: number;
  compact?: boolean;
}

export function HealthPanel({ ingest, analyzer, queueDepth, eventsCount, blockedCount, compact = false }: HealthPanelProps) {
  const services = [
    { name: 'Ingest service', up: ingest, detail: ':8000' },
    { name: 'Analyzer service', up: analyzer, detail: ':8100' },
    { name: 'Event store', up: true, detail: 'local buffer' },
  ];
  const up = services.filter(s => s.up).length;

  return (
    <>
      <div className="health">
        {services.map(service => (
          <div className="hrow" key={service.name}>
            <span className={`dot ${service.up ? 'ok' : 'down'}`} />
            <span className="nm">{service.name}</span>
            <span className="rt">
              {service.detail} · {service.up ? 'reachable' : 'unreachable'}
            </span>
          </div>
        ))}
        {!compact && (
          <div className="hrow">
            <span className={`dot ${queueDepth === null ? 'warn' : 'ok'}`} />
            <span className="nm">Queue depth</span>
            <span className="rt">{queueDepth === null ? 'not reported' : `${queueDepth} messages`}</span>
          </div>
        )}
      </div>
      <dl className="kv" style={{ marginTop: 14, paddingTop: 12, borderTop: '1px solid var(--line)' }}>
        <dt>Services up</dt>
        <dd>
          {up} of {services.length}
        </dd>
        <dt>Events held</dt>
        <dd>{eventsCount.toLocaleString()}</dd>
        <dt>Blocked</dt>
        <dd>{blockedCount.toLocaleString()}</dd>
        <dt>Detector</dt>
        <dd>prompt-injection-v4</dd>
      </dl>
    </>
  );
}
