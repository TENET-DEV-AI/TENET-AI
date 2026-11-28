import type { SecurityEvent, AlertWorkflowStatus } from '../types/security';

/** Severity buckets the console triages on, derived from verdict + risk score. */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** Minutes an alert may sit open before it breaches its SLA. */
export const SLA_MINUTES: Record<Severity, number> = {
  critical: 15,
  high: 60,
  medium: 240,
  low: 1440,
};

export function severityOf(event: SecurityEvent): Severity {
  if (event.verdict === 'malicious' && event.blocked && event.risk_score >= 0.85) return 'critical';
  if (event.blocked || event.risk_score >= 0.7) return 'high';
  if (event.verdict === 'suspicious' || event.risk_score >= 0.5) return 'medium';
  return 'low';
}

/** Badge tone for a verdict. Unblocked malicious traffic is still a threat. */
export function verdictTone(event: SecurityEvent): 'blocked' | 'flagged' | 'allowed' {
  if (event.blocked) return 'blocked';
  if (event.verdict === 'malicious' || event.verdict === 'suspicious') return 'flagged';
  return 'allowed';
}

export function workflowStatus(event: SecurityEvent): AlertWorkflowStatus {
  return event.alert_status ?? 'new';
}

/**
 * An open *alert*. Benign traffic is not an alert — it belongs in the feed, not
 * in the triage queue.
 */
export function isOpen(event: SecurityEvent): boolean {
  if (workflowStatus(event) === 'resolved') return false;
  return event.blocked || event.verdict !== 'benign';
}

/** Time since capture, live — what an analyst means by "how old is this". */
export function captureAgeMinutes(event: SecurityEvent): number {
  const ts = new Date(event.timestamp).getTime();
  if (Number.isNaN(ts)) return 0;
  return Math.max(0, Math.round((Date.now() - ts) / 60000));
}

/** Age that stops at resolution — the SLA clock, not the wall clock. */
export function ageMinutes(event: SecurityEvent): number {
  const ts = new Date(event.timestamp).getTime();
  if (Number.isNaN(ts)) return 0;
  // A resolved alert stops ageing: the clock should not keep running on it.
  const closed = event.resolved_at ? new Date(event.resolved_at).getTime() : null;
  const end = closed && !Number.isNaN(closed) ? closed : Date.now();
  return Math.max(0, Math.round((end - ts) / 60000));
}

export function isOverSla(event: SecurityEvent): boolean {
  if (!isOpen(event)) return false;
  const age = ageMinutes(event);
  return age > SLA_MINUTES[severityOf(event)];
}

export function slaRemainingLabel(event: SecurityEvent): string {
  const sev = severityOf(event);
  const remaining = SLA_MINUTES[sev] - ageMinutes(event);
  if (remaining >= 0) return `${agoLabel(remaining)} left`;
  return `${agoLabel(Math.abs(remaining))} past SLA`;
}

export function agoLabel(minutes: number): string {
  if (minutes < 1) return 'now';
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours < 24) return mins ? `${hours}h ${mins}m` : `${hours}h`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}

export function clockLabel(timestamp: string): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function dateTimeLabel(timestamp: string): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('en-GB', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/** Open alerts, worst SLA first — the triage strip and the queue both use it. */
export function rankForTriage(events: SecurityEvent[]): SecurityEvent[] {
  return [...events]
    .filter(isOpen)
    .sort((a, b) => {
      const bySeverity = SEVERITY_RANK[severityOf(a)] - SEVERITY_RANK[severityOf(b)];
      if (bySeverity !== 0) return bySeverity;
      return ageMinutes(b) - ageMinutes(a);
    });
}

/** The rows an analyst can actually see: queue view + free-text filter, worst first. */
export function visibleQueue(
  events: SecurityEvent[],
  view: 'open' | 'sla' | 'critical' | 'all',
  query: string,
): SecurityEvent[] {
  const needle = query.trim().toLowerCase();
  return [...events]
    .filter(event => {
      // Every view holds alerts only: benign traffic belongs to the feed.
      const isAlert = event.blocked || event.verdict !== 'benign';
      if (!isAlert) return false;
      if (view === 'open' && !isOpen(event)) return false;
      if (view === 'sla' && !isOverSla(event)) return false;
      if (view === 'critical' && severityOf(event) !== 'critical') return false;
      if (!needle) return true;
      return `${event.prompt} ${event.source_id} ${event.source_type} ${event.event_id}`
        .toLowerCase()
        .includes(needle);
    })
    .sort((a, b) => {
      const bySeverity = SEVERITY_RANK[severityOf(a)] - SEVERITY_RANK[severityOf(b)];
      return bySeverity !== 0 ? bySeverity : ageMinutes(b) - ageMinutes(a);
    });
}
