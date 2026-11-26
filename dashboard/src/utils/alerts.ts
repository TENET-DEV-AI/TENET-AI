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

export function workflowStatus(event: SecurityEvent): AlertWorkflowStatus {
  return event.alert_status ?? 'new';
}

export function isOpen(event: SecurityEvent): boolean {
  return workflowStatus(event) !== 'resolved';
}

export function ageMinutes(event: SecurityEvent): number {
  const ts = new Date(event.timestamp).getTime();
  if (Number.isNaN(ts)) return 0;
  return Math.max(0, Math.round((Date.now() - ts) / 60000));
}

export function isOverSla(event: SecurityEvent): boolean {
  return isOpen(event) && ageMinutes(event) > SLA_MINUTES[severityOf(event)];
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
