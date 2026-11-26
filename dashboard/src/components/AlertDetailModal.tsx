import { useEffect, useRef, useState } from 'react';
import type { SecurityEvent } from '../types/security';
import { threatTypeLabel } from '../constants/charts';
import { dateTimeLabel, severityOf, slaRemainingLabel, workflowStatus } from '../utils/alerts';

interface AlertDetailModalProps {
  event: SecurityEvent;
  onClose: () => void;
  onAcknowledge: (eventId: string) => void;
  onResolve: (eventId: string, note?: string) => void;
}

const getOwaspMapping = (threatType?: string): string[] => {
  switch (threatType) {
    case 'prompt_injection':
      return ['LLM01: Prompt Injection', 'LLM06: Excessive Agency', 'Rule: TENET-ADV-092-INJECT'];
    case 'jailbreak':
      return ['LLM01: Prompt Injection / Jailbreak', 'LLM02: Sensitive Information Disclosure', 'Rule: TENET-ADV-104-JAILBREAK'];
    case 'data_extraction':
      return ['LLM02: Sensitive Information Disclosure', 'LLM06: Excessive Agency', 'Rule: TENET-ADV-045-DATA-EXFIL'];
    case 'phishing':
      return ['LLM01: Prompt Injection', 'LLM05: Supply Chain Vulnerabilities', 'Rule: TENET-ADV-088-PHISH'];
    case 'role_manipulation':
      return ['LLM01: Prompt Injection', 'LLM07: Insecure Plugin Design', 'Rule: TENET-ADV-061-ROLE'];
    default:
      return ['LLM01: Prompt Injection', 'Rule: TENET-ADV-000-BASELINE'];
  }
};

export function AlertDetailModal({ event, onClose, onAcknowledge, onResolve }: AlertDetailModalProps) {
  const [copied, setCopied] = useState(false);
  const [showNoteInput, setShowNoteInput] = useState(false);
  const [resolutionNote, setResolutionNote] = useState('');
  const modalRef = useRef<HTMLDivElement>(null);

  const status = workflowStatus(event);
  const severity = severityOf(event);

  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    modalRef.current?.focus();

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== 'Tab' || !modalRef.current) return;
      const focusable = modalRef.current.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      previouslyFocused?.focus();
    };
  }, [onClose]);

  const handleCopyPrompt = async () => {
    try {
      await navigator.clipboard.writeText(event.prompt);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard blocked — leave the label unchanged rather than claim success */
    }
  };

  const handleResolve = () => {
    const trimmed = resolutionNote.trim();
    onResolve(event.event_id, trimmed || 'Resolved by SOC analyst');
    setShowNoteInput(false);
  };

  return (
    <div
      className="amodal"
      onMouseDown={e => {
        if (e.target === e.currentTarget) onClose();
      }}
      data-testid="alert-modal-backdrop"
    >
      <div
        ref={modalRef}
        className="amodal-card"
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="alert-modal-title"
        tabIndex={-1}
        data-testid="alert-detail-modal"
      >
        <div className="amodal-hd">
          <div className="t">
            <h2 id="alert-modal-title" data-testid="modal-alert-id">
              {threatTypeLabel(event.threat_type ?? event.verdict)} · {event.source_type}
            </h2>
            <div className="sub">
              {event.event_id} · {dateTimeLabel(event.timestamp)} · {slaRemainingLabel(event)}
            </div>
          </div>
          <button className="iconbtn" onClick={onClose} aria-label="Close alert" data-testid="modal-close-button" style={{ marginLeft: 'auto' }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M6 6l12 12M18 6L6 18" />
            </svg>
          </button>
        </div>

        <div className="amodal-bd">
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            <span className={`badge status-${status}`} data-testid="modal-workflow-status">
              {status}
            </span>
            <span className={`badge sev-${severity}`}>{severity}</span>
            <span className={`badge t-${event.blocked ? 'blocked' : 'flagged'}`} data-testid="modal-verdict">
              {event.verdict}
            </span>
            <span className="badge" data-testid="modal-risk-score">
              risk {event.risk_score.toFixed(2)}
            </span>
            {status === 'resolved' && event.resolved_at && (
              <span className="badge status-resolved" data-testid="modal-resolved-time">
                resolved {dateTimeLabel(event.resolved_at)}
              </span>
            )}
          </div>

          <dl className="kv">
            <dt>Threat vector</dt>
            <dd data-testid="modal-threat-type">{threatTypeLabel(event.threat_type || 'unknown')}</dd>
            <dt>Target model</dt>
            <dd>{event.model || 'unknown'}</dd>
            <dt>Source</dt>
            <dd>
              {event.source_type} · {event.source_id}
            </dd>
            <dt>Enforcement</dt>
            <dd>{event.blocked ? 'Dropped before the model' : 'Monitored, forwarded to the model'}</dd>
            <dt>Event id</dt>
            <dd data-testid="modal-full-event-id" style={{ fontFamily: 'var(--f-mono)', fontSize: 11 }}>
              {event.event_id}
            </dd>
          </dl>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 7 }}>
              <span className="lbl" style={{ marginRight: 'auto' }}>
                Intercepted payload
              </span>
              <button className="abtn" onClick={handleCopyPrompt} aria-label="Copy prompt text" data-testid="copy-prompt-btn">
                {copied ? 'Copied' : 'Copy payload'}
              </button>
            </div>
            <div className="promptbox" data-testid="modal-prompt-content">
              {event.prompt || '[No prompt content logged]'}
            </div>
          </div>

          <div>
            <span className="lbl" style={{ display: 'block', marginBottom: 7 }}>
              OWASP Top 10 for LLM reference
            </span>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {getOwaspMapping(event.threat_type).map(item => (
                <span className="badge" key={item}>
                  {item}
                </span>
              ))}
            </div>
          </div>

          {showNoteInput && (
            <div className="resolvebox">
              <label className="lbl" htmlFor="resolution-note">
                Analyst resolution note
              </label>
              <textarea
                id="resolution-note"
                data-testid="resolution-note-input"
                value={resolutionNote}
                onChange={e => setResolutionNote(e.target.value)}
                placeholder="Document the containment action or forensic findings…"
                rows={2}
              />
            </div>
          )}

          {event.acknowledged_at && (
            <p className="hint">Acknowledged {dateTimeLabel(event.acknowledged_at)}</p>
          )}
          {event.resolution_note && <p className="hint">Note: {event.resolution_note}</p>}
        </div>

        <div className="amodal-ft">
          {status === 'new' && (
            <button className="abtn primary" onClick={() => onAcknowledge(event.event_id)} data-testid="modal-acknowledge-btn">
              Acknowledge
            </button>
          )}
          {status !== 'resolved' &&
            (!showNoteInput ? (
              <button className="abtn" onClick={() => setShowNoteInput(true)} data-testid="modal-resolve-btn">
                Resolve
              </button>
            ) : (
              <button className="abtn primary" onClick={handleResolve} data-testid="modal-confirm-resolve-btn">
                Confirm resolution
              </button>
            ))}
          <span className="sp" />
          <button className="abtn" onClick={onClose} data-testid="modal-dismiss-btn">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
