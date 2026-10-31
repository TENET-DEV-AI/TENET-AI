import React, { useState, useEffect, useRef } from 'react';
import { X, ShieldAlert, CheckCircle2, AlertTriangle, Copy, Check, Terminal, Clock, Tag } from 'lucide-react';
import type { SecurityEvent } from '../types/security';
import { threatTypeLabel } from '../constants/charts';

interface AlertDetailModalProps {
  event: SecurityEvent;
  onClose: () => void;
  onAcknowledge: (eventId: string) => void;
  onResolve: (eventId: string, note?: string) => void;
}

const getOwaspMapping = (threatType?: string): string[] => {
  switch (threatType) {
    case 'prompt_injection':
      return [
        'LLM01: Prompt Injection',
        'LLM06: Excessive Agency',
        'Rule: TENET-ADV-092-INJECT',
      ];
    case 'jailbreak':
      return [
        'LLM01: Prompt Injection / Jailbreak',
        'LLM02: Sensitive Information Disclosure',
        'Rule: TENET-ADV-104-JAILBREAK',
      ];
    case 'data_extraction':
      return [
        'LLM02: Sensitive Information Disclosure',
        'LLM06: Excessive Agency',
        'Rule: TENET-ADV-045-DATA-EXFIL',
      ];
    case 'phishing':
      return [
        'LLM01: Prompt Injection',
        'LLM05: Supply Chain Vulnerabilities',
        'Rule: TENET-ADV-088-PHISH',
      ];
    case 'role_manipulation':
      return [
        'LLM01: Prompt Injection',
        'LLM06: Excessive Agency',
        'Rule: TENET-ADV-073-ROLE-SPOOF',
      ];
    default:
      return [
        'LLM General Reference',
        'Rule: TENET-ADV-GENERIC',
      ];
  }
};

export const AlertDetailModal: React.FC<AlertDetailModalProps> = ({
  event,
  onClose,
  onAcknowledge,
  onResolve,
}) => {
  const [copied, setCopied] = useState(false);
  const [resolutionNote, setResolutionNote] = useState('');
  const [showNoteInput, setShowNoteInput] = useState(false);
  const modalRef = useRef<HTMLDivElement>(null);

  const status = event.alert_status || 'new';

  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;

    // Focus the first focusable element inside the modal
    const focusable = modalRef.current?.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (focusable && focusable.length > 0) {
      focusable[0].focus();
    }

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key === 'Tab' && modalRef.current) {
        const focusableElements = Array.from(
          modalRef.current.querySelectorAll<HTMLElement>(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
          )
        ).filter(el => !el.hasAttribute('disabled'));

        if (focusableElements.length === 0) return;

        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === firstElement) {
            e.preventDefault();
            lastElement.focus();
          }
        } else {
          if (document.activeElement === lastElement) {
            e.preventDefault();
            firstElement.focus();
          }
        }
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
      // Rejection handled without falsely indicating Copied
    }
  };

  const handleResolve = () => {
    const trimmed = resolutionNote.trim();
    onResolve(event.event_id, trimmed || 'Resolved by SOC Analyst');
    setShowNoteInput(false);
  };

  return (
    <div
      className="modal-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
      data-testid="alert-modal-backdrop"
    >
      <div
        ref={modalRef}
        className="modal-card"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="alert-modal-title"
        data-testid="alert-detail-modal"
      >
        <div className="modal-header">
          <div className="modal-title-wrap">
            <ShieldAlert className="modal-icon" size={24} />
            <div>
              <h2 id="alert-modal-title" data-testid="modal-alert-id">
                Alert: {event.event_id.substring(0, 18)}...
              </h2>
              <span className="modal-timestamp">
                <Clock size={12} /> {new Date(event.timestamp).toLocaleString()}
              </span>
            </div>
          </div>
          <button
            className="modal-close-btn"
            onClick={onClose}
            aria-label="Close alert modal"
            data-testid="modal-close-button"
          >
            <X size={20} />
          </button>
        </div>

        <div className="modal-body">
          {/* Status and Triage Bar */}
          <div className="triage-status-banner">
            <div className="triage-status-pill">
              <span className="triage-label">Workflow Status:</span>
              <span className={`status-badge status-${status}`} data-testid="modal-workflow-status">
                {status === 'new' && '● New Alert'}
                {status === 'acknowledged' && '◐ Acknowledged'}
                {status === 'resolved' && '✔ Resolved'}
              </span>
            </div>
            <div className="triage-verdict-pill">
              <span className="triage-label">Verdict:</span>
              <span className={`verdict-badge ${event.verdict}`} data-testid="modal-verdict">
                {event.verdict}
              </span>
            </div>
            <div className="triage-score-pill">
              <span className="triage-label">Risk Score:</span>
              <span className="risk-score-value" data-testid="modal-risk-score">
                {(event.risk_score * 100).toFixed(0)}%
              </span>
            </div>
            {status === 'resolved' && event.resolved_at && (
              <div className="triage-status-pill">
                <span className="triage-label">Resolved:</span>
                <span className="resolved-note-value" style={{ fontSize: '11px', color: '#22c55e' }}>
                  {new Date(event.resolved_at).toLocaleTimeString()}{event.resolution_note ? ` (${event.resolution_note})` : ''}
                </span>
              </div>
            )}
          </div>

          {/* Forensic Metadata Grid */}
          <div className="forensic-grid">
            <div className="forensic-item">
              <span className="forensic-key">Threat Vector</span>
              <span className="forensic-val" data-testid="modal-threat-type">
                {threatTypeLabel(event.threat_type || 'unknown')}
              </span>
            </div>
            <div className="forensic-item">
              <span className="forensic-key">Target Model</span>
              <span className="forensic-val">{event.model || 'gpt-4o'}</span>
            </div>
            <div className="forensic-item">
              <span className="forensic-key">Source Identifier</span>
              <span className="forensic-val">{event.source_id}</span>
            </div>
            <div className="forensic-item">
              <span className="forensic-key">Policy Enforcement</span>
              <span className="forensic-val">
                {event.blocked ? '🛡️ Dropped / Blocked' : '⚠️ Monitored / Flagged'}
              </span>
            </div>
          </div>

          {/* Intercepted Prompt Section */}
          <div className="prompt-section">
            <div className="prompt-header">
              <span className="section-subtitle">
                <Terminal size={14} /> Intercepted User Payload
              </span>
              <button
                className="copy-prompt-btn"
                onClick={handleCopyPrompt}
                aria-label="Copy prompt text"
                data-testid="copy-prompt-btn"
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                <span>{copied ? 'Copied' : 'Copy Payload'}</span>
              </button>
            </div>
            <pre className="prompt-code-block" data-testid="modal-prompt-content">
              {event.prompt || '[No prompt content logged]'}
            </pre>
          </div>

          {/* Detection Heuristics */}
          <div className="mitre-section">
            <span className="section-subtitle">
              <Tag size={14} /> OWASP Top 10 for LLM Reference
            </span>
            <div className="mitre-tags">
              {getOwaspMapping(event.threat_type).map((item) => (
                <span key={item} className="mitre-pill">{item}</span>
              ))}
            </div>
          </div>

          {showNoteInput && (
            <div className="resolution-input-wrap">
              <label htmlFor="resolution-note">Analyst Resolution Note</label>
              <textarea
                id="resolution-note"
                data-testid="resolution-note-input"
                value={resolutionNote}
                onChange={(e) => setResolutionNote(e.target.value)}
                placeholder="Document containment action or forensic findings..."
                rows={2}
              />
            </div>
          )}
        </div>

        {/* Modal Actions */}
        <div className="modal-footer">
          <div className="modal-footer-left">
            <span
              className="modal-full-id"
              data-testid="modal-full-event-id"
              style={{ fontSize: '11px', color: '#71717a', fontFamily: 'monospace' }}
            >
              Full ID: {event.event_id}
            </span>
            {event.acknowledged_at && (
              <span className="ack-time-label">
                Acknowledged at {new Date(event.acknowledged_at).toLocaleTimeString()}
              </span>
            )}
            {event.resolved_at && (
              <span className="resolve-time-label" data-testid="modal-resolved-time" style={{ color: '#22c55e', fontSize: '11px' }}>
                Resolved at {new Date(event.resolved_at).toLocaleTimeString()}{event.resolution_note ? ` · ${event.resolution_note}` : ''}
              </span>
            )}
          </div>
          <div className="modal-footer-right">
            {status === 'new' && (
              <button
                type="button"
                className="btn-modal-ack"
                onClick={() => onAcknowledge(event.event_id)}
                data-testid="modal-acknowledge-btn"
              >
                <AlertTriangle size={15} />
                <span>Acknowledge Alert</span>
              </button>
            )}

            {status !== 'resolved' && (
              <>
                {!showNoteInput ? (
                  <button
                    type="button"
                    className="btn-modal-resolve"
                    onClick={() => setShowNoteInput(true)}
                    data-testid="modal-resolve-btn"
                  >
                    <CheckCircle2 size={15} />
                    <span>Resolve Alert</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn-modal-confirm-resolve"
                    onClick={handleResolve}
                    data-testid="modal-confirm-resolve-btn"
                  >
                    <CheckCircle2 size={15} />
                    <span>Confirm Resolution</span>
                  </button>
                )}
              </>
            )}

            <button
              type="button"
              className="btn-modal-dismiss"
              onClick={onClose}
              data-testid="modal-dismiss-btn"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
