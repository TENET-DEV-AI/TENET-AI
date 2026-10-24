import type { FilterState, SecurityEvent } from '../types/security';

export type ExportFormat = 'csv' | 'json' | 'pdf';

const CSV_COLUMNS = [
  'event_id',
  'timestamp',
  'source_type',
  'source_id',
  'model',
  'verdict',
  'threat_type',
  'risk_score',
  'blocked',
  'prompt',
] as const;

/**
 * Make a single value safe for a CSV cell.
 * - strings starting with = + - @ (or tab / CR) get a leading apostrophe so
 *   Excel / Sheets don't run them as formulas
 * - values with commas, quotes or newlines are wrapped in quotes, with inner
 *   quotes doubled
 */
export function escapeCsvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  let text = typeof value === 'string' ? value : String(value);
  if (typeof value === 'string' && /^[=+\-@\t\r]/.test(text)) {
    text = `'${text}`;
  }
  if (/[",\r\n]/.test(text)) {
    text = `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

export function toCsv(rows: SecurityEvent[]): string {
  const lines = [CSV_COLUMNS.join(',')];
  for (const row of rows) {
    lines.push(CSV_COLUMNS.map(col => escapeCsvCell(row[col])).join(','));
  }
  return lines.join('\r\n') + '\r\n';
}

export function toJson(rows: SecurityEvent[]): string {
  return JSON.stringify(rows, null, 2);
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function localDay(ts: string): string | null {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return null;
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${d.getFullYear()}-${mm}-${dd}`;
}

/**
 * Build a name like tenet-events_2026-10-01_to_2026-10-07_malicious.csv.
 * The date range comes from the date filters when set, otherwise from the
 * rows being exported. Active verdict / status / threat / type filters are
 * appended, or "all" when nothing is filtered.
 */
export function buildExportFilename(
  format: ExportFormat,
  filters: Partial<FilterState>,
  rows: SecurityEvent[],
): string {
  const days = rows.map(r => localDay(r.timestamp)).filter((d): d is string => d !== null).sort();
  const from = filters.dateFrom || days[0];
  const to = filters.dateTo || days[days.length - 1];

  const parts = ['tenet-events'];
  if (from && to) parts.push(`${from}_to_${to}`);
  else if (from) parts.push(`from_${from}`);
  else if (to) parts.push(`until_${to}`);

  const hourPart = filters.hourFrom || filters.hourTo
    ? `hour${filters.hourFrom || '0'}-${filters.hourTo || '23'}`
    : '';
  const filterParts = [
    filters.verdict,
    filters.status,
    filters.threatType,
    filters.detectionType,
    filters.sourceIP,
    filters.search && `search-${filters.search}`,
    filters.dayOfWeek && `day${filters.dayOfWeek}`,
    hourPart,
  ]
    .filter((v): v is string => Boolean(v))
    .map(slug)
    .filter(Boolean);
  parts.push(filterParts.length ? filterParts.join('-') : 'all');

  return `${parts.join('_')}.${format}`;
}

/** Trigger a browser download for a text payload. */
export function downloadText(filename: string, content: string, mime: string): void {
  // BOM so Excel reads UTF-8 CSVs correctly
  const body = mime === 'text/csv' ? '﻿' + content : content;
  const blob = new Blob([body], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Self-contained HTML for the printable summary report. */
export function buildReportHtml(
  rows: SecurityEvent[],
  title: string,
  filterSummary: string[],
): string {
  const count = (v: string) => rows.filter(r => r.verdict === v).length;
  const blocked = rows.filter(r => r.blocked).length;
  const avg = rows.length
    ? (rows.reduce((s, r) => s + r.risk_score, 0) / rows.length).toFixed(2)
    : '0.00';

  const body = rows
    .map(
      r =>
        `<tr><td>${escapeHtml(r.verdict)}</td><td>${escapeHtml(r.threat_type ?? '')}</td>` +
        `<td>${escapeHtml(r.timestamp)}</td><td>${escapeHtml(r.source_id)}</td>` +
        `<td>${r.risk_score.toFixed(2)}</td><td>${r.blocked ? 'Blocked' : 'Allowed'}</td>` +
        `<td>${escapeHtml(r.prompt ?? '')}</td></tr>`,
    )
    .join('');

  const filtersText = filterSummary.length ? escapeHtml(filterSummary.join(', ')) : 'none';

  return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>
body{font-family:Arial,sans-serif;color:#111;margin:24px}
h1{font-size:20px;margin:0 0 4px}
.meta{color:#555;font-size:12px;margin-bottom:16px}
.stats{display:flex;gap:12px;margin-bottom:16px}
.stat{border:1px solid #ccc;border-radius:6px;padding:8px 14px}
.stat b{display:block;font-size:18px}
table{width:100%;border-collapse:collapse;font-size:11px}
th,td{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#eee}
tr{page-break-inside:avoid}
</style></head><body>
<h1>TENET AI - Threat Events Report</h1>
<div class="meta">Generated ${escapeHtml(new Date().toLocaleString())} | Filters: ${filtersText}</div>
<div class="stats">
<div class="stat"><b>${rows.length}</b>Events</div>
<div class="stat"><b>${count('malicious')}</b>Malicious</div>
<div class="stat"><b>${count('suspicious')}</b>Suspicious</div>
<div class="stat"><b>${count('benign')}</b>Benign</div>
<div class="stat"><b>${blocked}</b>Blocked</div>
<div class="stat"><b>${avg}</b>Avg risk</div>
</div>
<table><thead><tr><th>Verdict</th><th>Threat</th><th>Timestamp</th><th>Source</th><th>Risk</th><th>Action</th><th>Prompt</th></tr></thead>
<tbody>${body}</tbody></table>
</body></html>`;
}

/**
 * Open the browser print dialog on the report; the user picks "Save as PDF".
 * Uses a hidden iframe so no popup blocker gets involved.
 */
export function printReport(html: string): void {
  const frame = document.createElement('iframe');
  frame.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0';
  frame.setAttribute('aria-hidden', 'true');
  document.body.appendChild(frame);
  const doc = frame.contentDocument;
  const win = frame.contentWindow;
  if (!doc || !win) {
    frame.remove();
    return;
  }
  doc.open();
  doc.write(html);
  doc.close();
  win.addEventListener('afterprint', () => frame.remove());
  win.focus();
  win.print();
}
