import { describe, expect, it } from 'vitest';
import type { SecurityEvent } from '../types/security';
import { buildExportFilename, buildReportHtml, escapeCsvCell, toCsv, toJson } from './exportEvents';

const base: SecurityEvent = {
  event_id: 'e1',
  timestamp: '2026-10-03T12:00:00',
  source_type: 'api-gateway',
  source_id: 'gw-1',
  model: 'gpt-4',
  prompt: 'hello',
  verdict: 'benign',
  risk_score: 0.1,
  blocked: false,
};

const HEADER = 'event_id,timestamp,source_type,source_id,model,verdict,threat_type,risk_score,blocked,prompt';

describe('escapeCsvCell', () => {
  it('leaves plain values alone', () => {
    expect(escapeCsvCell('abc')).toBe('abc');
    expect(escapeCsvCell(0.5)).toBe('0.5');
    expect(escapeCsvCell(false)).toBe('false');
  });

  it('returns empty string for null and undefined', () => {
    expect(escapeCsvCell(undefined)).toBe('');
    expect(escapeCsvCell(null)).toBe('');
  });

  it('quotes commas, quotes and newlines', () => {
    expect(escapeCsvCell('a,b')).toBe('"a,b"');
    expect(escapeCsvCell('say "hi"')).toBe('"say ""hi"""');
    expect(escapeCsvCell('line1\nline2')).toBe('"line1\nline2"');
  });

  it('neutralises spreadsheet formulas', () => {
    expect(escapeCsvCell('=SUM(A1:A2)')).toBe("'=SUM(A1:A2)");
    expect(escapeCsvCell('+1')).toBe("'+1");
    expect(escapeCsvCell('-2')).toBe("'-2");
    expect(escapeCsvCell('@cmd')).toBe("'@cmd");
    expect(escapeCsvCell('=HYPERLINK("x","y")')).toBe('"\'=HYPERLINK(""x"",""y"")"');
  });

  it('does not touch real negative numbers', () => {
    expect(escapeCsvCell(-1)).toBe('-1');
  });
});

describe('toCsv', () => {
  it('writes a header and one line per row', () => {
    const csv = toCsv([base, { ...base, event_id: 'e2' }]);
    const lines = csv.trimEnd().split('\r\n');
    expect(lines).toHaveLength(3);
    expect(lines[0]).toBe(HEADER);
    expect(lines[1]).toBe('e1,2026-10-03T12:00:00,api-gateway,gw-1,gpt-4,benign,,0.1,false,hello');
  });

  it('escapes prompts with commas and quotes', () => {
    const csv = toCsv([{ ...base, prompt: 'a, "b"' }]);
    expect(csv).toContain(',"a, ""b"""');
  });

  it('returns only the header for no rows', () => {
    expect(toCsv([])).toBe(HEADER + '\r\n');
  });
});

describe('toJson', () => {
  it('round-trips the rows', () => {
    const rows = [base, { ...base, event_id: 'e2', threat_type: 'jailbreak' }];
    expect(JSON.parse(toJson(rows))).toEqual(rows);
  });
});

describe('buildExportFilename', () => {
  it('uses the date filters and active filters', () => {
    expect(
      buildExportFilename('csv', { dateFrom: '2026-10-01', dateTo: '2026-10-07', verdict: 'malicious' }, [base]),
    ).toBe('tenet-events_2026-10-01_to_2026-10-07_malicious.csv');
  });

  it('falls back to the range of the rows', () => {
    const rows = [base, { ...base, timestamp: '2026-10-05T08:00:00' }];
    expect(buildExportFilename('json', {}, rows)).toBe('tenet-events_2026-10-03_to_2026-10-05_all.json');
  });

  it('joins several filters and slugs them', () => {
    expect(
      buildExportFilename(
        'pdf',
        { dateFrom: '2026-10-01', dateTo: '2026-10-02', verdict: 'malicious', status: 'blocked', threatType: 'prompt_injection' },
        [],
      ),
    ).toBe('tenet-events_2026-10-01_to_2026-10-02_malicious-blocked-prompt-injection.pdf');
  });

  it('includes search, source IP, day and hour filters', () => {
    expect(
      buildExportFilename(
        'csv',
        { search: 'Prompt Inj', sourceIP: '10.0.0.1', dayOfWeek: '2', hourFrom: '9', hourTo: '17' },
        [],
      ),
    ).toBe('tenet-events_10-0-0-1-search-prompt-inj-day2-hour9-17.csv');
  });

  it('works with no rows and no filters', () => {
    expect(buildExportFilename('csv', {}, [])).toBe('tenet-events_all.csv');
  });
});

describe('buildReportHtml', () => {
  it('escapes prompt content and lists filters', () => {
    const html = buildReportHtml([{ ...base, prompt: '<script>alert(1)</script>' }], 't', ['Severity: x']);
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('Severity: x');
  });
});
