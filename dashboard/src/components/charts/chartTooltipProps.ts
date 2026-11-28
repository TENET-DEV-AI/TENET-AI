/** Shared Recharts tooltip styling for dark theme readability */
export const CHART_TOOLTIP_PROPS = {
  contentStyle: {
    background: '#1A1512',
    border: '1px solid rgba(239,233,221,.10)',
    borderRadius: 8,
    color: '#EFE9DD',
  },
  labelStyle: {
    color: '#EFE9DD',
    fontWeight: 600,
    marginBottom: 4,
  },
  itemStyle: {
    color: '#EFE9DD',
  },
  wrapperStyle: {
    outline: 'none',
  },
} as const;

export function formatCountTooltip(value: unknown, label = 'Count'): [string, string] {
  const n = typeof value === 'number' ? value : Number(value) || 0;
  return [`${n} detections`, label];
}

export function formatPercentTooltip(
  value: unknown,
  name: string,
  total: number,
): [string, string] {
  const n = typeof value === 'number' ? value : Number(value) || 0;
  const pct = total > 0 ? ((n / total) * 100).toFixed(1) : '0';
  return [`${n} (${pct}%)`, name];
}
