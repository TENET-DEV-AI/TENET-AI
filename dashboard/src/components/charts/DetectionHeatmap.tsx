import { useMemo } from 'react';
import type { ChartFilterAction } from '../../types/security';
import type { HeatmapCell } from '../../utils/chartAggregations';
import { DAYS_OF_WEEK, HOUR_LABELS } from '../../constants/charts';
import { heatmapMaxCount } from '../../utils/chartAggregations';
import { ChartCard } from './ChartCard';

interface Props {
  cells: HeatmapCell[];
  onFilter: (action: ChartFilterAction) => void;
}

/** Ember intensity scale — the one accent, used only for threat volume. */
function heatColor(intensity: number): string {
  if (intensity <= 0) return '#171310';
  const t = Math.min(1, Math.max(0, intensity));
  const r = Math.round(34 + (225 - 34) * t);
  const g = Math.round(28 + (89 - 28) * t);
  const b = Math.round(24 + (60 - 24) * t);
  return `rgb(${r}, ${g}, ${b})`;
}

function summaryText(cells: HeatmapCell[]): string {
  const total = cells.reduce((s, c) => s + c.count, 0);
  if (total === 0) return 'No detection activity recorded.';
  const peak = [...cells].sort((a, b) => b.count - a.count)[0];
  return `${total} detections across the week. Peak activity on ${peak?.dayLabel} at ${peak?.hourLabel} with ${peak?.count} events.`;
}

export function DetectionHeatmap({ cells, onFilter }: Props) {
  const maxCount = useMemo(() => heatmapMaxCount(cells), [cells]);

  const grid = useMemo(() => {
    const byDay = new Map<number, HeatmapCell[]>();
    cells.forEach(c => {
      if (!byDay.has(c.day)) byDay.set(c.day, []);
      byDay.get(c.day)!.push(c);
    });
    return DAYS_OF_WEEK.map((_, day) => (byDay.get(day) ?? []).sort((a, b) => a.hour - b.hour));
  }, [cells]);

  const hourTicks = [0, 6, 12, 18];

  return (
    <ChartCard
      title="Detection Heatmap"
      description={`Heatmap of detections by day of week and hour of day. ${summaryText(cells)}. Click a cell to filter by that time slot.`}
      className="chart-container-wide"
    >
      <div className="heatmap-wrapper" aria-label="Detection heatmap by day and hour">
        <div className="heatmap-header-row">
          <span className="heatmap-corner" aria-hidden="true" />
          <div className="heatmap-hour-labels" aria-hidden="true">
            {hourTicks.map(h => (
              <span key={h}>{HOUR_LABELS[h]}</span>
            ))}
          </div>
        </div>

        {grid.map((row, dayIndex) => (
          <div key={dayIndex} className="heatmap-data-row">
            <span className="heatmap-day-label">{DAYS_OF_WEEK[dayIndex]}</span>
            <div className="heatmap-cells">
              {row.map(cell => {
                const intensity = cell.count / maxCount;
                const label = `${cell.dayLabel} ${cell.hourLabel}: ${cell.count} detection${cell.count !== 1 ? 's' : ''}`;
                return (
                  <button
                    key={`${cell.day}-${cell.hour}`}
                    type="button"
                    className="heatmap-cell"
                    style={{ backgroundColor: heatColor(intensity) }}
                    title={label}
                    aria-label={`${label}. Click to filter.`}
                    onClick={() =>
                      onFilter({
                        dayOfWeek: String(cell.day),
                        hourFrom: String(cell.hour),
                        hourTo: String(cell.hour),
                        dateFrom: '',
                        dateTo: '',
                      })
                    }
                  >
                    <span className="heatmap-cell-value" aria-hidden="true">
                      {cell.count > 0 ? cell.count : ''}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="heatmap-legend" aria-hidden="true">
        <span>Low</span>
        <div className="heatmap-legend-scale">
          {[0, 0.25, 0.5, 0.75, 1].map(v => (
            <span key={v} style={{ backgroundColor: heatColor(v) }} />
          ))}
        </div>
        <span>High</span>
      </div>
    </ChartCard>
  );
}
