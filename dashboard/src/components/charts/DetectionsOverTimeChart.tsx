import { useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line,
} from 'recharts';
import type { ChartFilterAction, TimeRange } from '../../types/security';
import type { TimeBucket } from '../../utils/chartAggregations';
import { CB_PALETTE } from '../../constants/charts';
import { ChartCard } from './ChartCard';
import { CHART_TOOLTIP_PROPS, formatCountTooltip } from './chartTooltipProps';

interface Props {
  data: TimeBucket[];
  range: TimeRange;
  onRangeChange: (range: TimeRange) => void;
  onFilter: (action: ChartFilterAction) => void;
}

const RANGE_OPTIONS: { value: TimeRange; label: string }[] = [
  { value: 'hourly', label: 'Hourly' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
];

function summaryText(data: TimeBucket[]): string {
  const total = data.reduce((s, d) => s + d.count, 0);
  if (total === 0) return 'No detections in the selected time range.';
  const peak = [...data].sort((a, b) => b.count - a.count)[0];
  return `${total} total detections. Peak at ${peak?.label ?? 'N/A'} with ${peak?.count ?? 0} events.`;
}

export function DetectionsOverTimeChart({ data, range, onRangeChange, onFilter }: Props) {
  const [chartType, setChartType] = useState<'bar' | 'line'>('line');

  const handleClick = (payload: TimeBucket) => {
    onFilter({
      dateFrom: payload.dateFrom,
      dateTo: payload.dateTo,
      hourFrom: payload.hourFrom ?? '',
      hourTo: payload.hourTo ?? '',
      dayOfWeek: '',
    });
  };

  const clickableDot = (dotProps: { cx?: number; cy?: number; index?: number }, active = false) => {
    const { cx, cy, index } = dotProps;
    if (cx == null || cy == null || index == null) return null;
    return (
      <circle
        key={active ? `active-${index}` : index}
        cx={cx}
        cy={cy}
        r={active ? 6 : 4}
        fill={CB_PALETTE[0]}
        stroke={active ? '#0C0A09' : undefined}
        strokeWidth={active ? 2 : undefined}
        cursor="pointer"
        onClick={(e) => {
          e.stopPropagation();
          const bucket = data[index];
          if (bucket) handleClick(bucket);
        }}
      />
    );
  };

  return (
    <ChartCard
      title="Detections Over Time"
      description={`${range} view of security detections. ${summaryText(data)}. Click a data point to filter by that time period.`}
      headerExtra={
        <div className="chart-controls">
          <div className="chart-toggle-group" role="group" aria-label="Time range">
            {RANGE_OPTIONS.map(opt => (
              <button
                key={opt.value}
                type="button"
                className={range === opt.value ? 'active' : ''}
                onClick={() => onRangeChange(opt.value)}
                aria-pressed={range === opt.value}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <div className="chart-toggle-group" role="group" aria-label="Chart type">
            <button
              type="button"
              className={chartType === 'bar' ? 'active' : ''}
              onClick={() => setChartType('bar')}
              aria-pressed={chartType === 'bar'}
            >
              Bar
            </button>
            <button
              type="button"
              className={chartType === 'line' ? 'active' : ''}
              onClick={() => setChartType('line')}
              aria-pressed={chartType === 'line'}
            >
              Line
            </button>
          </div>
        </div>
      }
    >
      <ResponsiveContainer width="100%" height={300}>
        {chartType === 'bar' ? (
          <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2A2320" vertical={false} />
            <XAxis dataKey="label" stroke="#8A8175" tick={{ fontSize: 11 }} interval="preserveStartEnd" />
            <YAxis stroke="#8A8175" allowDecimals={false} />
            <Tooltip
              {...CHART_TOOLTIP_PROPS}
              cursor={{ fill: 'rgba(225, 89, 60, 0.10)' }}
              formatter={(value) => formatCountTooltip(value)}
            />
            <Bar
              isAnimationActive={false}
              dataKey="count"
              fill={CB_PALETTE[0]}
              radius={[4, 4, 0, 0]}
              cursor="pointer"
              onClick={(_e, index) => {
                const bucket = data[index];
                if (bucket) handleClick(bucket);
              }}
            />
          </BarChart>
        ) : (
          <LineChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2A2320" vertical={false} />
            <XAxis dataKey="label" stroke="#8A8175" tick={{ fontSize: 11 }} interval="preserveStartEnd" />
            <YAxis stroke="#8A8175" allowDecimals={false} />
            <Tooltip
              {...CHART_TOOLTIP_PROPS}
              formatter={(value) => formatCountTooltip(value)}
            />
            <Line
              isAnimationActive={false}
              type="monotone"
              dataKey="count"
              stroke={CB_PALETTE[0]}
              strokeWidth={2}
              dot={clickableDot}
              activeDot={(props) => clickableDot(props, true)}
            />
          </LineChart>
        )}
      </ResponsiveContainer>
    </ChartCard>
  );
}
