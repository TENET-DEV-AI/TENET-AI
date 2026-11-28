import { PieChart, Pie, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import type { ChartFilterAction } from '../../types/security';
import type { NamedCount } from '../../utils/chartAggregations';
import { SEVERITY_COLORS } from '../../constants/charts';
import { ChartCard } from './ChartCard';
import { CHART_TOOLTIP_PROPS, formatPercentTooltip } from './chartTooltipProps';

interface Props {
  data: NamedCount[];
  onFilter: (action: ChartFilterAction) => void;
}

function summaryText(data: NamedCount[]): string {
  if (data.length === 0) return 'No severity data available.';
  return data.map(d => `${d.name}: ${d.value}`).join(', ');
}

/**
 * One reading of severity, not two: the donut carries the share, the legend
 * carries the counts. The previous build drew the same numbers as a bar chart
 * and a donut side by side, which doubled the panel for no extra information.
 */
export function SeverityDistributionChart({ data, onFilter }: Props) {
  const total = data.reduce((sum, entry) => sum + entry.value, 0);

  return (
    <ChartCard
      title="Severity Distribution"
      description={`Distribution of detections by severity level. ${summaryText(data)}. Click a segment to filter by severity.`}
      headerExtra={<span className="lbl">{total} scored</span>}
    >
      <div className="severity-charts">
        <div className="severity-donut">
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                isAnimationActive={false}
                data={data}
                dataKey="value"
                nameKey="name"
                innerRadius={54}
                outerRadius={80}
                paddingAngle={3}
                stroke="none"
                cursor="pointer"
                onClick={(_data, index) => {
                  const item = data[index];
                  if (item) onFilter({ verdict: item.key });
                }}
              >
                {data.map(entry => (
                  <Cell key={entry.key} fill={SEVERITY_COLORS[entry.key] ?? '#6E6A62'} />
                ))}
              </Pie>
              <Tooltip
                {...CHART_TOOLTIP_PROPS}
                formatter={(value, name) => formatPercentTooltip(value, String(name), total)}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="severity-center" aria-hidden="true">
            <b>{total}</b>
            <span>scored</span>
          </div>
        </div>

        <ul className="severity-key">
          {data.map(entry => (
            <li key={entry.key}>
              <button type="button" onClick={() => onFilter({ verdict: entry.key })}>
                <span className="sw" style={{ background: SEVERITY_COLORS[entry.key] ?? '#6E6A62' }} />
                <span className="nm">{entry.name}</span>
                <span className="vl">{entry.value}</span>
                <span className="pc">{total ? Math.round((entry.value / total) * 100) : 0}%</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </ChartCard>
  );
}
