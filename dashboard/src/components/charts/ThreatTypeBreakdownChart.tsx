import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import type { ChartFilterAction } from '../../types/security';
import type { NamedCount } from '../../utils/chartAggregations';
import { colorForIndex } from '../../constants/charts';
import { ChartCard } from './ChartCard';
import { CHART_TOOLTIP_PROPS, formatPercentTooltip } from './chartTooltipProps';

interface Props {
  data: NamedCount[];
  onFilter: (action: ChartFilterAction) => void;
}

function summaryText(data: NamedCount[]): string {
  if (data.length === 0) return 'No threat type data available.';
  return data.map(d => `${d.name}: ${d.value}`).join(', ');
}

export function ThreatTypeBreakdownChart({ data, onFilter }: Props) {
  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <ChartCard
      title="Threat Type Breakdown"
      description={`Donut chart showing distribution of threat types across ${total} detections. ${summaryText(data)}. Click a segment to filter the alert feed.`}
    >
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            isAnimationActive={false}
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={60}
            outerRadius={90}
            paddingAngle={3}
            cursor="pointer"
            onClick={(_data, index) => {
              const item = data[index];
              if (item) onFilter({ threatType: item.key });
            }}
          >
            {data.map((entry, index) => (
              <Cell
                key={entry.key}
                fill={colorForIndex(index)}
                stroke="#141417"
                strokeWidth={2}
              />
            ))}
          </Pie>
          <Tooltip
            {...CHART_TOOLTIP_PROPS}
            formatter={(value, name) => formatPercentTooltip(value, String(name), total)}
          />
          <Legend
            verticalAlign="bottom"
            formatter={(value: string) => <span style={{ color: '#8A8175', fontSize: 12 }}>{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
      {data.length === 0 && <p className="chart-empty" role="status">No threat type data to display.</p>}
    </ChartCard>
  );
}
