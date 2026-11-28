import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from 'recharts';
import type { ChartFilterAction } from '../../types/security';
import type { NamedCount } from '../../utils/chartAggregations';
import { colorForIndex } from '../../constants/charts';
import { ChartCard } from './ChartCard';
import { CHART_TOOLTIP_PROPS, formatCountTooltip } from './chartTooltipProps';

interface Props {
  data: NamedCount[];
  onFilter: (action: ChartFilterAction) => void;
}

function summaryText(data: NamedCount[]): string {
  if (data.length === 0) return 'No attack vector data available.';
  return `Top vectors: ${data.map(d => `${d.name} (${d.value})`).join(', ')}.`;
}

export function TopAttackVectorsChart({ data, onFilter }: Props) {
  const chartHeight = Math.max(200, data.length * 36 + 60);

  return (
    <ChartCard
      title="Top Attack Vectors"
      description={`Horizontal bar chart of the most common attack vectors. ${summaryText(data)}. Click a bar to filter by threat type.`}
    >
      <ResponsiveContainer width="100%" height={chartHeight}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 24, left: 8, bottom: 4 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#2A2320" horizontal={false} />
          <XAxis type="number" stroke="#8A8175" allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="name"
            stroke="#8A8175"
            width={130}
            tick={{ fontSize: 11 }}
          />
          <Tooltip
            {...CHART_TOOLTIP_PROPS}
            cursor={{ fill: 'rgba(59, 130, 246, 0.08)' }}
            formatter={(value) => formatCountTooltip(value)}
          />
          <Bar
            isAnimationActive={false}
            dataKey="value"
            radius={[0, 4, 4, 0]}
            cursor="pointer"
            onClick={(_e, index) => {
              const item = data[index];
              if (item) onFilter({ threatType: item.key });
            }}
          >
            {data.map((entry, index) => (
              <Cell key={entry.key} fill={colorForIndex(index)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      {data.length === 0 && <p className="chart-empty" role="status">No attack vector data to display.</p>}
    </ChartCard>
  );
}
