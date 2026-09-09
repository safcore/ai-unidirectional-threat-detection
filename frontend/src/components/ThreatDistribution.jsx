import { useMemo } from 'react'
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
} from 'recharts'

const PALETTE = [
  '#ef4444', // red
  '#f97316', // orange
  '#f59e0b', // amber
  '#0ea5e9', // cyan
  '#8b5cf6', // purple
  '#10b981', // green
]

function ThreatDistribution({ alerts = [] }) {
  const { chartData, total } = useMemo(() => {
    const counts = {}
    alerts.forEach((a) => {
      const t = a.threat_class || 'Other'
      counts[t] = (counts[t] || 0) + 1
    })

    const sorted = Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5) // Top 5 categories to prevent huge list

    const data = sorted.map(([name, value], idx) => ({
      name,
      value,
      color: PALETTE[idx % PALETTE.length],
    }))

    return { chartData: data, total: alerts.length }
  }, [alerts])

  return (
    <div className="viz-card">
      <div className="viz-header">
        <span className="viz-title">Threat Distribution</span>
        <span className="viz-sub-count">{total} Total Alerts</span>
      </div>

      <div className="viz-donut-grid">
        <div className="donut-chart-box">
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} stroke="#0b101c" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: '#0f172a',
                    border: '1px solid #334155',
                    borderRadius: '6px',
                    fontSize: '11px',
                    color: '#f87171',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="viz-empty">No distribution data</div>
          )}
        </div>

        <div className="donut-legend-box">
          {chartData.map((item) => (
            <div key={item.name} className="compact-legend-row">
              <span className="legend-dot" style={{ backgroundColor: item.color }}></span>
              <span className="legend-name" title={item.name}>{item.name}</span>
              <span className="legend-qty">{item.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default ThreatDistribution