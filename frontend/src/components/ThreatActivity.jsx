import { useMemo } from 'react'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts'

function ThreatActivity({ alerts = [] }) {
  const data = useMemo(() => {
    const timeCounts = alerts.reduce((counts, alert) => {
      const date = new Date(alert.timestamp)
      const time = date.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      })
      counts[time] = (counts[time] || 0) + 1
      return counts
    }, {})

    return Object.entries(timeCounts)
      .sort(([timeA], [timeB]) => timeA.localeCompare(timeB))
      .map(([time, threats]) => ({
        time,
        threats,
      }))
  }, [alerts])

  return (
    <div className="viz-card">
      <div className="viz-header">
        <span className="viz-title">Threat Activity</span>
        <div className="live-pill">
          <span className="dot dot-green"></span>
          <span>Live</span>
        </div>
      </div>

      <div className="viz-body">
        {data.length > 0 ? (
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={data} margin={{ top: 8, right: 12, left: -24, bottom: 0 }}>
              <defs>
                <linearGradient id="actGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 10 }} />
              <YAxis stroke="#475569" allowDecimals={false} tick={{ fontSize: 10 }} />
              <Tooltip
                contentStyle={{
                  background: '#0f172a',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  fontSize: '11px',
                  color: '#f8fafc',
                }}
              />
              <Area
                type="monotone"
                dataKey="threats"
                stroke="#0ea5e9"
                strokeWidth={2}
                fill="url(#actGradient)"
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="viz-empty">No activity data</div>
        )}
      </div>
    </div>
  )
}

export default ThreatActivity