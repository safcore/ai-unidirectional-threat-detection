import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts'


function ThreatActivity({ alerts = [] }) {

  const timeCounts = alerts.reduce(
    (counts, alert) => {

      const date =
        new Date(alert.timestamp)

      const time =
        date.toLocaleTimeString(
          [],
          {
            hour: '2-digit',
            minute: '2-digit',
            hour12: false,
          }
        )

      counts[time] =
        (counts[time] || 0) + 1

      return counts

    },
    {}
  )


  const data = Object.entries(
    timeCounts
  )
    .sort(
      ([timeA], [timeB]) =>
        timeA.localeCompare(timeB)
    )
    .map(
      ([time, threats]) => ({
        time,
        threats,
      })
    )


  return (
    <section className="chart-card">

      <div className="chart-header">

        <div>

          <h2>Threat Activity</h2>

          <p>
            Detected threats over time
          </p>

        </div>

      </div>


      <div className="chart-container">

        {data.length > 0 ? (

          <ResponsiveContainer
            width="100%"
            height={280}
          >

            <LineChart data={data}>

              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#1f2937"
              />

              <XAxis
                dataKey="time"
                stroke="#64748b"
              />

              <YAxis
                stroke="#64748b"
                allowDecimals={false}
              />

              <Tooltip
                contentStyle={{
                  background: '#0d111a',
                  border: '1px solid #26364a',
                  borderRadius: '8px',
                  color: '#e6edf7',
                }}
              />

              <Line
                type="monotone"
                dataKey="threats"
                stroke="#60a5fa"
                strokeWidth={3}
                dot={{ r: 4 }}
                activeDot={{ r: 6 }}
              />

            </LineChart>

          </ResponsiveContainer>

        ) : (

          <div className="no-chart-data">
            No threat activity data available.
          </div>

        )}

      </div>

    </section>
  )
}


export default ThreatActivity