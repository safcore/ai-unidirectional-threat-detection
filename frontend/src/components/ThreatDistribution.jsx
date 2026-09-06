import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
} from 'recharts'


function ThreatDistribution({ alerts = [] }) {

  const threatCounts = alerts.reduce(
    (counts, alert) => {

      const threat =
        alert.threat_class ||
        'Unknown'

      counts[threat] =
        (counts[threat] || 0) + 1

      return counts

    },
    {}
  )


  const data = Object.entries(
    threatCounts
  ).map(
    ([name, value]) => ({
      name,
      value,
    })
  )


  return (
    <section className="chart-card">

      <div className="chart-header">

        <div>

          <h2>Threat Distribution</h2>

          <p>
            Detected threats by category
          </p>

        </div>

      </div>


      <div className="chart-container">

        {data.length > 0 ? (

          <ResponsiveContainer
            width="100%"
            height={280}
          >

            <PieChart>

              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={65}
                outerRadius={100}
                paddingAngle={4}
                dataKey="value"
              >

                {data.map(
                  (entry, index) => (

                    <Cell
                      key={`cell-${index}`}
                      fill={
                        [
                          '#ef4444',
                          '#f59e0b',
                          '#60a5fa',
                          '#a78bfa',
                          '#22c55e',
                          '#ec4899',
                          '#14b8a6',
                          '#f97316',
                        ][
                          index %
                          8
                        ]
                      }
                    />

                  )
                )}

              </Pie>


              <Tooltip />


              <Legend />

            </PieChart>

          </ResponsiveContainer>

        ) : (

          <div className="no-chart-data">
            No threat data available.
          </div>

        )}

      </div>

    </section>
  )
}


export default ThreatDistribution