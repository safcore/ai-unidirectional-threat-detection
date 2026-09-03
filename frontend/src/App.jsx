import {
  useEffect,
  useMemo,
  useState,
} from 'react'

import './App.css'

import Header from './components/Header'
import StatCard from './components/StatCard'
import ThreatActivity from './components/ThreatActivity'
import ThreatDistribution from './components/ThreatDistribution'
import AlertTable from './components/AlertTable'
import AlertDetails from './components/AlertDetails'

import {
  fetchAlerts,
  fetchAlertStatistics,
  connectToAlertStream,
} from './services/alertService'


function App() {
  const [alerts, setAlerts] =
    useState([])

  const [
    selectedAlert,
    setSelectedAlert,
  ] = useState(null)

  const [
    loading,
    setLoading,
  ] = useState(true)

  const [
    backendError,
    setBackendError,
  ] = useState(false)

  const [
    streamConnected,
    setStreamConnected,
  ] = useState(false)

  const [
    backendStats,
    setBackendStats,
  ] = useState(null)


  useEffect(() => {

    async function loadDashboardData() {

      try {

        setLoading(true)

        setBackendError(false)


        const [
          backendAlerts,
          statistics,
        ] = await Promise.all([
          fetchAlerts(),
          fetchAlertStatistics(),
        ])


        setAlerts(
          backendAlerts
        )

        setBackendStats(
          statistics
        )

      } catch (error) {

        console.error(
          'Backend connection failed:',
          error
        )

        setBackendError(true)

      } finally {

        setLoading(false)

      }

    }


    loadDashboardData()


    const disconnectStream =
      connectToAlertStream(
        (newAlert) => {

          setAlerts(
            (currentAlerts) => {

              const exists =
                currentAlerts.some(
                  (alert) =>
                    alert.alert_id ===
                    newAlert.alert_id
                )


              if (exists) {
                return currentAlerts
              }


              return [
                newAlert,
                ...currentAlerts,
              ]

            }
          )


          fetchAlertStatistics()
            .then((statistics) => {

              setBackendStats(
                statistics
              )

            })
            .catch((error) => {

              console.error(
                'Failed to refresh statistics:',
                error
              )

            })

        },
        setStreamConnected
      )


    return () => {
      disconnectStream()
    }

  }, [])


  const statistics =
    useMemo(() => {

      if (backendStats) {
        return backendStats
      }


      const totalAlerts =
        alerts.length


      const critical =
        alerts.filter(
          (alert) =>
            alert.severity ===
            'CRITICAL'
        ).length


      const high =
        alerts.filter(
          (alert) =>
            alert.severity ===
            'HIGH'
        ).length


      const medium =
        alerts.filter(
          (alert) =>
            alert.severity ===
            'MEDIUM'
        ).length


      const low =
        alerts.filter(
          (alert) =>
            alert.severity ===
            'LOW'
        ).length


      return {
        total_alerts:
          totalAlerts,

        critical,

        high,

        medium,

        low,

        threat_types: {},
      }

    }, [
      backendStats,
      alerts,
    ])


  const averageConfidence =
    alerts.length > 0
      ? alerts.reduce(
          (sum, alert) =>
            sum +
            alert.confidence,
          0
        ) / alerts.length
      : 0


  return (
    <div className="app">

      <Header />


      <main className="dashboard-content">

        {backendError && (

          <div className="backend-error">

            Backend connection failed.
            Make sure Anika's Flask
            server is running on port 5000.

          </div>

        )}


        <section className="stats-grid">

          <StatCard
            type="flows"
            title="TOTAL FLOWS"
            value="N/A"
            change="Backend metric"
            changeLabel="not available"
          />


          <StatCard
            type="threats"
            title="THREATS DETECTED"
            value={
              loading
                ? '...'
                : statistics.total_alerts
            }
            change="Live"
            changeLabel={
              streamConnected
                ? 'LIVE BACKEND'
                : 'BACKEND DATA'
            }
          />


          <StatCard
            type="highRisk"
            title="HIGH RISK ALERTS"
            value={
              loading
                ? '...'
                : (
                    statistics.critical +
                    statistics.high
                  )
            }
            change="Critical + High"
            changeLabel="backend alerts"
          />


          <StatCard
            type="confidence"
            title="AVG CONFIDENCE"
            value={
              loading
                ? '...'
                : `${(
                    averageConfidence *
                    100
                  ).toFixed(1)}%`
            }
            change="Detection score"
            changeLabel="backend alerts"
          />

        </section>


        <div className="charts-grid">

          <ThreatActivity
            alerts={alerts}
          />

          <ThreatDistribution
            alerts={alerts}
          />

        </div>


        <AlertTable
          alerts={alerts}
          loading={loading}
          onSelectAlert={
            setSelectedAlert
          }
        />

      </main>


      <AlertDetails
        alert={selectedAlert}
        onClose={() =>
          setSelectedAlert(null)
        }
      />

    </div>
  )
}


export default App