import {
  useEffect,
  useMemo,
  useState,
  useCallback,
} from 'react'

import './styles/App.css'

import Header from './components/Header'
import RealTrafficAnalysis from './components/RealTrafficAnalysis'
import StatCard from './components/StatCard'
import ThreatActivity from './components/ThreatActivity'
import ThreatDistribution from './components/ThreatDistribution'
import AlertTable from './components/AlertTable'
import AttackSimulator from './components/AttackSimulator'
import AlertDetails from './components/AlertDetails'
import ToastNotification from './components/ToastNotification'

import {
  fetchAlerts,
  fetchAlertStatistics,
  connectToAlertStream,
} from './services/alertService'

function App() {
  const [alerts, setAlerts] = useState([])
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [loading, setLoading] = useState(true)
  const [streamState, setStreamState] = useState('connected')
  const [backendStats, setBackendStats] = useState(null)
  const [highlightAlertId, setHighlightAlertId] = useState(null)
  const [currentToast, setCurrentToast] = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [investigateTargetIp, setInvestigateTargetIp] = useState(null)
  const [mitreFilter, setMitreFilter] = useState('')

  const loadDashboardData = useCallback(async () => {
    try {
      setLoading(true)
      const [backendAlerts, statistics] = await Promise.all([
        fetchAlerts(),
        fetchAlertStatistics(),
      ])
      setAlerts(backendAlerts)
      setBackendStats(statistics)
    } catch (error) {
      console.error('Failed to load dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }, [])

  const handleManualRefresh = async () => {
    setRefreshing(true)
    try {
      await loadDashboardData()
    } finally {
      setTimeout(() => setRefreshing(false), 500)
    }
  }

  // Real-time SSE Stream Listener
  useEffect(() => {
    loadDashboardData()

    const disconnectStream = connectToAlertStream(
      (newAlert) => {
        setAlerts((current) => {
          const exists = current.some((a) => a.alert_id === newAlert.alert_id)
          if (exists) return current
          return [newAlert, ...current]
        })

        // Highlight newly ingested row
        setHighlightAlertId(newAlert.alert_id)
        setTimeout(() => {
          setHighlightAlertId((cur) => (cur === newAlert.alert_id ? null : cur))
        }, 4000)

        // Show clean Toast
        setCurrentToast({ alert: newAlert })

        // Refresh statistics
        fetchAlertStatistics()
          .then((stats) => setBackendStats(stats))
          .catch((err) => console.error('Failed to refresh stats on SSE event:', err))
      },
      (status) => setStreamState(status)
    )

    return () => {
      disconnectStream()
    }
  }, [loadDashboardData])

  // Statistics
  const statistics = useMemo(() => {
    if (backendStats) return backendStats

    const total = alerts.length
    const critical = alerts.filter((a) => a.severity === 'CRITICAL').length
    const high = alerts.filter((a) => a.severity === 'HIGH').length
    return {
      total_alerts: total,
      critical,
      high,
    }
  }, [backendStats, alerts])

  const threatLevel = useMemo(() => {
    if (statistics.critical > 0) return 'CRITICAL'
    if (statistics.high > 0) return 'ELEVATED'
    if (statistics.total_alerts > 0) return 'GUARDED'
    return 'NOMINAL'
  }, [statistics])

  const threatLevelVariant = useMemo(() => {
    if (threatLevel === 'CRITICAL') return 'threat-critical'
    if (threatLevel === 'ELEVATED') return 'threat-elevated'
    return 'threat-guarded'
  }, [threatLevel])

  const systemStatus = streamState === 'connected' ? 'ONLINE (RX DIODE)' : 'STANDBY (RX DIODE)'
  const observedFlowsCount = statistics.observed_flows ?? (alerts.length > 0 ? alerts.length : 0)

  return (
    <div className="clean-soc-app">
      {/* Real-time Toast */}
      <ToastNotification
        toast={currentToast}
        onDismiss={() => setCurrentToast(null)}
        onViewAlert={(a) => {
          setSelectedAlert(a)
          setCurrentToast(null)
        }}
      />

      {/* Header */}
      <Header
        streamState={streamState}
        onRefresh={handleManualRefresh}
        refreshing={refreshing}
      />

      {/* Hero Section: Real Traffic Analysis */}
      <div id="real-traffic-analysis-section">
        <RealTrafficAnalysis
          onSelectAlert={setSelectedAlert}
          alerts={alerts}
          targetIp={investigateTargetIp}
        />
      </div>

      {/* 4 KPIs: Professional SOC Metrics */}
      <section className="kpi-row">
        <StatCard
          title="SYSTEM STATUS"
          value={loading ? '...' : systemStatus}
          variant="system"
        />
        <StatCard
          title="THREAT LEVEL"
          value={loading ? '...' : threatLevel}
          variant={threatLevelVariant}
        />
        <StatCard
          title="ACTIVE ALERTS"
          value={loading ? '...' : statistics.total_alerts}
          variant="alerts"
        />
        <StatCard
          title="OBSERVED FLOWS"
          value={loading ? '...' : observedFlowsCount}
          variant="flows"
        />
      </section>

      {/* 2-Column Main Visualization Area */}
      <section className="viz-row">
        <ThreatActivity alerts={alerts} />
        <ThreatDistribution alerts={alerts} />
      </section>

      {/* Hero Live Threat Detection Log */}
      <div id="alert-table-section">
        <AlertTable
          alerts={alerts}
          loading={loading}
          onSelectAlert={setSelectedAlert}
          highlightAlertId={highlightAlertId}
          externalSearch={mitreFilter}
        />
      </div>

      {/* Secondary Bottom Section: Demo / Test Environment (Safe Simulation) */}
      <AttackSimulator />

      {/* Right-Side Investigation Drawer */}
      <AlertDetails
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onInvestigateIp={(ip) => {
          setInvestigateTargetIp(ip)
          // Smooth scroll to RealTrafficAnalysis section
          const el = document.getElementById('real-traffic-analysis-section')
          if (el) el.scrollIntoView({ behavior: 'smooth' })
        }}
        onFilterMitre={(techId) => {
          setMitreFilter(techId)
          // Smooth scroll to AlertTable section
          const el = document.getElementById('alert-table-section')
          if (el) el.scrollIntoView({ behavior: 'smooth' })
        }}
      />
    </div>
  )
}

export default App