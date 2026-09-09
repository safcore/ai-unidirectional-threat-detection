import { useState, useEffect, useMemo } from 'react'
import {
  Search,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'

function AlertTable({
  alerts = [],
  loading = false,
  onSelectAlert,
  highlightAlertId = null,
  externalSearch = '',
}) {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('ALL')
  const [threat, setThreat] = useState('ALL')
  const [sortBy, setSortBy] = useState('time_desc')
  const [page, setPage] = useState(1)
  const pageSize = 10

  // Sync external search if provided
  useEffect(() => {
    if (externalSearch) {
      setSearch(externalSearch)
      setPage(1)
    }
  }, [externalSearch])

  const availableThreats = useMemo(() => {
    const set = new Set()
    alerts.forEach((a) => {
      if (a.threat_class) set.add(a.threat_class)
    })
    return Array.from(set).sort()
  }, [alerts])

  const filteredAlerts = useMemo(() => {
    const q = search.trim().toLowerCase()

    const list = alerts.filter((alert) => {
      const matchSearch =
        !q ||
        alert.alert_id.toLowerCase().includes(q) ||
        alert.threat_class.toLowerCase().includes(q) ||
        alert.source.ip.toLowerCase().includes(q) ||
        alert.destination.ip.toLowerCase().includes(q) ||
        (alert.mitre?.technique_id && alert.mitre.technique_id.toLowerCase().includes(q))

      const matchSev = severity === 'ALL' || alert.severity === severity
      const matchThr = threat === 'ALL' || alert.threat_class === threat

      return matchSearch && matchSev && matchThr
    })

    list.sort((a, b) => {
      if (sortBy === 'time_desc') return new Date(b.timestamp) - new Date(a.timestamp)
      if (sortBy === 'time_asc') return new Date(a.timestamp) - new Date(b.timestamp)
      if (sortBy === 'conf_desc') return (b.confidence || 0) - (a.confidence || 0)
      if (sortBy === 'sev_desc') {
        const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }
        return (rank[b.severity] || 0) - (rank[a.severity] || 0)
      }
      return 0
    })

    return list
  }, [alerts, search, severity, threat, sortBy])

  const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / pageSize))
  const paginated = useMemo(() => {
    const start = (page - 1) * pageSize
    return filteredAlerts.slice(start, start + pageSize)
  }, [filteredAlerts, page, pageSize])

  const formatTime = (ts) => {
    if (!ts) return '—'
    const d = new Date(ts)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  }

  return (
    <section className="hero-log-section">
      <div className="log-header">
        <div>
          <h2>LIVE THREAT DETECTION</h2>
          <p className="log-sub">Real-time alerts from the unidirectional detection pipeline</p>
        </div>

        <div className="log-live-badge">
          <span className="dot dot-green pulse"></span>
          <span>LIVE</span>
        </div>
      </div>

      <div className="log-controls">
        <div className="control-search">
          <Search size={14} className="text-dim" />
          <input
            type="text"
            placeholder="Search ID, IP, Threat, MITRE..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
          />
        </div>

        <div className="control-selects">
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value)
              setPage(1)
            }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={threat}
            onChange={(e) => {
              setThreat(e.target.value)
              setPage(1)
            }}
          >
            <option value="ALL">All Threats</option>
            {availableThreats.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>

          <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
            <option value="time_desc">Newest First</option>
            <option value="time_asc">Oldest First</option>
            <option value="conf_desc">Confidence</option>
            <option value="sev_desc">Severity</option>
          </select>
        </div>
      </div>

      <div className="log-table-wrap">
        <table className="clean-table">
          <thead>
            <tr>
              <th style={{ width: '90px' }}>SEVERITY</th>
              <th style={{ width: '100px' }}>ALERT ID</th>
              <th>THREAT</th>
              <th style={{ width: '110px' }}>CONFIDENCE</th>
              <th>SOURCE</th>
              <th>DESTINATION</th>
              <th style={{ width: '90px' }}>MITRE</th>
              <th style={{ width: '90px' }}>TIME</th>
              <th style={{ width: '70px', textAlign: 'right' }}>ACTION</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="9" className="td-empty">Loading alerts...</td>
              </tr>
            ) : paginated.length === 0 ? (
              <tr>
                <td colSpan="9" className="td-empty">No alerts match the criteria.</td>
              </tr>
            ) : (
              paginated.map((alert) => {
                const isNew = alert.alert_id === highlightAlertId
                const pct = Math.round((alert.confidence || 0) * 100)
                const sev = (alert.severity || 'MEDIUM').toUpperCase()

                return (
                  <tr
                    key={alert.alert_id}
                    className={`table-row ${isNew ? 'row-highlight' : ''}`}
                    onClick={() => onSelectAlert(alert)}
                  >
                    <td>
                      <span className={`pill-sev sev-${sev.toLowerCase()}`}>{sev}</span>
                    </td>
                    <td>
                      <span className="cell-mono text-white">{alert.alert_id}</span>
                    </td>
                    <td>
                      <span className="cell-threat">{alert.threat_class}</span>
                    </td>
                    <td>
                      <div className="conf-bar-wrap">
                        <div className="conf-track">
                          <div
                            className={`conf-fill ${pct >= 90 ? 'conf-high' : pct >= 70 ? 'conf-med' : 'conf-low'}`}
                            style={{ width: `${pct}%` }}
                          ></div>
                        </div>
                        <span className="conf-text">{pct}%</span>
                      </div>
                    </td>
                    <td>
                      <span className="cell-mono text-muted">{alert.source.ip}:{alert.source.port}</span>
                    </td>
                    <td>
                      <span className="cell-mono text-muted">{alert.destination.ip}:{alert.destination.port}</span>
                    </td>
                    <td>
                      <span className="pill-mitre">{alert.mitre?.technique_id || 'T1498'}</span>
                    </td>
                    <td>
                      <span className="cell-time">{formatTime(alert.timestamp)}</span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        type="button"
                        className="btn-view"
                        onClick={(e) => {
                          e.stopPropagation()
                          onSelectAlert(alert)
                        }}
                      >
                        VIEW
                      </button>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="log-pagination">
          <span className="page-text">
            Showing {paginated.length} of {filteredAlerts.length} alerts
          </span>
          <div className="page-nav">
            <button
              className="page-btn"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              aria-label="Previous page"
            >
              <ChevronLeft size={14} />
            </button>
            <span className="page-current">{page} / {totalPages}</span>
            <button
              className="page-btn"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              aria-label="Next page"
            >
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </section>
  )
}

export default AlertTable