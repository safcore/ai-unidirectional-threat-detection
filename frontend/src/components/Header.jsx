import { useState, useEffect } from 'react'
import { ShieldCheck, RefreshCw } from 'lucide-react'
import { checkAIHealth, fetchBackendHealthDetails } from '../services/alertService'

function Header({
  streamState = 'connected',
  onRefresh,
  refreshing = false,
}) {
  const [backendHealth, setBackendHealth] = useState({ healthy: true })
  const [aiHealth, setAiHealth] = useState({ available: false })

  useEffect(() => {
    let mounted = true

    async function pollHealth() {
      try {
        const [bHealth, aHealth] = await Promise.all([
          fetchBackendHealthDetails(),
          checkAIHealth(),
        ])
        if (mounted) {
          setBackendHealth(bHealth)
          setAiHealth(aHealth)
        }
      } catch {
        if (mounted) {
          setBackendHealth({ healthy: false })
          setAiHealth({ available: false })
        }
      }
    }

    pollHealth()
    const interval = setInterval(pollHealth, 15000)
    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [])

  return (
    <header className="clean-header">
      <div className="header-left">
        <div className="brand-badge">
          <ShieldCheck size={22} className="text-cyan" />
        </div>
        <div className="brand-text">
          <div className="title-row">
            <h1 className="netrion-logo">NETRION</h1>
            <span className="platform-tag">CYBER SOC</span>
          </div>
          <p className="subtitle">Cyber Threat Detection & Investigation</p>
        </div>
      </div>

      <div className="header-right">
        <div className="status-item">
          <span className={`dot ${backendHealth.healthy ? 'dot-green' : 'dot-red'}`}></span>
          <span>Backend {backendHealth.healthy ? 'Online' : 'Offline'}</span>
        </div>

        <div className="status-item">
          <span
            className={`dot ${
              streamState === 'connected'
                ? 'dot-green pulse'
                : streamState === 'reconnecting'
                ? 'dot-amber pulse'
                : 'dot-red'
            }`}
          ></span>
          <span>
            {streamState === 'connected'
              ? 'SSE Stream Active'
              : streamState === 'reconnecting'
              ? 'Reconnecting...'
              : 'Detection Offline'}
          </span>
        </div>

        <div className="status-item">
          <span className={`dot ${aiHealth.available ? 'dot-green' : 'dot-dim'}`}></span>
          <span>Nemotron {aiHealth.available ? 'Active' : 'Standby'}</span>
        </div>

        <button
          className={`sync-btn ${refreshing ? 'spinning' : ''}`}
          onClick={onRefresh}
          title="Refresh dashboard"
          aria-label="Refresh dashboard"
        >
          <RefreshCw size={14} />
        </button>
      </div>
    </header>
  )
}

export default Header