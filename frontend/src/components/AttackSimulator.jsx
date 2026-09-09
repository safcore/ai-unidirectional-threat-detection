import { useState } from 'react'
import { Play } from 'lucide-react'
import { triggerAttackSimulation } from '../services/alertService'

const THREAT_OPTIONS = [
  { id: 'syn_flood', label: 'SYN FLOOD', mitre: 'T1498', proto: 'TCP' },
  { id: 'port_scan', label: 'PORT SCAN', mitre: 'T1046', proto: 'TCP' },
  { id: 'dns_tunnel', label: 'DNS TUNNEL', mitre: 'T1071.004', proto: 'UDP' },
  { id: 'c2_beacon', label: 'C2 BEACON', mitre: 'T1071.001', proto: 'TCP' },
  { id: 'data_exfiltration', label: 'DATA EXFILTRATION', mitre: 'T1048', proto: 'TCP' },
  { id: 'tls_metadata', label: 'TLS ANOMALY', mitre: 'T1573', proto: 'TCP' },
]

function AttackSimulator() {
  const [selectedId, setSelectedId] = useState('syn_flood')
  const [loading, setLoading] = useState(false)
  const [statusMsg, setStatusMsg] = useState('')

  const active = THREAT_OPTIONS.find((t) => t.id === selectedId) || THREAT_OPTIONS[0]

  const handleSimulate = async () => {
    try {
      setLoading(true)
      setStatusMsg('Simulating...')
      await triggerAttackSimulation(selectedId, {
        target: '127.0.0.1',
        duration: 2,
        simulation: true,
      })
      setStatusMsg('Threat simulated • Alert streamed via SSE')
      setTimeout(() => setStatusMsg(''), 4000)
    } catch (err) {
      console.error('Simulation error:', err)
      setStatusMsg(err.message || 'Simulation error')
      setTimeout(() => setStatusMsg(''), 4000)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="sim-panel secondary-demo-panel">
      <div className="sim-header">
        <div>
          <h2>DEMO / TEST ENVIRONMENT</h2>
          <p className="sim-sub">Secondary test harness: inject simulated attack flows through the detection pipeline on-demand.</p>
        </div>
        <span className="sim-tag">Secondary Fallback • Manual Trigger Only</span>
      </div>

      <div className="sim-threat-grid">
        {THREAT_OPTIONS.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`threat-btn ${selectedId === t.id ? 'active' : ''}`}
            onClick={() => setSelectedId(t.id)}
            disabled={loading}
          >
            <span className="threat-btn-name">{t.label}</span>
            <span className="threat-btn-mitre">{t.mitre}</span>
          </button>
        ))}
      </div>

      <div className="sim-action-row">
        <div className="sim-config-chips">
          <div className="sim-chip">
            <span className="chip-k">SOURCE</span>
            <span className="chip-v">Auto Generated</span>
          </div>
          <div className="sim-chip">
            <span className="chip-k">DESTINATION</span>
            <span className="chip-v">SOC Loopback</span>
          </div>
          <div className="sim-chip">
            <span className="chip-k">PROTOCOL</span>
            <span className="chip-v">{active.proto}</span>
          </div>
        </div>

        <div className="sim-btn-wrap">
          <button
            type="button"
            className="sim-execute-btn"
            onClick={handleSimulate}
            disabled={loading}
          >
            {loading ? (
              <span>INGESTING...</span>
            ) : (
              <>
                <Play size={14} />
                <span>SIMULATE THREAT</span>
              </>
            )}
          </button>
        </div>
      </div>

      <div className="sim-footer">
        <span className="sim-helper">Traffic is processed through the live M1 → M5 pipeline.</span>
        {statusMsg && <span className="sim-live-status">{statusMsg}</span>}
      </div>
    </div>
  )
}

export default AttackSimulator
