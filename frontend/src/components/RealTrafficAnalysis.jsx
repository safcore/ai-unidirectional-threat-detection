import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Search,
  ShieldCheck,
  AlertTriangle,
  UploadCloud,
  FileCode,
  ExternalLink,
  Cpu,
  Activity,
  CheckCircle2,
  XCircle,
  X,
  HelpCircle,
  Play,
  ChevronDown,
  ChevronUp,
  Clock,
  Sparkles,
  ShieldAlert,
} from 'lucide-react'
import {
  analyzeIP,
  replayPCAP,
  uploadPCAP,
  startSafeTestTraffic,
  inspectLiveTraffic,
  normalizeAlert,
  requestAIAnalysis,
} from '../services/alertService'

function formatErrorMessage(err, fallback = 'Operation failed') {
  const msg = err?.message || String(err || '')
  if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('Network request failed')) {
    return 'Backend service unreachable. Ensure the NETRION backend is running on port 5000.'
  }
  return msg || fallback
}

export default function RealTrafficAnalysis({ onSelectAlert, alerts = [], targetIp = null }) {
  const [ipInput, setIpInput] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [errorMsg, setErrorMsg] = useState('')
  const [statusNotice, setStatusNotice] = useState(null)
  const [actionLoading, setActionLoading] = useState(false)
  const [showRiskBreakdown, setShowRiskBreakdown] = useState(false)
  const [aiAdvisoryData, setAiAdvisoryData] = useState(null)
  const [aiAdvisoryLoading, setAiAdvisoryLoading] = useState(false)
  const [aiAdvisoryError, setAiAdvisoryError] = useState(null)
  const fileInputRef = useRef(null)

  const handleAnalyze = useCallback(async (targetIp) => {
    const ip = (targetIp || ipInput).trim()
    setErrorMsg('')
    setStatusNotice(null)
    setAiAdvisoryData(null)
    setAiAdvisoryError(null)

    // Basic IPv4 format validation
    const ipv4Regex =
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    if (!ipv4Regex.test(ip)) {
      setErrorMsg(`Invalid IP address format: '${ip}'. Please enter a valid IPv4 address.`)
      return
    }

    try {
      setAnalyzing(true)
      const res = await analyzeIP(ip)
      setResult(res)
    } catch (err) {
      console.error('IP Analysis error:', err)
      setErrorMsg(formatErrorMessage(err, 'Failed to analyze IP address'))
    } finally {
      setAnalyzing(false)
    }
  }, [ipInput])

  useEffect(() => {
    if (targetIp) {
      setIpInput(targetIp)
      handleAnalyze(targetIp)
    }
  }, [targetIp, handleAnalyze])

  const handleReplayPCAP = async () => {
    try {
      setActionLoading(true)
      setErrorMsg('')
      setStatusNotice(null)
      const res = await replayPCAP()
      setStatusNotice({
        type: 'success',
        text: `PCAP Ingest Complete: ${res.packets_processed || 'N/A'} packets, ${res.flows_extracted || 'N/A'} flows evaluated across passive interface.`,
      })
      setTimeout(() => setStatusNotice(null), 7000)
    } catch (err) {
      setErrorMsg(formatErrorMessage(err, 'PCAP replay failed'))
    } finally {
      setActionLoading(false)
    }
  }

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return

    try {
      setActionLoading(true)
      setErrorMsg('')
      setStatusNotice(null)
      const res = await uploadPCAP(file)
      setStatusNotice({
        type: 'success',
        text: `Custom PCAP Ingested: ${res.filename} (${res.packets_processed} packets, ${res.flows_extracted} flows, ${res.threats_detected} threats detected).`,
      })
      setTimeout(() => setStatusNotice(null), 7000)
    } catch (err) {
      setErrorMsg(formatErrorMessage(err, 'PCAP upload failed'))
    } finally {
      setActionLoading(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const handleStartSafeTestTraffic = async () => {
    try {
      setActionLoading(true)
      setErrorMsg('')
      setStatusNotice(null)
      const res = await startSafeTestTraffic()
      setStatusNotice({
        type: 'success',
        text: `Safe Test Traffic Ingested: ${res.flows_ingested} flows evaluated (${res.alerts_generated} threats detected and streamed to live log).`,
      })
      setTimeout(() => setStatusNotice(null), 7000)
    } catch (err) {
      setErrorMsg(formatErrorMessage(err, 'Failed to start safe test traffic'))
    } finally {
      setActionLoading(false)
    }
  }

  const handleInspectLive = async () => {
    try {
      setActionLoading(true)
      setErrorMsg('')
      setStatusNotice(null)
      const res = await inspectLiveTraffic()
      const totalF = res.total_flows ?? 'N/A'
      const totalP = res.total_packets ?? 'N/A'
      setStatusNotice({
        type: 'info',
        text: `Live Ingress Mirror (${res.interface || 'diode0'}): ${totalP} packets observed, ${totalF} active flows in memory.`,
      })
      setTimeout(() => setStatusNotice(null), 7000)
    } catch (err) {
      setErrorMsg(formatErrorMessage(err, 'Live traffic check failed'))
    } finally {
      setActionLoading(false)
    }
  }

  const handleViewInvestigation = (alertIdToView = null) => {
    if (!result) return

    const targetAlertId = alertIdToView || result.alert_id

    if (targetAlertId) {
      const match = alerts.find((a) => a.alert_id === targetAlertId)
      if (match) {
        onSelectAlert(match)
        return
      }
    }

    if (result.full_alert) {
      const norm = normalizeAlert(result.full_alert)
      if (targetAlertId) norm.alert_id = targetAlertId
      onSelectAlert(norm)
      return
    }

    const syntheticAlert = normalizeAlert({
      alert_id: targetAlertId || `INSPECT-${result.ip.replace(/\./g, '-')}`,
      timestamp: new Date().toISOString(),
      threat: result.threat || 'Observed Host Traffic',
      severity: result.severity || 'LOW',
      confidence: result.confidence || 0.85,
      source_ip: result.ip,
      destination_ip: result.traffic_evidence?.destination_ips?.[0] || result.evidence?.dst_ip || '10.0.0.1',
      source_port: result.traffic_evidence?.source_ports?.[0] || result.evidence?.src_port || 54321,
      destination_port: result.traffic_evidence?.destination_ports?.[0] || result.evidence?.dst_port || 80,
      protocol: Object.keys(result.traffic_evidence?.protocol_distribution || {})[0] || result.evidence?.protocol || 'TCP',
      mitre: result.mitre || {
        tactic: 'None',
        technique: 'None',
        technique_name: 'No Adversarial Behavior',
      },
      evidence: result.evidence || {
        decision_reason: 'Observed traffic evaluated through M3/M4 pipeline.',
      },
    })

    onSelectAlert(syntheticAlert)
  }

  const handleAskNemotron = async () => {
    if (!result || aiAdvisoryLoading) return
    setAiAdvisoryLoading(true)
    setAiAdvisoryError(null)

    try {
      const candidateAlert = result.full_alert || {
        alert_id: result.alert_id || `IP-${result.ip.replace(/\./g, '-')}`,
        timestamp: new Date().toISOString(),
        threat_class: result.threat || 'Observed Network Traffic',
        severity: result.severity || 'LOW',
        confidence: result.confidence || 0.85,
        source: {
          ip: result.ip,
          port: result.traffic_evidence?.source_ports?.[0] || 0,
        },
        destination: {
          ip: result.traffic_evidence?.destination_ips?.[0] || '10.0.0.1',
          port: result.traffic_evidence?.destination_ports?.[0] || 80,
        },
        protocol:
          Object.keys(result.traffic_evidence?.protocol_distribution || {})[0] || 'TCP',
        evidence: {
          decision_reason: `IP Investigation for ${result.ip}: ${result.attack_behaviors?.join(', ') || 'Observed flows'}`,
          anomaly_score: result.dual_engine?.behavioral_anomaly_detection?.anomaly_score || 0.5,
          iocs: [{ ioc_type: 'IPv4', value: result.ip, reputation: result.is_threat ? 'MALICIOUS' : 'BENIGN' }],
        },
      }

      const data = await requestAIAnalysis(candidateAlert.alert_id, null, candidateAlert)
      if (data && data.ai_analysis) {
        if (data.ai_analysis.error) {
          setAiAdvisoryError(data.ai_analysis.error)
        } else {
          setAiAdvisoryData(data.ai_analysis)
        }
      } else if (data && data.summary) {
        setAiAdvisoryData({
          ai_summary: data.summary,
          threat_assessment: data.threat_assessment || 'Threat analysis complete.',
          why_suspicious: data.why_suspicious || [],
          recommended_actions: data.recommended_actions || [],
        })
      } else {
        setAiAdvisoryError('AI advisory returned no structured data.')
      }
    } catch (err) {
      console.warn('Nemotron IP advisory error:', err)
      setAiAdvisoryError(err.message || 'AI Assistance Unavailable')
    } finally {
      setAiAdvisoryLoading(false)
    }
  }

  return (
    <section className="real-traffic-section">
      <div className="real-traffic-header">
        <div className="real-traffic-title-wrap">
          <h2>REAL TRAFFIC ANALYSIS</h2>
          <p className="real-traffic-subtitle">
            Analyze observed traffic by source IP
          </p>
        </div>

        <div className="real-traffic-actions">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            accept=".pcap,.pcapng"
            style={{ display: 'none' }}
          />

          <button
            type="button"
            className="secondary-flow-btn"
            onClick={handleInspectLive}
            disabled={actionLoading}
            title="Inspect passive live traffic status"
          >
            <Activity size={14} />
            <span>LIVE TRAFFIC</span>
          </button>

          <button
            type="button"
            className="secondary-flow-btn"
            onClick={() => fileInputRef.current?.click()}
            disabled={actionLoading}
            title="Upload a PCAP capture file"
          >
            <UploadCloud size={14} />
            <span>UPLOAD PCAP</span>
          </button>

          <button
            type="button"
            className="secondary-flow-btn"
            onClick={handleReplayPCAP}
            disabled={actionLoading}
            title="Replay test_capture.pcap through ML detection pipeline"
          >
            <FileCode size={14} />
            <span>REPLAY PCAP</span>
          </button>

          <button
            type="button"
            className="secondary-flow-btn primary-test-flow-btn"
            onClick={handleStartSafeTestTraffic}
            disabled={actionLoading}
            title="Feed representative traffic (benign + threat) through detection pipeline"
          >
            <Play size={13} />
            <span>{actionLoading ? 'GENERATING TEST TRAFFIC...' : 'START SAFE TEST TRAFFIC'}</span>
          </button>

        </div>
      </div>

      {statusNotice && (
        <div className={`status-notice-banner notice-${statusNotice.type}`}>
          <CheckCircle2 size={16} />
          <span>{statusNotice.text}</span>
        </div>
      )}

      {errorMsg && (
        <div className="status-notice-banner notice-error">
          <XCircle size={16} />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Input Search Row & Quick Sample IPs */}
      <div className="traffic-input-container">
        <div className="traffic-search-bar">
          <div className="traffic-input-wrap">
            <Search size={16} className="search-input-icon" />
            <input
              type="text"
              className="traffic-ip-input"
              placeholder="Enter Source IP to analyze observed traffic..."
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleAnalyze()
              }}
              disabled={analyzing}
            />
            {ipInput && (
              <button
                type="button"
                className="clear-ip-btn"
                onClick={() => {
                  setIpInput('')
                  setResult(null)
                  setErrorMsg('')
                }}
                title="Clear input"
                aria-label="Clear input"
              >
                <X size={14} />
              </button>
            )}
          </div>

          <button
            type="button"
            className="traffic-analyze-btn"
            onClick={() => handleAnalyze()}
            disabled={analyzing || !ipInput.trim()}
          >
            {analyzing ? (
              <>
                <Cpu size={14} className="spin-icon" />
                <span>ANALYZING OBSERVED FLOWS...</span>
              </>
            ) : (
              <>
                <Search size={14} />
                <span>ANALYZE IP</span>
              </>
            )}
          </button>
        </div>

        {/* Quick Demo Helpers */}
        <div className="sample-ips-bar">
          <span className="sample-label">Quick Demo Helpers (Optional):</span>
          <div className="sample-tags">
            <button
              type="button"
              className={`sample-tag tag-threat ${ipInput === '192.168.1.105' ? 'tag-selected' : ''}`}
              onClick={() => {
                setIpInput('192.168.1.105')
                handleAnalyze('192.168.1.105')
              }}
              title="Threat source observed in test traffic (SYN Flood / DDoS)"
            >
              <span className="tag-dot" />
              192.168.1.105 (Threat Flow)
            </button>

            <button
              type="button"
              className={`sample-tag tag-safe ${ipInput === '192.168.1.50' ? 'tag-selected' : ''}`}
              onClick={() => {
                setIpInput('192.168.1.50')
                handleAnalyze('192.168.1.50')
              }}
              title="Benign HTTP client in test_capture.pcap"
            >
              <span className="tag-dot" />
              192.168.1.50 (Benign PCAP)
            </button>

            <button
              type="button"
              className={`sample-tag tag-unobserved ${ipInput === '8.8.8.8' ? 'tag-selected' : ''}`}
              onClick={() => {
                setIpInput('8.8.8.8')
                handleAnalyze('8.8.8.8')
              }}
              title="Unobserved external IP with zero traffic"
            >
              <span className="tag-dot" />
              8.8.8.8 (Unobserved IP)
            </button>
          </div>
        </div>
      </div>

      {/* Real-time Result Card / Comprehensive Dossier */}
      {result && (
        <div
          className={`traffic-result-card ${
            result.status === 'NO_OBSERVED_TRAFFIC'
              ? 'result-unobserved'
              : (result.status === 'THREAT_DETECTED' || result.is_threat)
              ? 'result-malicious'
              : 'result-benign'
          }`}
        >
          {result.status === 'NO_OBSERVED_TRAFFIC' ? (
            <div className="unobserved-card-body">
              <div className="unobserved-header">
                <div className="verdict-badge verdict-unobserved">
                  <HelpCircle size={15} />
                  <span>NO OBSERVED TRAFFIC</span>
                </div>
                <span className="ip-mono">{result.ip}</span>
              </div>
              <p className="unobserved-msg">
                NETRION has not observed sufficient traffic evidence for {result.ip}. No malicious or benign verdict is generated.
              </p>
              <div className="unobserved-kpis">
                <div className="unobserved-kpi">
                  <span className="kpi-k">CONFIDENCE</span>
                  <span className="kpi-v">N/A</span>
                </div>
                <div className="unobserved-kpi">
                  <span className="kpi-k">RISK SCORE</span>
                  <span className="kpi-v">N/A</span>
                </div>
                <div className="unobserved-kpi">
                  <span className="kpi-k">OBSERVED PACKETS</span>
                  <span className="kpi-v">0</span>
                </div>
                <div className="unobserved-kpi">
                  <span className="kpi-k">OBSERVED FLOWS</span>
                  <span className="kpi-v">0</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="ip-dossier-wrap">
              {/* DOSSIER HEADER */}
              <div className="result-card-header">
                <div className="result-title-left">
                  <div className="dossier-tag-group">
                    <span className="observed-dot-badge">● TRAFFIC OBSERVED</span>
                    {(result.status === 'THREAT_DETECTED' || result.is_threat) ? (
                      <div className="verdict-badge verdict-threat">
                        <AlertTriangle size={15} />
                        <span>THREAT DETECTED</span>
                      </div>
                    ) : (
                      <div className="verdict-badge verdict-safe">
                        <ShieldCheck size={15} />
                        <span>OBSERVED (BENIGN)</span>
                      </div>
                    )}
                  </div>
                  <div className="result-ip-display">
                    <h3 className="dossier-title">IP INVESTIGATION — {result.ip}</h3>
                    <span className="ip-role-tag">Source Host Dossier</span>
                  </div>
                </div>

                <div className="result-actions-right">
                  {(result.status === 'THREAT_DETECTED' || result.is_threat) && (
                    <button
                      type="button"
                      className="view-investigation-btn"
                      onClick={() => handleViewInvestigation()}
                      title="Open complete investigation drawer for this threat"
                    >
                      <span>VIEW DETAILED INVESTIGATION</span>
                      <ExternalLink size={13} />
                    </button>
                  )}
                </div>
              </div>

              {/* 4 TOP DOSSIER CARDS (INCLUDING 0-100 RISK SCORE) */}
              <div className="dossier-exec-row">
                <div className="dossier-card risk-card">
                  <div className="dossier-card-head">
                    <span className="dossier-card-title">RISK SCORE</span>
                    <span className={`risk-level-badge risk-${(result.risk_engine?.level || result.severity || 'LOW').toLowerCase()}`}>
                      {result.risk_engine?.level || result.severity || 'LOW'}
                    </span>
                  </div>
                  <div className="risk-score-value">
                    <span className="score-number">
                      {result.risk_score != null ? Math.round(result.risk_score) : 'N/A'}
                    </span>
                    <span className="score-max">/100</span>
                  </div>
                  <button
                    type="button"
                    className="risk-formula-toggle-btn"
                    onClick={() => setShowRiskBreakdown(!showRiskBreakdown)}
                  >
                    <span>{showRiskBreakdown ? 'Hide Formula' : 'Show Formula & Breakdown'}</span>
                    {showRiskBreakdown ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                  </button>
                </div>

                <div className="dossier-card">
                  <span className="dossier-card-title">ML CONFIDENCE</span>
                  <div className="dossier-card-main-val text-cyan">
                    {result.confidence != null ? `${Math.round(result.confidence * 100)}%` : 'N/A'}
                  </div>
                  <span className="dossier-card-sub">Ensemble Certainty</span>
                </div>

                <div className="dossier-card">
                  <span className="dossier-card-title">CLASSIFICATION</span>
                  <div className={`dossier-card-main-val font-bold ${(result.status === 'THREAT_DETECTED' || result.is_threat) ? 'text-threat' : 'text-safe'}`}>
                    {result.threat || 'Benign / Normal Traffic'}
                  </div>
                  <span className="dossier-card-sub">Verdict Classification</span>
                </div>

                <div className="dossier-card">
                  <span className="dossier-card-title">SEVERITY LEVEL</span>
                  <div className="dossier-card-main-val">
                    <span className={`metric-badge sev-${(result.severity || 'LOW').toLowerCase()}`}>
                      {result.severity || 'LOW'}
                    </span>
                  </div>
                  <span className="dossier-card-sub">Impact Assessment</span>
                </div>
              </div>

              {/* TOGGLEABLE RISK SCORE FORMULA BREAKDOWN */}
              {showRiskBreakdown && result.risk_engine && (
                <div className="risk-breakdown-panel">
                  <div className="risk-formula-desc">
                    <span className="formula-label">FORMULA:</span>
                    <code>Score = 0.25 × ML_Conf + 0.20 × Anom + 0.25 × Sev + 0.15 × Intel + 0.15 × Freq</code>
                  </div>
                  <div className="risk-components-grid">
                    <div className="risk-comp-item">
                      <div className="comp-head">
                        <span>ML Confidence (25%)</span>
                        <span className="comp-val">{Math.round(result.risk_engine.components?.confidence || 0)}%</span>
                      </div>
                      <div className="comp-bar-track">
                        <div
                          className="comp-bar-fill fill-cyan"
                          style={{ width: `${Math.min(100, Math.round(result.risk_engine.components?.confidence || 0))}%` }}
                        />
                      </div>
                    </div>

                    <div className="risk-comp-item">
                      <div className="comp-head">
                        <span>Behavioral Anomaly (20%)</span>
                        <span className="comp-val">{Math.round(result.risk_engine.components?.anomaly || 0)}%</span>
                      </div>
                      <div className="comp-bar-track">
                        <div
                          className="comp-bar-fill fill-amber"
                          style={{ width: `${Math.min(100, Math.round(result.risk_engine.components?.anomaly || 0))}%` }}
                        />
                      </div>
                    </div>

                    <div className="risk-comp-item">
                      <div className="comp-head">
                        <span>Severity Weight (25%)</span>
                        <span className="comp-val">{Math.round(result.risk_engine.components?.severity || 0)}%</span>
                      </div>
                      <div className="comp-bar-track">
                        <div
                          className="comp-bar-fill fill-red"
                          style={{ width: `${Math.min(100, Math.round(result.risk_engine.components?.severity || 0))}%` }}
                        />
                      </div>
                    </div>

                    <div className="risk-comp-item">
                      <div className="comp-head">
                        <span>Threat Intel (15%)</span>
                        <span className="comp-val">{Math.round(result.risk_engine.components?.threat_intel || 0)}%</span>
                      </div>
                      <div className="comp-bar-track">
                        <div
                          className="comp-bar-fill fill-purple"
                          style={{ width: `${Math.min(100, Math.round(result.risk_engine.components?.threat_intel || 0))}%` }}
                        />
                      </div>
                    </div>

                    <div className="risk-comp-item">
                      <div className="comp-head">
                        <span>Flow Frequency (15%)</span>
                        <span className="comp-val">{Math.round(result.risk_engine.components?.flow_frequency || 0)}%</span>
                      </div>
                      <div className="comp-bar-track">
                        <div
                          className="comp-bar-fill fill-blue"
                          style={{ width: `${Math.min(100, Math.round(result.risk_engine.components?.flow_frequency || 0))}%` }}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* ATTACK BEHAVIORS IDENTIFIED */}
              <div className="behaviors-wrap">
                <span className="behaviors-label">BEHAVIORS IDENTIFIED:</span>
                <div className="behaviors-list">
                  {result.attack_behaviors && result.attack_behaviors.length > 0 ? (
                    result.attack_behaviors.map((b, idx) => (
                      <span key={idx} className="behavior-chip">
                        {b}
                      </span>
                    ))
                  ) : (
                    <span className="behavior-chip chip-neutral">
                      BASELINE_CONFORMANT_FLOWS
                    </span>
                  )}
                </div>
              </div>

              {/* COMPLETE TRAFFIC EVIDENCE GRID */}
              <div className="traffic-evidence-section">
                <span className="section-mini-title">OBSERVED TRAFFIC EVIDENCE</span>
                <div className="evidence-grid">
                  <div className="evidence-item">
                    <span className="ev-k">TOTAL PACKETS</span>
                    <span className="ev-v">{result.traffic_evidence?.total_packets ?? result.evidence?.packet_count ?? 0}</span>
                  </div>
                  <div className="evidence-item">
                    <span className="ev-k">TOTAL FLOWS</span>
                    <span className="ev-v">{result.traffic_evidence?.total_flows ?? result.evidence?.flow_count ?? 0}</span>
                  </div>
                  <div className="evidence-item">
                    <span className="ev-k">TOTAL BYTES</span>
                    <span className="ev-v">{result.traffic_evidence?.total_bytes ?? result.evidence?.byte_count ?? 0} B</span>
                  </div>
                  <div className="evidence-item">
                    <span className="ev-k">FIRST SEEN</span>
                    <span className="ev-v mono">{result.traffic_evidence?.first_seen ? new Date(result.traffic_evidence.first_seen).toLocaleTimeString() : 'Recent'}</span>
                  </div>
                  <div className="evidence-item">
                    <span className="ev-k">LAST SEEN</span>
                    <span className="ev-v mono">{result.traffic_evidence?.last_seen ? new Date(result.traffic_evidence.last_seen).toLocaleTimeString() : 'Active'}</span>
                  </div>
                  <div className="evidence-item">
                    <span className="ev-k">SOURCE PORTS</span>
                    <span className="ev-v mono">
                      {result.traffic_evidence?.source_ports?.slice(0, 6).join(', ') || 'Dynamic'}
                    </span>
                  </div>
                  <div className="evidence-item">
                    <span className="ev-k">TARGET PORTS</span>
                    <span className="ev-v mono">
                      {result.traffic_evidence?.destination_ports?.slice(0, 6).join(', ') || 'N/A'}
                    </span>
                  </div>
                  <div className="evidence-item">
                    <span className="ev-k">TARGET DESTINATIONS</span>
                    <span className="ev-v mono">
                      {result.traffic_evidence?.destination_ips?.slice(0, 3).join(', ') || 'N/A'}
                    </span>
                  </div>
                  <div className="evidence-item">
                    <span className="ev-k">PROTOCOL DISTRIB</span>
                    <span className="ev-v mono">
                      {result.traffic_evidence?.protocol_distribution
                        ? Object.entries(result.traffic_evidence.protocol_distribution)
                            .map(([p, cnt]) => `${p}:${cnt}`)
                            .join(' ')
                        : 'TCP'}
                    </span>
                  </div>
                  <div className="evidence-item">
                    <span className="ev-k">CONNECTION STATS</span>
                    <span className="ev-v mono">
                      SYN: {result.traffic_evidence?.connection_statistics?.syn_count || 0} | FIN: {result.traffic_evidence?.connection_statistics?.fin_count || 0} | Avg: {result.traffic_evidence?.connection_statistics?.avg_payload_bytes || 0}B
                    </span>
                  </div>
                </div>
              </div>

              {/* DUAL DETECTION ENGINE: KNOWN PATTERN VS BEHAVIORAL ANOMALY */}
              {result.dual_engine && (
                <div className="dual-engine-grid">
                  <div className="engine-card">
                    <div className="engine-card-head">
                      <ShieldCheck size={14} className="text-cyan" />
                      <span>KNOWN PATTERN DETECTION</span>
                    </div>
                    <div className="engine-details">
                      <div className="engine-row">
                        <span className="eng-k">Engine:</span>
                        <span className="eng-v">{result.dual_engine.known_pattern_detection?.engine}</span>
                      </div>
                      <div className="engine-row">
                        <span className="eng-k">Pattern Class:</span>
                        <span className="eng-v font-bold">{result.dual_engine.known_pattern_detection?.threat_class || 'None'}</span>
                      </div>
                      <div className="engine-row">
                        <span className="eng-k">Rule Trigger:</span>
                        <span className="eng-v mono">{result.dual_engine.known_pattern_detection?.signature_rule}</span>
                      </div>
                      <div className="engine-row">
                        <span className="eng-k">MITRE Tech:</span>
                        <span className="eng-v mono text-cyan">{result.dual_engine.known_pattern_detection?.mitre_technique || 'N/A'}</span>
                      </div>
                    </div>
                  </div>

                  <div className="engine-card">
                    <div className="engine-card-head">
                      <ShieldAlert size={14} className="text-amber" />
                      <span>BEHAVIORAL ANOMALY DETECTION</span>
                    </div>
                    <div className="engine-details">
                      <div className="engine-row">
                        <span className="eng-k">Engine:</span>
                        <span className="eng-v">{result.dual_engine.behavioral_anomaly_detection?.engine}</span>
                      </div>
                      <div className="engine-row">
                        <span className="eng-k">Anomaly Score:</span>
                        <span className="eng-v font-bold text-amber">
                          {result.dual_engine.behavioral_anomaly_detection?.anomaly_score != null
                            ? Number(result.dual_engine.behavioral_anomaly_detection.anomaly_score).toFixed(3)
                            : '0.000'}
                        </span>
                      </div>
                      <div className="engine-row">
                        <span className="eng-k">Indicators:</span>
                        <span className="eng-v">
                          {result.dual_engine.behavioral_anomaly_detection?.anomalous_indicators?.join(', ') || 'Within baseline'}
                        </span>
                      </div>
                      <div className="engine-row">
                        <span className="eng-k">Engine Status:</span>
                        <span className="eng-v text-green">{result.dual_engine.behavioral_anomaly_detection?.status || 'Active'}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* CHRONOLOGICAL INVESTIGATION TIMELINE */}
              {result.investigation_timeline && result.investigation_timeline.length > 0 && (
                <div className="dossier-timeline-section">
                  <div className="timeline-title-row">
                    <Clock size={14} className="text-cyan" />
                    <span className="section-mini-title">CHRONOLOGICAL INVESTIGATION TIMELINE</span>
                  </div>
                  <div className="dossier-timeline-list">
                    {result.investigation_timeline.map((item, idx) => (
                      <div key={idx} className="dossier-timeline-item">
                        <div className="timeline-time mono">
                          {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '00:00:00'}
                        </div>
                        <div className="timeline-node-marker" />
                        <div className="timeline-body">
                          <span className="timeline-event-name">{item.event}</span>
                          <p className="timeline-detail">{item.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ASSOCIATED ALERTS LIST */}
              {result.associated_alerts && result.associated_alerts.length > 0 && (
                <div className="associated-alerts-section">
                  <span className="section-mini-title">ASSOCIATED THREAT ALERTS ({result.associated_alerts.length})</span>
                  <div className="associated-alerts-list">
                    {result.associated_alerts.map((al, idx) => (
                      <button
                        key={idx}
                        type="button"
                        className="associated-alert-chip"
                        onClick={() => handleViewInvestigation(al.alert_id)}
                        title={`Click to view alert ${al.alert_id} in investigation drawer`}
                      >
                        <span className="alert-id-mono">{al.alert_id}</span>
                        <span className="alert-threat-name">{al.threat}</span>
                        <span className={`pill-sev-mini sev-${al.severity.toLowerCase()}`}>{al.severity}</span>
                        <ExternalLink size={11} />
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* NEMOTRON ADVISORY ASSISTANT */}
              <div className="dossier-ai-box">
                <div className="ai-box-head">
                  <div className="ai-box-title">
                    <Sparkles size={15} className="text-cyan" />
                    <span>NVIDIA NEMOTRON ADVISORY ASSISTANT</span>
                  </div>
                  <button
                    type="button"
                    className="ask-nemotron-btn"
                    onClick={handleAskNemotron}
                    disabled={aiAdvisoryLoading}
                  >
                    {aiAdvisoryLoading ? (
                      <>
                        <Cpu size={13} className="spin-icon" />
                        <span>CONSULTING NEMOTRON...</span>
                      </>
                    ) : (
                      <>
                        <Sparkles size={13} />
                        <span>ASK NEMOTRON: WHY IS THIS IP SUSPICIOUS?</span>
                      </>
                    )}
                  </button>
                </div>

                {aiAdvisoryError && (
                  <div className="ai-error-notice">
                    <AlertTriangle size={13} />
                    <span>{aiAdvisoryError}</span>
                  </div>
                )}

                {aiAdvisoryData && (
                  <div className="ai-advisory-content">
                    <p className="ai-summary-text">{aiAdvisoryData.ai_summary}</p>
                    <div className="ai-details-grid">
                      {aiAdvisoryData.why_suspicious && aiAdvisoryData.why_suspicious.length > 0 && (
                        <div className="ai-detail-block">
                          <span className="ai-detail-label">BEHAVIORAL RISK RATIONALE</span>
                          <ul className="ai-bullets">
                            {aiAdvisoryData.why_suspicious.map((item, idx) => (
                              <li key={idx}>{item}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {aiAdvisoryData.recommended_actions && aiAdvisoryData.recommended_actions.length > 0 && (
                        <div className="ai-detail-block">
                          <span className="ai-detail-label">RECOMMENDED INCIDENT RESPONSE</span>
                          <ul className="ai-bullets">
                            {aiAdvisoryData.recommended_actions.map((item, idx) => (
                              <li key={idx}>{item}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
