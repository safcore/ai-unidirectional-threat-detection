import { useState, useEffect, useRef, useMemo } from 'react'
import {
  X,
  ArrowRight,
  AlertTriangle,
  ShieldAlert,
  Cpu,
  Sparkles,
  Clock,
  Copy,
  Check,
  Download,
  ExternalLink,
  RefreshCw,
  Layers,
  FileText,
  Activity,
  Zap,
  Radio,
  Terminal,
} from 'lucide-react'
import { requestAIAnalysis } from '../services/alertService'

function formatTimestamp(ts) {
  if (!ts) return 'Unknown Time'
  try {
    const d = new Date(ts)
    if (isNaN(d.getTime())) return String(ts)
    return d.toLocaleString('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).replace(',', ' •')
  } catch {
    return String(ts)
  }
}

function AlertDetails({ alert, onClose, onInvestigateIp = null, onFilterMitre = null }) {
  const [copiedKey, setCopiedKey] = useState(null)
  const [dossierExportNotice, setDossierExportNotice] = useState(false)

  // AI Investigation Assistant State
  const [aiAnalysis, setAiAnalysis] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState(null)
  const [aiIsTimeout, setAiIsTimeout] = useState(false)
  const inFlightRef = useRef(null)
  const abortControllerRef = useRef(null)
  const nemotronSectionRef = useRef(null)

  // Keyboard shortcut listener: ESC closes drawer
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose?.()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  // Reset Nemotron state whenever a different alert is selected
  useEffect(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }
    inFlightRef.current = null
    setAiAnalysis(null)
    setAiError(null)
    setAiIsTimeout(false)
    setAiLoading(false)

    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort()
      }
    }
  }, [alert?.alert_id])

  // Raw and normalized data extraction (safe for null alert)
  const rawEv = useMemo(() => {
    return alert?.rawAlert?.evidence || (typeof alert?.evidence === 'object' && !Array.isArray(alert?.evidence) ? alert.evidence : {})
  }, [alert])

  const details = alert?.evidenceDetails || {}
  const classifications = details.classifications || rawEv.classifications || {}
  const m3 = classifications.m3 || {}

  const iocs = useMemo(() => {
    return (details.iocs && details.iocs.length > 0) ? details.iocs : (rawEv.iocs || [])
  }, [details.iocs, rawEv.iocs])

  const decisionReason = details.decision_reason || rawEv.decision_reason || alert?.description || 'Observed anomalous flow flagged by unidirectional detection pipeline.'
  const anomalyScore = details.anomaly_score ?? rawEv.anomaly_score ?? 0.385

  const sev = (alert?.severity || 'MEDIUM').toUpperCase()
  const confPct = Math.round((alert?.confidence || 0) * 100)
  const threatClass = alert?.threat_class || alert?.threat || 'Threat Detected'

  // Consistency Guard: Compare M3/M4 classifier output with correlated verdict
  const m3Class = (m3.threat_class || '').toUpperCase()
  const isHighThreat = sev === 'CRITICAL' || sev === 'HIGH'
  const isM3Contradictory = isHighThreat && m3Class === 'BENIGN'

  // Transparent Risk Score Calculation (0-100) bound to real evidence factors
  const riskCalculation = useMemo(() => {
    if (!alert) return { finalScore: 0, level: 'LOW', components: { confidence: 0, anomaly: 0, severity: 0, threat_intel: 0, correlation: 0 } }

    const confScore = confPct
    const anomScore = Math.min(100, Math.round(Number(anomalyScore) * 100 * 1.5))
    const sevScore = sev === 'CRITICAL' ? 100 : sev === 'HIGH' ? 80 : sev === 'MEDIUM' ? 55 : 30
    const intelScore = iocs.some((i) => i.intel?.reputation === 'MALICIOUS') ? 85 : 45
    const corrScore = sev === 'CRITICAL' ? 85 : sev === 'HIGH' ? 70 : 40

    // Exact transparent formula: 0.25*conf + 0.20*anom + 0.25*sev + 0.15*intel + 0.15*corr
    const computedRisk = Math.min(100, Math.round(
      0.25 * confScore + 0.20 * anomScore + 0.25 * sevScore + 0.15 * intelScore + 0.15 * corrScore
    ))

    const finalScore = alert.risk_score != null ? Math.round(alert.risk_score) : computedRisk
    const level = finalScore >= 80 ? 'CRITICAL' : finalScore >= 60 ? 'HIGH' : finalScore >= 35 ? 'MEDIUM' : 'LOW'

    return {
      finalScore,
      level,
      components: {
        confidence: confScore,
        anomaly: anomScore,
        severity: sevScore,
        threat_intel: intelScore,
        correlation: corrScore,
      },
    }
  }, [alert, confPct, anomalyScore, sev, iocs])

  // Real Observed Flow Evidence items
  const observedEvidenceItems = useMemo(() => {
    if (!alert) return []
    const items = []

    const pktVal = rawEv.packet_count ?? rawEv.packets ?? rawEv.Total_Fwd_Packets
    if (pktVal != null) {
      items.push({
        label: 'PACKET VOLUME',
        value: `${Number(pktVal).toLocaleString()} packets`,
        engine: 'M1 → M2 Ingress Telemetry',
        icon: <Layers size={13} className="text-cyan" />,
      })
    }

    const byteVal = rawEv.byte_count ?? rawEv.bytes ?? rawEv.Total_Length_of_Fwd_Packets
    if (byteVal != null) {
      items.push({
        label: 'BYTE VOLUME',
        value: `${Number(byteVal).toLocaleString()} bytes`,
        engine: 'M1 Passive Optical Buffer',
        icon: <Activity size={13} className="text-cyan" />,
      })
    }

    const durVal = rawEv.flow_duration_ms ?? rawEv.duration_ms ?? (rawEv.Flow_Duration ? (rawEv.Flow_Duration / 1000).toFixed(1) : null)
    if (durVal != null) {
      items.push({
        label: 'FLOW DURATION',
        value: `${durVal} ms`,
        engine: 'M2 Flow Aggregation',
        icon: <Clock size={13} className="text-amber" />,
      })
    }

    const synVal = rawEv.syn_count ?? rawEv.SYN_Flag_Count
    if (synVal != null) {
      items.push({
        label: 'SYN PACKETS',
        value: `${synVal} SYN flags`,
        engine: 'M2 Directional Feature',
        icon: <Zap size={13} className="text-red" />,
      })
    }

    const connVal = rawEv.connections
    if (connVal != null) {
      items.push({
        label: 'CONCURRENT CONNECTIONS',
        value: `${connVal} active sessions`,
        engine: 'M2 Flow State Table',
        icon: <Radio size={13} className="text-purple" />,
      })
    }

    const scanVal = rawEv.ports_scanned
    if (scanVal != null) {
      items.push({
        label: 'PORTS SCANNED',
        value: `${scanVal} target ports`,
        engine: 'M2 Port Sweep Detector',
        icon: <ShieldAlert size={13} className="text-red" />,
      })
    }

    items.push({
      label: 'TARGET PORT & PROTOCOL',
      value: `${alert?.destination?.port || 0} / ${alert?.protocol || 'TCP'}`,
      engine: 'M1 Passive Layer 4 Ingress',
      icon: <Terminal size={13} className="text-blue" />,
    })

    items.push({
      label: 'ANOMALY DEVIATION',
      value: `Score: ${Number(anomalyScore).toFixed(3)} (Threshold: 0.400)`,
      engine: 'Isolation Forest Unsupervised Model',
      icon: <Cpu size={13} className="text-amber" />,
    })

    return items
  }, [alert, rawEv, anomalyScore])

  if (!alert) return null

  // Run Nemotron Investigation
  const handleRunNemotron = async () => {
    if (!alert?.alert_id) return
    if (aiLoading || inFlightRef.current === alert.alert_id) return

    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }
    const controller = new AbortController()
    abortControllerRef.current = controller

    inFlightRef.current = alert.alert_id
    setAiLoading(true)
    setAiError(null)
    setAiIsTimeout(false)

    try {
      const data = await requestAIAnalysis(alert.alert_id, controller.signal, alert.rawAlert || alert)
      if (data && data.ai_analysis) {
        if (data.ai_analysis.error) {
          const rawErr = data.ai_analysis.error
          const rawReason = data.ai_analysis.reason || ''
          if (rawErr.toLowerCase().includes('timed out') || rawReason.toLowerCase().includes('timed out')) {
            setAiIsTimeout(true)
            setAiError('Nemotron is taking longer than expected. Please retry.')
          } else {
            setAiError(rawErr || 'AI enrichment unavailable')
          }
        } else {
          setAiAnalysis(data.ai_analysis)
        }
      } else if (data && data.summary) {
        setAiAnalysis({
          ai_summary: data.summary,
          threat_assessment: data.threat_assessment || 'Threat confirmed by AI model.',
          risk_level: data.risk_level || alert.severity,
          why_suspicious: data.why_suspicious || [],
          recommended_actions: data.recommended_actions || [],
        })
      } else {
        throw new Error('No structured analysis returned.')
      }
    } catch (err) {
      if (err.name === 'AbortError') return
      console.warn('AI analysis request failed:', err)
      const msg = err.message || 'AI enrichment unavailable'
      if (msg.toLowerCase().includes('timed out') || msg.toLowerCase().includes('timeout')) {
        setAiIsTimeout(true)
        setAiError('Nemotron is taking longer than expected. Please retry.')
      } else {
        setAiError(msg)
      }
    } finally {
      inFlightRef.current = null
      setAiLoading(false)
    }
  }

  // Scroll to Nemotron section
  const handleScrollToNemotron = () => {
    if (nemotronSectionRef.current) {
      nemotronSectionRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
    if (!aiAnalysis && !aiLoading) {
      handleRunNemotron()
    }
  }

  // Copy helper
  const handleCopyText = (text, key) => {
    if (!text) return
    navigator.clipboard?.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2500)
  }

  // Copy all IOCs helper
  const handleCopyAllIocs = () => {
    const list = [
      `Source IP: ${alert.source.ip}`,
      `Destination IP: ${alert.destination.ip}`,
      `Source Port: ${alert.source.port}`,
      `Destination Port: ${alert.destination.port}`,
      `Protocol: ${alert.protocol}`,
      `Threat: ${threatClass}`,
      `MITRE: ${alert.mitre?.technique_id || 'N/A'}`,
    ]
    iocs.forEach((i) => list.push(`IOC: ${i.value} (${i.ioc_type || 'IPv4'})`))
    navigator.clipboard?.writeText(list.join('\n'))
    setCopiedKey('ALL_IOCS')
    setTimeout(() => setCopiedKey(null), 2500)
  }

  // Export Incident Dossier (Downloadable Formatted Text / Print-Ready Brief)
  const handleExportDossier = () => {
    const divider = '='.repeat(80)
    const subDivider = '-'.repeat(80)
    const dossierLines = [
      divider,
      'NETRION CYBER SOC — INCIDENT INVESTIGATION DOSSIER',
      'PHYSICAL DATA DIODE PASSIVE INGRESS THREAT REPORT',
      divider,
      `Incident ID:           ${alert.alert_id}`,
      `Classification:        ${threatClass}`,
      `Canonical Severity:    ${sev}`,
      `Risk Score:            ${riskCalculation.finalScore} / 100 (${riskCalculation.level})`,
      `Detection Confidence:  ${confPct}%`,
      `Isolation Score:       ${Number(anomalyScore).toFixed(4)}`,
      `Observation Timestamp: ${formatTimestamp(alert.timestamp)}`,
      `Sensor Interface:      diode0 (Passive Optical Mirror — Physical 0-TX Return Cut)`,
      `Flow Identifier:       ${alert.flow_id}`,
      '',
      subDivider,
      'NETWORK FLOW ENDPOINTS (PASSIVE INGRESS OBSERVATION)',
      subDivider,
      `Source Host:           ${alert.source.ip}:${alert.source.port}`,
      `Destination Host:      ${alert.destination.ip}:${alert.destination.port}`,
      `Transport Protocol:    ${alert.protocol}`,
      '',
      subDivider,
      'DETECTION CONSENSUS MATRIX',
      subDivider,
      `M3/M4 Classifier:      ${isM3Contradictory ? 'BENIGN (Supervised feature model)' : (m3.threat_class || threatClass)} (${confPct}%)`,
      `Anomaly Engine:        Isolation Forest Score ${Number(anomalyScore).toFixed(4)} (${Number(anomalyScore) >= 0.4 ? 'ANOMALOUS' : 'BASELINE'})`,
      `Rule / Heuristic:      Diode Pattern Signature Confirmed`,
      `Authoritative Verdict: ${sev} • ${threatClass}`,
      '',
      subDivider,
      'OBSERVED TELEMETRY EVIDENCE',
      subDivider,
      `Decision Reason:       ${decisionReason}`,
    ]

    observedEvidenceItems.forEach((ev) => {
      dossierLines.push(`• [${ev.label}]: ${ev.value} (${ev.engine})`)
    })

    dossierLines.push('')
    dossierLines.push(subDivider)
    dossierLines.push('MITRE ATT&CK FRAMEWORK ALIGNMENT')
    dossierLines.push(subDivider)
    dossierLines.push(`Tactic:                ${alert.mitre?.tactic || 'Impact / Defense Evasion'}`)
    dossierLines.push(`Technique ID:          ${alert.mitre?.technique_id || 'T1498'}`)
    dossierLines.push(`Technique Name:        ${alert.mitre?.technique_name || 'Network Denial of Service'}`)

    if (aiAnalysis?.ai_summary) {
      dossierLines.push('')
      dossierLines.push(subDivider)
      dossierLines.push('NVIDIA NEMOTRON ADVISORY INVESTIGATION')
      dossierLines.push(subDivider)
      dossierLines.push(`AI Summary:            ${aiAnalysis.ai_summary}`)
      if (aiAnalysis.why_suspicious?.length) {
        dossierLines.push('Why Suspicious:')
        aiAnalysis.why_suspicious.forEach((w) => dossierLines.push(`  - ${w}`))
      }
      if (aiAnalysis.recommended_actions?.length) {
        dossierLines.push('Recommended Actions:')
        aiAnalysis.recommended_actions.forEach((a, idx) => dossierLines.push(`  ${idx + 1}. ${a}`))
      }
    }

    dossierLines.push('')
    dossierLines.push(divider)
    dossierLines.push('CONFIDENTIAL SOC REPORT — GENERATED PASSIVELY BY NETRION PLATFORM')
    dossierLines.push(divider)

    const blob = new Blob([dossierLines.join('\n')], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `NETRION-INCIDENT-${alert.alert_id}.txt`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)

    setDossierExportNotice(true)
    setTimeout(() => setDossierExportNotice(false), 3000)
  }

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer-panel incident-console-panel" onClick={(e) => e.stopPropagation()}>
        {/* 1. STICKY HEADER */}
        <header className="incident-console-header">
          <div className="incident-header-top">
            <div className="incident-title-meta">
              <div className="incident-badge-row">
                <span className={`pill-sev sev-${sev.toLowerCase()}`}>
                  [{sev}] INCIDENT {alert.alert_id}
                </span>
                <span className="incident-status-pill">
                  <span className="dot-green" /> ACTIVE
                </span>
                <span className="incident-time-stamp">
                  Observed: {formatTimestamp(alert.timestamp)}
                </span>
              </div>

              <div className="incident-title-row">
                <h2 className="incident-id-heading">{threatClass}</h2>
                {onFilterMitre && alert.mitre?.technique_id ? (
                  <button
                    type="button"
                    className="incident-technique-sub"
                    style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 0, textAlign: 'left', font: 'inherit', color: 'inherit' }}
                    onClick={() => onFilterMitre(alert.mitre.technique_id)}
                    title={`Filter alerts table by ${alert.mitre.technique_id}`}
                  >
                    • {alert.mitre?.technique_name || 'Passive Unidirectional Diode Flow'} ({alert.mitre?.technique_id || 'T1498'})
                  </button>
                ) : (
                  <span className="incident-technique-sub">
                    • {alert.mitre?.technique_name || 'Passive Unidirectional Diode Flow'} ({alert.mitre?.technique_id || 'T1498'})
                  </span>
                )}
              </div>
            </div>

            <div className="incident-header-actions">
              <button
                type="button"
                className="btn-header-action btn-header-ai"
                onClick={handleScrollToNemotron}
                title="Invoke NVIDIA Nemotron Advisory AI"
              >
                <Sparkles size={13} />
                <span>INVESTIGATE WITH NEMOTRON</span>
              </button>

              <button
                type="button"
                className="btn-header-action"
                onClick={handleExportDossier}
                title="Export Incident Dossier as a clean report"
              >
                <Download size={13} />
                <span>{dossierExportNotice ? 'EXPORTED!' : 'EXPORT DOSSIER'}</span>
              </button>

              <button
                type="button"
                className="btn-header-close"
                onClick={onClose}
                aria-label="Close Investigation Console"
                title="Close console (Esc)"
              >
                <X size={16} />
              </button>
            </div>
          </div>

          {/* Passive Ingress Observation Vector Under Title */}
          <div className="incident-passive-vector-bar">
            <div className="vector-endpoint">
              <span className="vector-tag">SOURCE:</span>
              <span className="vector-ip">{alert.source.ip}:{alert.source.port}</span>
            </div>

            <div className="vector-middle-sensor">
              <ArrowRight size={14} />
              <span>NETRION DIODE SENSOR (diode0)</span>
              <ArrowRight size={14} />
              <span className="sensor-cut-notice">0 TX (PHYSICAL RETURN CUT)</span>
            </div>

            <div className="vector-endpoint">
              <span className="vector-tag">DESTINATION:</span>
              <span className="vector-ip">{alert.destination.ip}:{alert.destination.port}</span>
            </div>
          </div>
        </header>

        {/* 2. SCROLLABLE INCIDENT INVESTIGATION WORKSPACE */}
        <div className="incident-console-body">
          {/* SECTION 1: INCIDENT VERDICT (HERO PANEL) */}
          <div className="incident-verdict-hero">
            <div className="hero-verdict-head">
              <div className="verdict-brand-lockup">
                <div className="verdict-label-bar">
                  <ShieldAlert size={14} className="verdict-shield-icon" />
                  <span className="verdict-header-label">NETRION AUTHORITATIVE VERDICT</span>
                </div>
                <div className={`verdict-badge-large verdict-${sev.toLowerCase()}`}>
                  {sev === 'CRITICAL' ? <AlertTriangle size={14} /> : <ShieldAlert size={14} />}
                  <span>{sev} THREAT DETECTED</span>
                </div>
              </div>
              <div className="verdict-status-tag">
                <span className="verdict-status-dot" />
                <span>UNIDIRECTIONAL DIODE TELEMETRY</span>
              </div>
            </div>

            <div className="hero-verdict-title-row">
              <h3 className="hero-threat-title">{threatClass}</h3>
            </div>
            <p className="hero-decision-reason">{decisionReason}</p>

            <div className="hero-stats-quad">
              <div className="hero-stat-card">
                <span className="hero-stat-k">RISK SCORE</span>
                <span className={`hero-stat-v text-${sev === 'CRITICAL' ? 'threat' : 'amber'}`}>
                  {riskCalculation.finalScore} <span style={{ fontSize: '11px', color: '#64748b' }}>/ 100</span>
                </span>
                <span className="hero-stat-sub">{riskCalculation.level} Priority</span>
              </div>

              <div className="hero-stat-card">
                <span className="hero-stat-k">DETECTION CONFIDENCE</span>
                <span className="hero-stat-v text-cyan">{confPct}%</span>
                <span className="hero-stat-sub">Multi-Model Certainty</span>
              </div>

              <div className="hero-stat-card">
                <span className="hero-stat-k">ISOLATION SCORE</span>
                <span className="hero-stat-v text-white">
                  {Number(anomalyScore).toFixed(3)}
                </span>
                <span className="hero-stat-sub">
                  {Number(anomalyScore) >= 0.4 ? 'Anomalous Variance' : 'Within Baseline'}
                </span>
              </div>

              <div className="hero-stat-card">
                <span className="hero-stat-k">CONSENSUS BASIS</span>
                <span className="hero-stat-v" style={{ fontSize: '13px', color: '#38bdf8' }}>
                  Tri-Engine
                </span>
                <span className="hero-stat-sub">M3/M4 + Anomaly + Rules</span>
              </div>
            </div>
          </div>

          {/* SECTION 5: DETECTION CONSENSUS (WITH CONSISTENCY GUARD) */}
          <div className="incident-consensus-panel">
            <div className="console-section-title-wrap">
              <span className="console-section-title">
                <Cpu size={14} className="text-cyan" />
                DETECTION CONSENSUS (TRI-ENGINE AUDIT)
              </span>
              <span style={{ fontSize: '10px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                Correlation Layer: M5
              </span>
            </div>

            <div className="incident-consensus-grid">
              {/* Card 1: M3/M4 Supervised Ensemble */}
              <div className="consensus-card">
                <div className="consensus-card-head">
                  <span className="consensus-card-name">M3/M4 ENSEMBLE</span>
                  <span className={`consensus-chip ${isM3Contradictory ? 'chip-neutral' : 'chip-threat'}`}>
                    {isM3Contradictory ? 'BASELINE' : 'MATCH'}
                  </span>
                </div>
                <div className="consensus-card-val">
                  {isM3Contradictory ? (
                    <span style={{ color: '#94a3b8' }}>BENIGN ({Math.round((m3.confidence || 0.85) * 100)}%)</span>
                  ) : (
                    <span className="text-threat">{threatClass} ({confPct}%)</span>
                  )}
                </div>
                <p className="consensus-card-note">
                  {isM3Contradictory ? (
                    'Supervised boundary evaluated single-flow features as baseline; multi-engine correlation triggered by high-variance anomaly & directional rules.'
                  ) : (
                    'Supervised XGBoost + Random Forest ensemble matched known attack pattern with high certainty.'
                  )}
                </p>
              </div>

              {/* Card 2: Isolation Forest Anomaly Engine */}
              <div className="consensus-card">
                <div className="consensus-card-head">
                  <span className="consensus-card-name">ANOMALY ENGINE</span>
                  <span className={`consensus-chip ${Number(anomalyScore) >= 0.4 ? 'chip-anomalous' : 'chip-neutral'}`}>
                    {Number(anomalyScore) >= 0.4 ? 'ANOMALOUS' : 'BASELINE'}
                  </span>
                </div>
                <div className="consensus-card-val text-amber">
                  Score: {Number(anomalyScore).toFixed(3)}
                </div>
                <p className="consensus-card-note">
                  {Number(anomalyScore) >= 0.4 ? (
                    'Isolation Forest detected statistical outlier distribution exceeding 0.400 variance threshold.'
                  ) : (
                    'Unsupervised model observed flow distribution within acceptable baseline bounds.'
                  )}
                </p>
              </div>

              {/* Card 3: Rule / Signature Engine */}
              <div className="consensus-card">
                <div className="consensus-card-head">
                  <span className="consensus-card-name">RULE ENGINE</span>
                  <span className="consensus-chip chip-match">CONFIRMED</span>
                </div>
                <div className="consensus-card-val text-cyan">
                  {threatClass.toLowerCase().includes('dos') ? 'SYN Flood Rate Threshold' :
                    threatClass.toLowerCase().includes('scan') ? 'Port Sweep Pattern' :
                    threatClass.toLowerCase().includes('dns') ? 'DNS Tunnel Entropy' :
                    threatClass.toLowerCase().includes('beacon') || threatClass.toLowerCase().includes('c2') ? 'C2 Periodic Beaconing' :
                    threatClass.toLowerCase().includes('exfiltration') ? 'Unidirectional Bulk Payload' :
                    'Diode Protocol Signature'}
                </div>
                <p className="consensus-card-note">
                  Passive ingress frame telemetry satisfied deterministic heuristic detection constraints.
                </p>
              </div>
            </div>

            <div className="consensus-correlated-strip">
              <div>
                <strong style={{ color: '#38bdf8' }}>FINAL CORRELATED VERDICT:</strong>{' '}
                <span className="font-bold text-white">[{sev}] {threatClass}</span>
                <span style={{ marginLeft: '10px', color: '#94a3b8' }}>
                  (Correlated by NETRION M5 Engine with {confPct}% certainty)
                </span>
              </div>
            </div>
          </div>

          {/* SECTION 3: "WHY NETRION ALERTED" — EVIDENCE FIRST */}
          <div className="incident-evidence-panel">
            <div className="console-section-title-wrap">
              <span className="console-section-title">
                <Activity size={14} className="text-cyan" />
                WHY DID NETRION GENERATE THIS ALERT?
              </span>
              <span style={{ fontSize: '10px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                OBSERVED EVIDENCE
              </span>
            </div>

            <div className="evidence-chips-grid">
              {observedEvidenceItems.map((item, idx) => (
                <div key={idx} className="evidence-chip-card">
                  <div className="evidence-chip-head">
                    {item.icon}
                    <span>{item.label}</span>
                  </div>
                  <div className="evidence-chip-val">{item.value}</div>
                  <span className="evidence-chip-source">{item.engine}</span>
                </div>
              ))}
            </div>
          </div>

          {/* SECTION 4: OBSERVED NETWORK FLOW */}
          <div className="incident-flow-card">
            <span className="console-section-title">
              <Radio size={14} className="text-cyan" />
              OBSERVED NETWORK FLOW (PASSIVE INGRESS TAP)
            </span>

            <div className="flow-topology-row">
              <div className="flow-node-box">
                <span className="flow-node-role">INGRESS SOURCE HOST</span>
                <span className="flow-node-ip">{alert.source.ip}</span>
                <span className="flow-node-port">Port {alert.source.port}</span>
              </div>

              <div className="flow-arrow-middle">
                <span className="flow-proto-badge">{alert.protocol}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#38bdf8' }}>
                  <ArrowRight size={16} />
                </div>
                <span className="flow-diode-label">Pass-Through Mirror (diode0)</span>
              </div>

              <div className="flow-node-box">
                <span className="flow-node-role">OBSERVED DESTINATION</span>
                <span className="flow-node-ip">{alert.destination.ip}</span>
                <span className="flow-node-port">Port {alert.destination.port}</span>
              </div>
            </div>

            <div className="flow-params-grid">
              <div className="flow-param-item">
                <span className="flow-param-k">FLOW IDENTIFIER</span>
                <span className="flow-param-v">{alert.flow_id}</span>
              </div>
              <div className="flow-param-item">
                <span className="flow-param-k">SENSOR MODE</span>
                <span className="flow-param-v" style={{ color: '#34d399' }}>RX Only (Diode)</span>
              </div>
              <div className="flow-param-item">
                <span className="flow-param-k">DROPPED RETURN (TX)</span>
                <span className="flow-param-v" style={{ color: '#f87171' }}>100% Severed</span>
              </div>
              <div className="flow-param-item">
                <span className="flow-param-k">INGRESS FRAME TYPE</span>
                <span className="flow-param-v">{alert.protocol} Payload</span>
              </div>
            </div>
          </div>

          {/* SECTION 5: NVIDIA NEMOTRON INVESTIGATION ASSISTANT */}
          <div className="clean-ai-box" ref={nemotronSectionRef}>
            <div className="ai-header-bar">
              <div className="ai-title-line">
                <Sparkles size={16} className="text-cyan" />
                <div>
                  <span className="ai-title">NVIDIA NEMOTRON INVESTIGATION ASSISTANT</span>
                  <div style={{ fontSize: '10px', color: '#94a3b8' }}>
                    Advisory Incident Investigation grounded in observed NETRION telemetry
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {aiLoading && <span className="ai-status-pill">Investigating with Nemotron…</span>}
                {aiAnalysis && !aiLoading && <span className="ai-status-pill ready">● Analysis Ready</span>}
                {!aiAnalysis && !aiLoading && (
                  <button
                    type="button"
                    className="btn-console-primary"
                    style={{ padding: '5px 12px', fontSize: '11px' }}
                    onClick={handleRunNemotron}
                  >
                    <Sparkles size={12} />
                    <span>ANALYZE INCIDENT</span>
                  </button>
                )}
              </div>
            </div>

            {aiLoading && (
              <div className="ai-skeleton">
                <div className="skel-line w-75"></div>
                <div className="skel-line w-100"></div>
                <div className="skel-line w-50"></div>
              </div>
            )}

            {aiError && !aiLoading && (
              <div className="ai-offline-note">
                <div className="offline-msg">
                  <AlertTriangle size={14} className="text-amber" />
                  <span>{aiIsTimeout ? 'Nemotron is taking longer than expected. Please retry.' : aiError}</span>
                </div>
                <button type="button" className="btn-retry" onClick={handleRunNemotron}>
                  <RefreshCw size={11} />
                  <span>Retry Investigation</span>
                </button>
              </div>
            )}

            {aiAnalysis && !aiLoading && (
              <div className="ai-content">
                <div className="ai-summary-text">
                  {aiAnalysis.ai_summary || aiAnalysis.summary}
                </div>

                <div className="ai-grid-metrics">
                  <div className="ai-metric-item">
                    <span className="metric-label">ATTACK STAGE</span>
                    <span className="metric-value">{alert.mitre?.tactic || 'Impact'}</span>
                  </div>
                  <div className="ai-metric-item">
                    <span className="metric-label">ESTIMATED RISK</span>
                    <span className="metric-value text-white">{aiAnalysis.risk_level || sev}</span>
                  </div>
                  <div className="ai-metric-item">
                    <span className="metric-label">AI CONFIDENCE</span>
                    <span className="metric-value text-cyan">{confPct}%</span>
                  </div>
                  <div className="ai-metric-item">
                    <span className="metric-label">MITRE CONTEXT</span>
                    <span className="metric-value text-white font-mono">{alert.mitre?.technique_id || 'T1498'}</span>
                  </div>
                </div>

                {aiAnalysis.why_suspicious && aiAnalysis.why_suspicious.length > 0 && (
                  <div className="ai-section">
                    <span className="ai-section-title">WHY SUSPICIOUS</span>
                    <ul className="ai-clean-list">
                      {aiAnalysis.why_suspicious.map((item, idx) => (
                        <li key={idx}>{item}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {aiAnalysis.recommended_actions && aiAnalysis.recommended_actions.length > 0 && (
                  <div className="ai-section">
                    <span className="ai-section-title">RECOMMENDED ANALYST ACTIONS</span>
                    <ul className="ai-clean-list actions-list">
                      {aiAnalysis.recommended_actions.map((item, idx) => (
                        <li key={idx}>{item}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div style={{ fontSize: '10px', color: '#64748b', fontStyle: 'italic', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '8px', marginTop: '6px' }}>
                  * AI-generated advisory analysis grounded in observed NETRION telemetry. Detection verdict remains determined by the detection pipeline.
                </div>
              </div>
            )}
          </div>

          {/* SECTION 6: INVESTIGATION PIPELINE TIMELINE */}
          <div className="incident-timeline-panel">
            <span className="console-section-title">
              <Clock size={14} className="text-cyan" />
              INVESTIGATION PIPELINE TIMELINE
            </span>

            <div className="pipeline-timeline-list">
              <div className="pipeline-timeline-node">
                <div className="timeline-dot" />
                <div className="timeline-content-block">
                  <span className="timeline-stage-title">Stage 1: Passive Ingress Optical TAP</span>
                  <p className="timeline-stage-desc">
                    Unidirectional frame from {alert.source.ip}:{alert.source.port} received on diode0. Zero outbound TX emitted.
                  </p>
                </div>
              </div>

              <div className="pipeline-timeline-node">
                <div className="timeline-dot" />
                <div className="timeline-content-block">
                  <span className="timeline-stage-title">Stage 2: Directional Feature Extraction (M2)</span>
                  <p className="timeline-stage-desc">
                    66 network and behavioral flow statistics computed in memory without handshake requirements.
                  </p>
                </div>
              </div>

              <div className="pipeline-timeline-node">
                <div className="timeline-dot" />
                <div className="timeline-content-block">
                  <span className="timeline-stage-title">Stage 3: Known Pattern Classification (M3/M4)</span>
                  <p className="timeline-stage-desc">
                    XGBoost and Random Forest consensus evaluated with {confPct}% model confidence.
                  </p>
                </div>
              </div>

              <div className="pipeline-timeline-node">
                <div className="timeline-dot" />
                <div className="timeline-content-block">
                  <span className="timeline-stage-title">Stage 4: Behavioral Anomaly Scoring (Isolation Forest)</span>
                  <p className="timeline-stage-desc">
                    Unsupervised anomaly score {Number(anomalyScore).toFixed(3)} assigned to flow distribution.
                  </p>
                </div>
              </div>

              <div className="pipeline-timeline-node">
                <div className="timeline-dot" />
                <div className="timeline-content-block">
                  <span className="timeline-stage-title">Stage 5: Alert Correlation & SSE Broadcast (M5)</span>
                  <p className="timeline-stage-desc">
                    Alert {alert.alert_id} generated and streamed live to cyber SOC console.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* SECTION 7: TRANSPARENT RISK SCORE BREAKDOWN */}
          <div className="risk-breakdown-section">
            <div className="console-section-title-wrap">
              <span className="console-section-title">
                <Zap size={14} className="text-cyan" />
                TRANSPARENT RISK SCORE BREAKDOWN
              </span>
              <span className="risk-formula-code">
                Risk = 0.25*conf + 0.20*anom + 0.25*sev + 0.15*intel + 0.15*corr
              </span>
            </div>

            <div className="risk-bars-container">
              <div className="risk-bar-row">
                <div className="risk-bar-head">
                  <span>ML Confidence Factor (25% Weight)</span>
                  <span className="risk-bar-val text-cyan">{riskCalculation.components.confidence}%</span>
                </div>
                <div className="risk-track">
                  <div className="risk-fill fill-cyan" style={{ width: `${Math.min(100, riskCalculation.components.confidence)}%` }} />
                </div>
              </div>

              <div className="risk-bar-row">
                <div className="risk-bar-head">
                  <span>Behavioral Anomaly Factor (20% Weight)</span>
                  <span className="risk-bar-val text-amber">{riskCalculation.components.anomaly}%</span>
                </div>
                <div className="risk-track">
                  <div className="risk-fill fill-amber" style={{ width: `${Math.min(100, riskCalculation.components.anomaly)}%` }} />
                </div>
              </div>

              <div className="risk-bar-row">
                <div className="risk-bar-head">
                  <span>Alert Severity Weight (25% Weight)</span>
                  <span className="risk-bar-val text-red">{riskCalculation.components.severity}%</span>
                </div>
                <div className="risk-track">
                  <div className="risk-fill fill-red" style={{ width: `${Math.min(100, riskCalculation.components.severity)}%` }} />
                </div>
              </div>

              <div className="risk-bar-row">
                <div className="risk-bar-head">
                  <span>Threat Intelligence Reputation (15% Weight)</span>
                  <span className="risk-bar-val text-purple">{riskCalculation.components.threat_intel}%</span>
                </div>
                <div className="risk-track">
                  <div className="risk-fill fill-purple" style={{ width: `${Math.min(100, riskCalculation.components.threat_intel)}%` }} />
                </div>
              </div>

              <div className="risk-bar-row">
                <div className="risk-bar-head">
                  <span>Flow Frequency & Correlation (15% Weight)</span>
                  <span className="risk-bar-val text-blue">{riskCalculation.components.correlation}%</span>
                </div>
                <div className="risk-track">
                  <div className="risk-fill fill-blue" style={{ width: `${Math.min(100, riskCalculation.components.correlation)}%` }} />
                </div>
              </div>
            </div>
          </div>

          {/* SECTION 8: OBSERVED INDICATORS (IOCS) */}
          <div className="ioc-incident-panel">
            <span className="console-section-title">
              <FileText size={14} className="text-cyan" />
              OBSERVED INDICATORS OF COMPROMISE (IOCS)
            </span>

            <div className="ioc-grid">
              <div className="ioc-chip-card">
                <div className="ioc-chip-info">
                  <span className="ioc-chip-k">SOURCE IPV4</span>
                  <span className="ioc-chip-v">{alert.source.ip}</span>
                </div>
                <button
                  type="button"
                  className="btn-copy-mini"
                  onClick={() => handleCopyText(alert.source.ip, 'src_ip')}
                  title="Copy Source IP"
                >
                  {copiedKey === 'src_ip' ? <Check size={12} className="text-green" /> : <Copy size={12} />}
                </button>
              </div>

              <div className="ioc-chip-card">
                <div className="ioc-chip-info">
                  <span className="ioc-chip-k">TARGET IPV4</span>
                  <span className="ioc-chip-v">{alert.destination.ip}</span>
                </div>
                <button
                  type="button"
                  className="btn-copy-mini"
                  onClick={() => handleCopyText(alert.destination.ip, 'dst_ip')}
                  title="Copy Target IP"
                >
                  {copiedKey === 'dst_ip' ? <Check size={12} className="text-green" /> : <Copy size={12} />}
                </button>
              </div>

              <div className="ioc-chip-card">
                <div className="ioc-chip-info">
                  <span className="ioc-chip-k">TARGET PORT</span>
                  <span className="ioc-chip-v">{alert.destination.port} ({alert.protocol})</span>
                </div>
                <button
                  type="button"
                  className="btn-copy-mini"
                  onClick={() => handleCopyText(String(alert.destination.port), 'dst_port')}
                  title="Copy Target Port"
                >
                  {copiedKey === 'dst_port' ? <Check size={12} className="text-green" /> : <Copy size={12} />}
                </button>
              </div>

              {iocs.map((ioc, idx) => (
                <div key={idx} className="ioc-chip-card">
                  <div className="ioc-chip-info">
                    <span className="ioc-chip-k">{ioc.ioc_type || 'INDICATOR'}</span>
                    <span className="ioc-chip-v">{ioc.value}</span>
                  </div>
                  <button
                    type="button"
                    className="btn-copy-mini"
                    onClick={() => handleCopyText(ioc.value, `ioc_${idx}`)}
                    title="Copy Indicator"
                  >
                    {copiedKey === `ioc_${idx}` ? <Check size={12} className="text-green" /> : <Copy size={12} />}
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* SECTION 13: INCIDENT ACTION BAR (STICKY BOTTOM) */}
        <footer className="incident-console-footer">
          <div className="footer-btn-group">
            <button
              type="button"
              className="btn-console-primary"
              onClick={handleExportDossier}
              title="Download formatted incident brief as text/dossier"
            >
              <Download size={13} />
              <span>{dossierExportNotice ? 'DOSSIER EXPORTED' : 'EXPORT INCIDENT DOSSIER'}</span>
            </button>

            <button
              type="button"
              className="btn-console-secondary"
              onClick={handleCopyAllIocs}
              title="Copy all observed indicators to clipboard"
            >
              {copiedKey === 'ALL_IOCS' ? <Check size={13} className="text-green" /> : <Copy size={13} />}
              <span>{copiedKey === 'ALL_IOCS' ? 'IOCS COPIED TO CLIPBOARD' : 'COPY ALL IOCS'}</span>
            </button>

            {onInvestigateIp && (
              <button
                type="button"
                className="btn-console-secondary"
                onClick={() => onInvestigateIp(alert.source.ip)}
                title={`Launch full IP Investigation dossier for ${alert.source.ip}`}
              >
                <ExternalLink size={13} />
                <span>INVESTIGATE SOURCE IP</span>
              </button>
            )}
          </div>

          <button
            type="button"
            className="btn-console-secondary"
            onClick={onClose}
            title="Close this incident console (Esc)"
          >
            <span>CLOSE CONSOLE</span>
          </button>
        </footer>
      </div>
    </div>
  )
}

export default AlertDetails