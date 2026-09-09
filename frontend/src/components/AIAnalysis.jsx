import { useState, useEffect, useRef } from 'react'
import { Sparkles, AlertCircle, RefreshCw, Play, Clock } from 'lucide-react'
import { requestAIAnalysis } from '../services/alertService'

function AIAnalysis({ alert }) {
  const [analysis, setAnalysis] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [isTimeout, setIsTimeout] = useState(false)

  // Track the currently running alertId to prevent duplicate/concurrent runs
  const inFlightRef = useRef(null)
  const abortControllerRef = useRef(null)

  const handleRunAI = async () => {
    if (!alert?.alert_id) return
    if (loading || inFlightRef.current === alert.alert_id) return

    // Cancel any previous in-flight request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }
    const controller = new AbortController()
    abortControllerRef.current = controller

    inFlightRef.current = alert.alert_id
    setLoading(true)
    setError(null)
    setIsTimeout(false)

    try {
      const data = await requestAIAnalysis(alert.alert_id, controller.signal, alert.rawAlert || alert)
      if (data && data.ai_analysis) {
        if (data.ai_analysis.error) {
          const rawErr = data.ai_analysis.error
          const rawReason = data.ai_analysis.reason || ''
          if (rawErr.toLowerCase().includes('timed out') || rawReason.toLowerCase().includes('timed out') || rawReason.toLowerCase().includes('taking longer')) {
            setIsTimeout(true)
            setError('Nemotron is taking longer than expected. Please retry.')
          } else if (rawErr.toLowerCase().includes('malformed') || rawErr.toLowerCase().includes('unusable') || rawReason.toLowerCase().includes('malformed') || rawReason.toLowerCase().includes('unusable')) {
            setError('Nemotron returned an unusable response. Please retry the investigation.')
          } else {
            setError(rawErr || 'AI enrichment unavailable')
          }
        } else {
          setAnalysis(data.ai_analysis)
        }

      } else if (data && data.summary) {
        setAnalysis({
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
      if (msg.toLowerCase().includes('timed out') || msg.toLowerCase().includes('timeout') || msg.toLowerCase().includes('taking longer')) {
        setIsTimeout(true)
        setError('Nemotron is taking longer than expected. Please retry.')
      } else {
        setError(msg)
      }
    } finally {
      inFlightRef.current = null
      setLoading(false)
    }
  }

  // Reset state whenever a different alert is selected
  useEffect(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }
    inFlightRef.current = null
    setAnalysis(null)
    setError(null)
    setIsTimeout(false)
    setLoading(false)

    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort()
      }
    }
  }, [alert?.alert_id])

  if (!alert) return null

  return (
    <div className="clean-ai-box">
      <div className="ai-header-bar">
        <div className="ai-title-line">
          <Sparkles size={15} className="text-cyan" />
          <span className="ai-title">NVIDIA Nemotron AI Investigation</span>
        </div>
        {loading && <span className="ai-status-pill">Investigating with Nemotron…</span>}
        {analysis && !loading && <span className="ai-status-pill ready">Active</span>}
        {!analysis && !loading && !error && (
          <button
            type="button"
            className="ai-status-pill ready"
            style={{ cursor: 'pointer', border: 'none', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
            onClick={handleRunAI}
            disabled={loading}
          >
            <Play size={10} />
            <span>Investigate</span>
          </button>
        )}
      </div>

      {!analysis && !loading && !error && (
        <div className="ai-idle-prompt" style={{ padding: '12px 0', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
            Enrich canonical detection with Nemotron 3.5 LLM reasoning.
          </span>
          <button
            type="button"
            className="btn-retry"
            style={{ background: 'rgba(6, 182, 212, 0.15)', color: '#06b6d4', border: '1px solid rgba(6, 182, 212, 0.3)', padding: '6px 12px', borderRadius: '4px', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '0.78rem' }}
            onClick={handleRunAI}
            disabled={loading}
          >
            <Sparkles size={12} />
            <span>INVESTIGATE WITH NEMOTRON</span>
          </button>
        </div>
      )}

      {loading && (
        <div className="ai-skeleton">
          <div className="skel-line w-75"></div>
          <div className="skel-line w-100"></div>
          <div className="skel-line w-50"></div>
        </div>
      )}

      {error && !loading && (
        <div className="ai-offline-note">
          <div className="offline-msg">
            {isTimeout ? (
              <Clock size={14} className="text-amber" />
            ) : (
              <AlertCircle size={14} className="text-amber" />
            )}
            <span>
              {isTimeout
                ? 'Nemotron is taking longer than expected. Please retry.'
                : error}
            </span>
          </div>
          <button type="button" className="btn-retry" onClick={handleRunAI} disabled={loading}>
            <RefreshCw size={11} />
            <span>Retry</span>
          </button>
        </div>
      )}

      {analysis && !loading && (
        <div className="ai-content">
          <div className="ai-summary-text">
            {analysis.ai_summary || analysis.summary}
          </div>

          <div className="ai-grid-metrics">
            <div className="ai-metric-item">
              <span className="metric-label">THREAT ASSESSMENT</span>
              <span className="metric-value">{analysis.threat_assessment || 'Anomalous'}</span>
            </div>
            <div className="ai-metric-item">
              <span className="metric-label">RISK LEVEL</span>
              <span className="metric-value text-white">{analysis.risk_level || alert.severity}</span>
            </div>
          </div>

          {analysis.why_suspicious && analysis.why_suspicious.length > 0 && (
            <div className="ai-section">
              <span className="ai-section-title">WHY SUSPICIOUS</span>
              <ul className="ai-clean-list">
                {analysis.why_suspicious.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            </div>
          )}

          {analysis.recommended_actions && analysis.recommended_actions.length > 0 && (
            <div className="ai-section">
              <span className="ai-section-title">RECOMMENDED ACTIONS</span>
              <ul className="ai-clean-list actions-list">
                {analysis.recommended_actions.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default AIAnalysis