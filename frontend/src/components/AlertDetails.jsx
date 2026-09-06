import {
  X,
  ShieldAlert,
  Activity,
  Target,
} from 'lucide-react'

import AIAnalysis from './AIAnalysis'

function AlertDetails({ alert, onClose }) {
  if (!alert) {
    return null
  }

  return (
    <div className="alert-details-overlay">
      <div className="alert-details-panel">

        <div className="details-header">
          <div className="details-title">
            <div className="details-icon">
              <ShieldAlert size={22} />
            </div>

            <div>
              <h2>Alert Details</h2>
              <p>{alert.alert_id}</p>
            </div>
          </div>

          <button
            className="details-close"
            onClick={onClose}
            aria-label="Close alert details"
          >
            <X size={20} />
          </button>
        </div>

        <div className="details-summary">

          <div className="detail-summary-card">
            <span>THREAT</span>
            <strong>{alert.threat_class}</strong>
          </div>

          <div className="detail-summary-card">
            <span>SEVERITY</span>
            <strong
              className={`detail-severity ${alert.severity.toLowerCase()}`}
            >
              {alert.severity}
            </strong>
          </div>

          <div className="detail-summary-card">
            <span>CONFIDENCE</span>
            <strong>
              {(alert.confidence * 100).toFixed(0)}%
            </strong>
          </div>

          <div className="detail-summary-card">
            <span>STATUS</span>
            <strong>{alert.status}</strong>
          </div>

        </div>

        <div className="details-section">
          <div className="details-section-title">
            <Activity size={17} />
            <h3>Network Flow</h3>
          </div>

          <div className="network-grid">

            <div className="network-item">
              <span>Source IP</span>
              <strong>{alert.source.ip}</strong>
            </div>

            <div className="network-item">
              <span>Source Port</span>
              <strong>{alert.source.port}</strong>
            </div>

            <div className="network-item">
              <span>Destination IP</span>
              <strong>{alert.destination.ip}</strong>
            </div>

            <div className="network-item">
              <span>Destination Port</span>
              <strong>{alert.destination.port}</strong>
            </div>

            <div className="network-item">
              <span>Protocol</span>
              <strong>{alert.protocol}</strong>
            </div>

            <div className="network-item">
              <span>Flow ID</span>
              <strong>{alert.flow_id}</strong>
            </div>

          </div>
        </div>

        <div className="details-section">
          <div className="details-section-title">
            <Target size={17} />
            <h3>Detection Information</h3>
          </div>

          <div className="detection-info">

            <div>
              <span>Detection Method</span>
              <strong>
                {alert.detection_method.join(', ')}
              </strong>
            </div>

            <div>
              <span>Timestamp</span>
              <strong>
                {new Date(alert.timestamp).toLocaleString()}
              </strong>
            </div>

          </div>
        </div>

        <div className="details-section">
          <div className="details-section-title">
            <ShieldAlert size={17} />
            <h3>Evidence</h3>
          </div>

          <div className="evidence-list">
            {alert.evidence.map((item, index) => (
              <div
                className="evidence-item"
                key={index}
              >
                <span className="evidence-number">
                  {index + 1}
                </span>

                <span>{item}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="details-section">
          <div className="details-section-title">
            <Target size={17} />
            <h3>MITRE ATT&CK Context</h3>
          </div>

          <div className="mitre-card">

            <div className="mitre-item">
              <span>Tactic</span>
              <strong>
                {alert.mitre.tactic}
              </strong>
            </div>

            <div className="mitre-item">
              <span>Technique</span>
              <strong>
                {alert.mitre.technique_id
                  ? alert.mitre.technique_id
                  : 'Not verified'}
              </strong>
            </div>

            <div className="mitre-item">
              <span>Verification</span>
              <strong>
                {alert.mitre.verify
                  ? 'Verification required'
                  : 'Verified'}
              </strong>
            </div>

          </div>
        </div>

        <AIAnalysis alert={alert} />

      </div>
    </div>
  )
}

export default AlertDetails