import { useEffect } from 'react'
import { ShieldAlert, X } from 'lucide-react'

function ToastNotification({ toast, onDismiss, onViewAlert }) {
  useEffect(() => {
    if (!toast) return
    const timer = setTimeout(() => {
      onDismiss()
    }, 4500)
    return () => clearTimeout(timer)
  }, [toast, onDismiss])

  if (!toast) return null

  const { alert } = toast
  const sev = (alert.severity || 'CRITICAL').toUpperCase()

  return (
    <div className="clean-toast" onClick={() => onViewAlert(alert)}>
      <div className="toast-icon-wrap">
        <ShieldAlert size={16} />
      </div>

      <div className="toast-text-wrap">
        <span className="toast-title">NEW THREAT DETECTED</span>
        <span className="toast-detail">
          {alert.threat_class} • <strong className={`sev-${sev.toLowerCase()}`}>{sev}</strong>
        </span>
      </div>

      <button
        type="button"
        className="toast-close"
        onClick={(e) => {
          e.stopPropagation()
          onDismiss()
        }}
        aria-label="Dismiss"
      >
        <X size={14} />
      </button>
    </div>
  )
}

export default ToastNotification
