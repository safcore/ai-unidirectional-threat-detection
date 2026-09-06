import {
  Activity,
  AlertTriangle,
  ShieldAlert,
  Target,
} from 'lucide-react'

const iconMap = {
  flows: Activity,
  threats: AlertTriangle,
  highRisk: ShieldAlert,
  confidence: Target,
}

function StatCard({ type, title, value, change, changeLabel }) {
  const Icon = iconMap[type]

  return (
    <div className="stat-card">
      <div className="stat-card-top">
        <div className="stat-icon">
          <Icon size={20} />
        </div>

        <span className="stat-title">{title}</span>
      </div>

      <div className="stat-value">
        {value}
      </div>

      <div className="stat-change">
        <span>{change}</span>
        <span className="stat-change-label">{changeLabel}</span>
      </div>
    </div>
  )
}

export default StatCard
