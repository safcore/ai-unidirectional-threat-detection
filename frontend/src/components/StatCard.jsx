function StatCard({ title, value, variant = 'default' }) {
  const isText = typeof value === 'string' && value.length > 5
  return (
    <div className={`clean-kpi-card kpi-${variant}`}>
      <span className="kpi-title">{title}</span>
      <span className={`kpi-number ${isText ? 'kpi-number-compact' : ''}`}>{value}</span>
    </div>
  )
}

export default StatCard
