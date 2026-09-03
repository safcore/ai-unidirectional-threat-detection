import { ShieldCheck, Activity, Radio } from 'lucide-react'

function Header() {
  return (
    <header className="soc-header">
      <div className="header-brand">
        <div className="brand-icon">
          <ShieldCheck size={30} />
        </div>

        <div>
          <h1>AI Threat Detection SOC</h1>
          <p>Unidirectional IP Traffic Monitoring</p>
        </div>
      </div>

      <div className="system-status">
        <span className="status-dot"></span>
        <span>SYSTEM ONLINE</span>
      </div>

      <div className="architecture-status">
        <div>
          <Radio size={16} />
          <span>READ-ONLY INGEST</span>
        </div>

        <div>
          <Activity size={16} />
          <span>ONE-WAY PATH</span>
        </div>

        <div>
          <ShieldCheck size={16} />
          <span>METADATA ONLY</span>
        </div>
      </div>
    </header>
  )
}

export default Header