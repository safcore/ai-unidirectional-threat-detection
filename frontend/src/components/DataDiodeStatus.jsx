import { ArrowRight } from 'lucide-react'

function DataDiodeStatus() {
  return (
    <div className="arch-strip">
      <div className="arch-flow">
        <span className="arch-node"><strong>M1</strong> PASSIVE RX</span>
        <ArrowRight size={13} className="arch-arrow" />
        <span className="arch-node"><strong>M2</strong> FEATURES</span>
        <ArrowRight size={13} className="arch-arrow" />
        <span className="arch-node"><strong>M3/M4</strong> DETECTION</span>
        <ArrowRight size={13} className="arch-arrow" />
        <span className="arch-node"><strong>M5</strong> ALERT</span>
        <ArrowRight size={13} className="arch-arrow" />
        <span className="arch-node"><strong>SSE</strong> SOC</span>
      </div>
      <div className="arch-caption">
        RX-ONLY • TX SEVERED • ZERO REVERSE DATA FLOW
      </div>
    </div>
  )
}

export default DataDiodeStatus
