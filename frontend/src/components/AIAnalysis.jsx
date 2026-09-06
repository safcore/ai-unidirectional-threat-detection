import { useEffect, useState } from 'react'

import {
  BrainCircuit,
  AlertTriangle,
  Lightbulb,
  Target,
  ShieldCheck,
} from 'lucide-react'


const API_BASE_URL = 'http://127.0.0.1:5000/api'


function AIAnalysis({ alert }) {

  const [analysis, setAnalysis] = useState(null)

  const [loading, setLoading] =
    useState(false)

  const [error, setError] =
    useState(false)


  useEffect(() => {

    if (!alert?.alert_id) {
      return
    }


    async function loadAIAnalysis() {

      try {

        setLoading(true)

        setError(false)

        setAnalysis(null)


        const response = await fetch(
          `${API_BASE_URL}/ai/analyze/${alert.alert_id}`,
          {
            method: 'POST',
          }
        )


        if (!response.ok) {
          throw new Error(
            `AI analysis failed: ${response.status}`
          )
        }


        const data =
          await response.json()


        setAnalysis(
          data.ai_analysis
        )

      } catch (err) {

        console.error(
          'AI analysis error:',
          err
        )

        setError(true)

      } finally {

        setLoading(false)

      }

    }


    loadAIAnalysis()

  }, [alert?.alert_id])


  if (!alert) {
    return null
  }


  return (
    <div className="ai-analysis-card">

      <div className="ai-analysis-header">

        <div className="ai-analysis-title">

          <div className="ai-icon">
            <BrainCircuit size={19} />
          </div>

          <div>

            <h3>
              AI Security Analysis
            </h3>

            <p>
              NVIDIA Nemotron threat interpretation
            </p>

          </div>

        </div>


        <span className="ai-demo-badge">
          {loading
            ? 'ANALYZING'
            : analysis
              ? 'LIVE AI'
              : 'AI ERROR'}
        </span>

      </div>


      {loading && (

        <div className="ai-analysis-section">

          <div className="ai-section-label">

            <BrainCircuit size={15} />

            <span>
              ANALYSIS
            </span>

          </div>

          <p>
            NVIDIA Nemotron is analyzing
            this security alert...
          </p>

        </div>

      )}


      {error && (

        <div className="ai-analysis-section">

          <div className="ai-section-label">

            <AlertTriangle size={15} />

            <span>
              AI SERVICE
            </span>

          </div>

          <p>
            Unable to generate AI analysis.
            The alert detection data is still
            available above.
          </p>

        </div>

      )}


      {analysis && (

        <>

          <div className="ai-analysis-section">

            <div className="ai-section-label">

              <BrainCircuit size={15} />

              <span>
                ANALYSIS
              </span>

            </div>

            <p>
              {analysis.ai_summary}
            </p>

          </div>


          <div className="ai-analysis-section">

            <div className="ai-section-label">

              <AlertTriangle size={15} />

              <span>
                THREAT ASSESSMENT
              </span>

            </div>

            <p>
              {analysis.threat_assessment}
            </p>

          </div>


          <div className="ai-analysis-section">

            <div className="ai-section-label">

              <Target size={15} />

              <span>
                RISK ASSESSMENT
              </span>

            </div>

            <p>
              Risk Level:{' '}
              <strong>
                {analysis.risk_level}
              </strong>
              {' '}| Investigation Priority:{' '}
              <strong>
                {analysis.investigation_priority}
              </strong>
              {' '}| AI Confidence:{' '}
              <strong>
                {(analysis.confidence * 100).toFixed(0)}%
              </strong>
            </p>

          </div>


          <div className="ai-analysis-section">

            <div className="ai-section-label">

              <AlertTriangle size={15} />

              <span>
                WHY SUSPICIOUS
              </span>

            </div>

            <ul>

              {analysis.why_suspicious?.map(
                (reason, index) => (
                  <li key={index}>
                    {reason}
                  </li>
                )
              )}

            </ul>

          </div>


          <div className="ai-analysis-section">

            <div className="ai-section-label">

              <Target size={15} />

              <span>
                ATTACK CONTEXT
              </span>

            </div>

            <p>
              Attack Stage:{' '}
              <strong>
                {analysis.attack_stage}
              </strong>
              {' '}| MITRE Tactic:{' '}
              <strong>
                {analysis.mitre_context?.tactic ||
                  'Not specified'}
              </strong>
              {' '}| Technique:{' '}
              <strong>
                {analysis.mitre_context?.technique ||
                  'Not verified'}
              </strong>
            </p>

          </div>


          <div className="ai-analysis-section">

            <div className="ai-section-label">

              <Lightbulb size={15} />

              <span>
                RECOMMENDED ACTIONS
              </span>

            </div>

            <ul>

              {analysis.recommended_actions?.map(
                (action, index) => (
                  <li key={index}>
                    {action}
                  </li>
                )
              )}

            </ul>

          </div>


          <div className="ai-analysis-section">

            <div className="ai-section-label">

              <ShieldCheck size={15} />

              <span>
                AI CONFIDENCE
              </span>

            </div>

            <p>
              Nemotron confidence:{' '}
              <strong>
                {(analysis.confidence * 100).toFixed(0)}%
              </strong>
            </p>

          </div>


          <div className="ai-disclaimer">

            AI analysis generated by the
            integrated NVIDIA Nemotron service.
            Use as analyst assistance and verify
            findings against network evidence.

          </div>

        </>

      )}

    </div>
  )
}


export default AIAnalysis