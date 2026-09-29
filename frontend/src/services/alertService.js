const API_BASE_URL = 'http://127.0.0.1:5000/api'

export function normalizeAlert(alert) {
  const rawEv = typeof alert.evidence === 'object' && alert.evidence !== null ? alert.evidence : {}

  // Format evidence items into readable strings if rawEv has nested objects
  const evidenceList = Array.isArray(alert.evidence)
    ? alert.evidence
    : Object.entries(rawEv).map(([key, value]) => {
        if (typeof value === 'object' && value !== null) {
          return `${key}: ${JSON.stringify(value)}`
        }
        return `${key}: ${value}`
      })

  return {
    alert_id: alert.alert_id,
    timestamp: alert.timestamp,
    description:
      alert.description ||
      rawEv.decision_reason ||
      alert.reason ||
      'Threat Detected',

    flow_id:
      alert.flow_id ||
      `flow-${alert.alert_id}`,

    source: {
      ip:
        alert.source?.ip ||
        alert.source_ip ||
        'Unknown',

      port:
        alert.source?.port ??
        alert.source_port ??
        0,
    },

    destination: {
      ip:
        alert.destination?.ip ||
        alert.destination_ip ||
        'Unknown',

      port:
        alert.destination?.port ??
        alert.destination_port ??
        0,
    },

    protocol:
      alert.protocol ||
      'Unknown',

    threat_class:
      alert.threat_class ||
      alert.threat ||
      'Unknown',

    confidence:
      Number(alert.confidence) || 0,

    severity:
      alert.severity ||
      'MEDIUM',

    detection_method:
      Array.isArray(alert.detection_method)
        ? alert.detection_method
        : ['BACKEND'],

    evidence: evidenceList,

    // Deep SOC Evidence & Investigation Data (NETRION)
    evidenceDetails: {
      decision_reason: rawEv.decision_reason || alert.reason || '',
      anomaly_score: typeof rawEv.anomaly_score === 'number' ? rawEv.anomaly_score : null,
      classifications: rawEv.classifications || {},
      investigation: rawEv.investigation || {},
      iocs: Array.isArray(rawEv.iocs) ? rawEv.iocs : [],
    },

    mitre: {
      tactic:
        alert.mitre?.tactic ||
        'Not specified',

      technique_id:
        alert.mitre?.technique_id ||
        alert.mitre?.technique ||
        null,

      technique_name:
        alert.mitre?.technique_name ||
        null,

      verify:
        alert.mitre?.verify ??
        true,
    },

    status:
      alert.status ||
      'NEW',

    rawAlert: alert,
  }
}

export async function fetchAlerts() {
  const response = await fetch(
    `${API_BASE_URL}/alerts`
  )

  if (!response.ok) {
    throw new Error(
      `Failed to fetch alerts: ${response.status}`
    )
  }

  const data = await response.json()

  return (data.alerts || []).map(
    normalizeAlert
  )
}

export async function fetchAlertById(alertId) {
  const response = await fetch(
    `${API_BASE_URL}/alerts/${alertId}`
  )

  if (!response.ok) {
    throw new Error(
      `Failed to fetch alert: ${response.status}`
    )
  }

  const data = await response.json()

  return normalizeAlert(data)
}

export async function fetchAlertStatistics() {
  const response = await fetch(
    `${API_BASE_URL}/stats`
  )

  if (!response.ok) {
    throw new Error(
      `Failed to fetch statistics: ${response.status}`
    )
  }

  return response.json()
}

export async function checkBackendHealth() {
  try {
    const response = await fetch(
      `${API_BASE_URL}/health`
    )

    if (!response.ok) {
      return false
    }

    const data = await response.json()
    return data.status === 'healthy'
  } catch {
    return false
  }
}

export async function fetchBackendHealthDetails() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`)
    if (!response.ok) {
      return { healthy: false, error: `HTTP ${response.status}` }
    }
    const data = await response.json()
    return {
      healthy: data.status === 'healthy',
      alertCount: data.alert_count,
      service: data.service,
      version: data.version,
    }
  } catch (err) {
    return { healthy: false, error: err.message }
  }
}

export async function checkAIHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/ai/health`)
    if (!response.ok) {
      return { available: false, status: 'offline', error: `HTTP ${response.status}` }
    }
    const data = await response.json()
    return {
      available: data.ai_enabled === true && data.status === 'available',
      provider: data.provider || 'NVIDIA',
      model: data.model || 'meta/llama-3.1-70b-instruct',
      status: data.status || 'unknown',
      reason: data.reason || null,
    }
  } catch (err) {
    return { available: false, status: 'offline', error: err.message }
  }
}

export async function triggerAttackSimulation(attackType, params = {}) {
  const response = await fetch(`${API_BASE_URL}/attack/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: attackType,
      ...params,
    }),
  })

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}))
    throw new Error(errData.error || `Attack simulation failed: ${response.status}`)
  }

  return response.json()
}

export async function fetchAttackStatus(attackId) {
  const url = attackId
    ? `${API_BASE_URL}/attack/status?attack_id=${encodeURIComponent(attackId)}`
    : `${API_BASE_URL}/attack/status`
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Failed to fetch attack status: ${response.status}`)
  }
  return response.json()
}

export async function requestAIAnalysis(alertId, signal = null, alertData = null, refresh = false) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), 50000)

  // Listen to external signal if provided
  if (signal) {
    signal.addEventListener('abort', () => controller.abort())
  }

  try {
    const fetchOptions = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
    }
    if (alertData) {
      fetchOptions.body = JSON.stringify({ alert: alertData })
    }

    const endpointUrl = refresh
      ? `${API_BASE_URL}/ai/analyze/${alertId}?refresh=true`
      : `${API_BASE_URL}/ai/analyze/${alertId}`
    const response = await fetch(endpointUrl, fetchOptions)

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}))
      throw new Error(errData.error || `AI analysis failed: ${response.status}`)
    }

    return await response.json()
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('Nemotron is taking longer than expected. Please retry.', { cause: err })
    }
    throw err
  } finally {
    clearTimeout(timeoutId)
  }
}


export async function analyzeIP(ip) {
  const response = await fetch(`${API_BASE_URL}/traffic/analyze-ip`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  })

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}))
    throw new Error(errData.error || `IP analysis failed: ${response.status}`)
  }

  return response.json()
}

export async function replayPCAP(options = {}) {
  const response = await fetch(`${API_BASE_URL}/traffic/replay-pcap`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(options),
  })

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}))
    throw new Error(errData.error || `PCAP replay failed: ${response.status}`)
  }

  return response.json()
}

export async function inspectLiveTraffic() {
  const response = await fetch(`${API_BASE_URL}/traffic/live-sample`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  })

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}))
    throw new Error(errData.error || `Live inspection failed: ${response.status}`)
  }

  return response.json()
}

export async function uploadPCAP(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await fetch(`${API_BASE_URL}/traffic/upload-pcap`, {
    method: 'POST',
    body: formData,
  })

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}))
    throw new Error(errData.error || `PCAP upload failed: ${response.status}`)
  }

  return response.json()
}

export async function startSafeTestTraffic() {
  const response = await fetch(`${API_BASE_URL}/traffic/start-test-traffic`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  })

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}))
    throw new Error(errData.error || `Test traffic failed: ${response.status}`)
  }

  return response.json()
}

export async function getTrafficStatus() {
  const response = await fetch(`${API_BASE_URL}/traffic/status`)
  if (!response.ok) {
    throw new Error(`Failed to fetch traffic status: ${response.status}`)
  }
  return response.json()
}

/*
 * SERVER-SENT EVENTS WITH AUTO-RECONNECT
 */
export function connectToAlertStream(onAlert, onStatusChange) {
  let eventSource = null
  let reconnectTimeout = null
  let isClosed = false

  function setupConnection() {
    if (isClosed) return

    try {
      if (onStatusChange) {
        onStatusChange('reconnecting')
      }

      eventSource = new EventSource(`${API_BASE_URL}/stream`)

      eventSource.onopen = () => {
        console.log('SSE connection established')
        if (onStatusChange) {
          onStatusChange('connected')
        }
      }

      eventSource.addEventListener('connected', (event) => {
        console.log('SSE connected event:', event.data)
      })

      eventSource.onmessage = (event) => {
        try {
          const alert = JSON.parse(event.data)
          onAlert(normalizeAlert(alert))
        } catch (error) {
          console.error('Failed to parse SSE alert:', error)
        }
      }

      eventSource.onerror = () => {
        console.warn('SSE connection interrupted, scheduling reconnect...')
        if (eventSource) {
          eventSource.close()
          eventSource = null
        }
        if (onStatusChange) {
          onStatusChange('reconnecting')
        }
        if (!isClosed && !reconnectTimeout) {
          reconnectTimeout = setTimeout(() => {
            reconnectTimeout = null
            setupConnection()
          }, 3000)
        }
      }
    } catch (err) {
      console.error('Error creating EventSource:', err)
      if (onStatusChange) {
        onStatusChange('disconnected')
      }
      if (!isClosed && !reconnectTimeout) {
        reconnectTimeout = setTimeout(() => {
          reconnectTimeout = null
          setupConnection()
        }, 3000)
      }
    }
  }

  setupConnection()

  return () => {
    isClosed = true
    if (reconnectTimeout) {
      clearTimeout(reconnectTimeout)
      reconnectTimeout = null
    }
    if (eventSource) {
      eventSource.close()
      eventSource = null
    }
    if (onStatusChange) {
      onStatusChange('disconnected')
    }
    console.log('SSE connection closed by consumer')
  }
}
